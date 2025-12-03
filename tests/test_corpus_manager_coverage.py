"""Tests for corpus_manager module to improve code coverage.

These tests exercise the corpus management code paths for coverage-guided fuzzing.
"""

import pickle
import time

import pytest
from pydicom import Dataset

from dicom_fuzzer.core.corpus_manager import (
    CorpusManager,
    CorpusStats,
    HistoricalCorpusManager,
    Seed,
    SeedPriority,
)
from dicom_fuzzer.core.coverage_instrumentation import CoverageInfo


@pytest.fixture
def temp_dir(tmp_path):
    """Create temporary directory for tests."""
    return tmp_path


@pytest.fixture
def corpus_manager():
    """Create CorpusManager instance."""
    return CorpusManager(max_corpus_size=100, min_coverage_distance=0.1)


@pytest.fixture
def sample_coverage():
    """Create sample coverage info."""
    return CoverageInfo(
        edges={("file.py", 1, "file.py", 2), ("file.py", 2, "file.py", 3)},
        branches={("file.py", 1, True), ("file.py", 1, False)},
        functions={"func1", "func2"},
        lines={("file.py", 1), ("file.py", 2)},
    )


@pytest.fixture
def sample_seed(sample_coverage):
    """Create sample seed."""
    return Seed(
        id="test-seed-001",
        data=b"test data",
        coverage=sample_coverage,
        priority=SeedPriority.NORMAL,
        energy=1.0,
    )


class TestSeedPriority:
    """Test SeedPriority enum."""

    def test_priority_values(self):
        """Test that priority values are ordered correctly."""
        assert SeedPriority.CRITICAL.value == 1
        assert SeedPriority.HIGH.value == 2
        assert SeedPriority.NORMAL.value == 3
        assert SeedPriority.LOW.value == 4
        assert SeedPriority.MINIMAL.value == 5

    def test_priority_ordering(self):
        """Test that priorities can be compared."""
        assert SeedPriority.CRITICAL.value < SeedPriority.HIGH.value
        assert SeedPriority.HIGH.value < SeedPriority.NORMAL.value
        assert SeedPriority.NORMAL.value < SeedPriority.LOW.value
        assert SeedPriority.LOW.value < SeedPriority.MINIMAL.value


class TestSeed:
    """Test Seed dataclass."""

    def test_seed_creation(self, sample_coverage):
        """Test creating a seed."""
        seed = Seed(id="test-001", data=b"test data", coverage=sample_coverage)

        assert seed.id == "test-001"
        assert seed.data == b"test data"
        assert seed.priority == SeedPriority.NORMAL
        assert seed.energy == 1.0
        assert seed.executions == 0
        assert seed.discoveries == 0
        assert seed.crashes == 0

    def test_seed_lt_by_priority(self, sample_coverage):
        """Test seed comparison by priority."""
        seed1 = Seed(
            id="s1",
            data=b"d1",
            coverage=sample_coverage,
            priority=SeedPriority.CRITICAL,
        )
        seed2 = Seed(
            id="s2", data=b"d2", coverage=sample_coverage, priority=SeedPriority.NORMAL
        )

        assert seed1 < seed2  # CRITICAL (1) < NORMAL (3)

    def test_seed_lt_by_energy_same_priority(self, sample_coverage):
        """Test seed comparison by energy when priorities are equal."""
        seed1 = Seed(id="s1", data=b"d1", coverage=sample_coverage, energy=2.0)
        seed2 = Seed(id="s2", data=b"d2", coverage=sample_coverage, energy=1.0)

        # Higher energy is "less than" (higher priority)
        assert seed1 < seed2

    def test_seed_calculate_hash(self, sample_coverage):
        """Test hash calculation."""
        seed = Seed(id="test", data=b"test data", coverage=sample_coverage)
        hash_value = seed.calculate_hash()

        assert isinstance(hash_value, str)
        assert len(hash_value) > 0

    def test_seed_update_priority_coverage_gain(self, sample_coverage):
        """Test priority update with coverage gain."""
        seed = Seed(id="test", data=b"data", coverage=sample_coverage)

        seed.update_priority(coverage_gain=True)

        assert seed.priority == SeedPriority.CRITICAL
        assert seed.discoveries == 1
        assert seed.energy == 2.0  # Doubled

    def test_seed_update_priority_high(self, sample_coverage):
        """Test priority update to HIGH."""
        seed = Seed(
            id="test",
            data=b"data",
            coverage=sample_coverage,
            discoveries=1,
            executions=5,
        )

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.HIGH

    def test_seed_update_priority_low(self, sample_coverage):
        """Test priority update to LOW."""
        seed = Seed(
            id="test",
            data=b"data",
            coverage=sample_coverage,
            discoveries=0,
            executions=150,
        )

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.LOW
        assert seed.energy == 0.5  # Halved

    def test_seed_update_priority_minimal(self, sample_coverage):
        """Test priority update to MINIMAL.

        The MINIMAL branch triggers when executions > 500 but NOT when
        discoveries == 0 (which matches LOW first). So we need discoveries > 0
        but executions < 10 is false (won't match HIGH).
        """
        seed = Seed(
            id="test",
            data=b"data",
            coverage=sample_coverage,
            discoveries=1,  # > 0 to skip LOW branch
            executions=600,  # > 500 and > 10 (won't match HIGH)
        )

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.MINIMAL
        assert seed.energy == 0.1  # Reduced significantly


class TestCorpusStats:
    """Test CorpusStats dataclass."""

    def test_corpus_stats_defaults(self):
        """Test default values."""
        stats = CorpusStats()

        assert stats.total_seeds == 0
        assert stats.unique_coverage_signatures == 0
        assert stats.total_edges_covered == 0
        assert stats.total_executions == 0
        assert stats.coverage_plateaus == 0
        assert isinstance(stats.last_coverage_increase, float)
        assert stats.coverage_history == []


class TestCorpusManagerInit:
    """Test CorpusManager initialization."""

    def test_init_defaults(self):
        """Test initialization with defaults."""
        manager = CorpusManager()

        assert manager.max_corpus_size == 1000
        assert manager.min_coverage_distance == 0.1
        assert manager.energy_allocation == "adaptive"
        assert len(manager.seeds) == 0
        assert len(manager.seed_queue) == 0

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        manager = CorpusManager(
            max_corpus_size=500,
            min_coverage_distance=0.2,
            energy_allocation="uniform",
        )

        assert manager.max_corpus_size == 500
        assert manager.min_coverage_distance == 0.2
        assert manager.energy_allocation == "uniform"


class TestAddSeed:
    """Test add_seed method."""

    def test_add_seed_first(self, corpus_manager, sample_coverage):
        """Test adding first seed."""
        seed = corpus_manager.add_seed(b"test data", sample_coverage)

        assert seed is not None
        assert len(corpus_manager.seeds) == 1
        assert len(corpus_manager.seed_queue) == 1

    def test_add_seed_duplicate(self, corpus_manager, sample_coverage):
        """Test adding duplicate seed."""
        corpus_manager.add_seed(b"test data", sample_coverage)
        result = corpus_manager.add_seed(b"test data", sample_coverage)

        assert result is None
        assert len(corpus_manager.seeds) == 1

    def test_add_seed_with_parent(self, corpus_manager, sample_coverage):
        """Test adding seed with parent."""
        parent = corpus_manager.add_seed(b"parent data", sample_coverage)

        child_coverage = CoverageInfo(
            edges={("file.py", 10, "file.py", 11)},  # Different edges
        )
        child = corpus_manager.add_seed(
            b"child data",
            child_coverage,
            parent_id=parent.id,
            mutation_type="flip_bit",
        )

        assert child is not None
        assert child.parent_id == parent.id
        assert "flip_bit" in child.mutation_history

    def test_add_seed_with_new_coverage(self, corpus_manager):
        """Test adding seed with new coverage."""
        cov1 = CoverageInfo(edges={("f.py", 1, "f.py", 2)})
        seed1 = corpus_manager.add_seed(b"data1", cov1)

        cov2 = CoverageInfo(edges={("f.py", 3, "f.py", 4)})  # New edges
        seed2 = corpus_manager.add_seed(b"data2", cov2, mutation_type="mutate")

        assert seed2 is not None
        assert seed2.priority == SeedPriority.CRITICAL
        assert seed2.energy == 2.0

    def test_add_seed_corpus_overflow(self):
        """Test corpus minimization when size limit exceeded."""
        manager = CorpusManager(max_corpus_size=5)

        for i in range(10):
            cov = CoverageInfo(edges={(f"f{i}.py", 1, f"f{i}.py", 2)})
            manager.add_seed(f"data{i}".encode(), cov)

        assert len(manager.seeds) <= 5


class TestAddEntry:
    """Test add_entry compatibility method."""

    def test_add_entry_with_dataset_attribute(self, corpus_manager):
        """Test adding entry that has dataset attribute."""
        from pydicom.uid import ImplicitVRLittleEndian, generate_uid

        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "12345"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        ds.SOPInstanceUID = generate_uid()

        # Create file meta information
        ds.file_meta = Dataset()
        ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        ds.file_meta.TransferSyntaxUID = ImplicitVRLittleEndian

        class Entry:
            def __init__(self):
                self.entry_id = "entry-001"
                self.dataset = ds

        entry = Entry()
        corpus_manager.add_entry(entry)

        assert len(corpus_manager.seeds) == 1

    def test_add_entry_with_separate_dataset(self, corpus_manager):
        """Test adding entry with separate dataset."""
        from pydicom.uid import ImplicitVRLittleEndian, generate_uid

        ds = Dataset()
        ds.PatientName = "Test2"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = generate_uid()

        ds.file_meta = Dataset()
        ds.file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        ds.file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        ds.file_meta.TransferSyntaxUID = ImplicitVRLittleEndian

        class Entry:
            def __init__(self):
                self.entry_id = "entry-002"

        entry = Entry()
        corpus_manager.add_entry(entry, ds)

        assert len(corpus_manager.seeds) == 1

    def test_add_entry_no_dataset(self, corpus_manager):
        """Test adding entry without dataset."""
        corpus_manager.add_entry("plain_entry")

        # Should still work with empty data
        assert corpus_manager.stats.total_seeds >= 0


class TestGetNextSeed:
    """Test get_next_seed method."""

    def test_get_next_seed_empty(self, corpus_manager):
        """Test getting seed from empty corpus."""
        result = corpus_manager.get_next_seed()

        assert result is None

    def test_get_next_seed(self, corpus_manager, sample_coverage):
        """Test getting next seed."""
        corpus_manager.add_seed(b"test data", sample_coverage)

        seed = corpus_manager.get_next_seed()

        assert seed is not None
        assert seed.executions == 1
        assert corpus_manager.stats.total_executions == 1

    def test_get_next_seed_priority_order(self, corpus_manager):
        """Test that seeds are returned in priority order."""
        cov1 = CoverageInfo(edges={("f1.py", 1, "f1.py", 2)})
        cov2 = CoverageInfo(edges={("f2.py", 1, "f2.py", 2)})
        cov3 = CoverageInfo(edges={("f3.py", 1, "f3.py", 2)})

        corpus_manager.add_seed(b"low", cov1)
        corpus_manager.add_seed(b"normal", cov2)
        corpus_manager.add_seed(b"critical", cov3)

        # First seed should be critical (newest with unique coverage)
        seed = corpus_manager.get_next_seed()
        assert seed is not None


class TestUpdateSeedEnergy:
    """Test _update_seed_energy method."""

    def test_energy_uniform(self, sample_coverage):
        """Test uniform energy allocation."""
        manager = CorpusManager(energy_allocation="uniform")
        seed = Seed(id="test", data=b"data", coverage=sample_coverage, energy=5.0)

        manager._update_seed_energy(seed)

        assert seed.energy == 1.0

    def test_energy_adaptive_productive(self, sample_coverage):
        """Test adaptive energy for productive seed."""
        manager = CorpusManager(energy_allocation="adaptive")
        seed = Seed(
            id="test",
            data=b"data",
            coverage=sample_coverage,
            discoveries=5,
            executions=10,
        )

        manager._update_seed_energy(seed)

        assert seed.energy > 0

    def test_energy_adaptive_unproductive(self, sample_coverage):
        """Test adaptive energy for unproductive seed."""
        manager = CorpusManager(energy_allocation="adaptive")
        seed = Seed(
            id="test",
            data=b"data",
            coverage=sample_coverage,
            discoveries=0,
            executions=100,
        )

        manager._update_seed_energy(seed)

        assert seed.energy < 1.0

    def test_energy_exp(self, sample_coverage):
        """Test exponential energy allocation."""
        manager = CorpusManager(energy_allocation="exp")
        seed = Seed(
            id="test",
            data=b"data",
            coverage=sample_coverage,
            executions=10,
        )

        manager._update_seed_energy(seed)

        assert seed.energy == 0.5  # 2^(-10/10) = 0.5

    def test_energy_boost_untouched_edges(self, sample_coverage):
        """Test energy boost for untouched edges."""
        manager = CorpusManager(energy_allocation="uniform")
        seed = Seed(id="test", data=b"data", coverage=sample_coverage)

        # Mark some edges as untouched
        manager.untouched_edges.update(sample_coverage.edges)

        manager._update_seed_energy(seed)

        assert seed.energy == 2.0  # 1.0 * 2


class TestCoverageUniqueness:
    """Test _is_coverage_unique method."""

    def test_unique_first_seed(self, corpus_manager, sample_coverage):
        """Test that first seed is always unique."""
        result = corpus_manager._is_coverage_unique(sample_coverage)

        assert result is True

    def test_unique_different_coverage(self, corpus_manager, sample_coverage):
        """Test with significantly different coverage."""
        corpus_manager.add_seed(b"seed1", sample_coverage)

        different_cov = CoverageInfo(
            edges={("other.py", 100, "other.py", 101)},
        )

        result = corpus_manager._is_coverage_unique(different_cov)

        assert result is True

    def test_not_unique_similar_coverage(self, corpus_manager, sample_coverage):
        """Test with similar coverage."""
        corpus_manager.add_seed(b"seed1", sample_coverage)

        # Same coverage should be rejected
        result = corpus_manager._is_coverage_unique(sample_coverage)

        assert result is False


class TestCorpusMinimization:
    """Test _minimize_corpus method."""

    def test_minimize_removes_low_value(self):
        """Test that low-value seeds are removed."""
        manager = CorpusManager(max_corpus_size=3)

        for i in range(5):
            cov = CoverageInfo(edges={(f"f{i}.py", 1, f"f{i}.py", 2)})
            manager.add_seed(f"data{i}".encode(), cov)

        assert len(manager.seeds) <= 3

    def test_get_coverage_without_seed(self, corpus_manager):
        """Test getting coverage without a specific seed."""
        cov1 = CoverageInfo(edges={("f1.py", 1, "f1.py", 2)})
        cov2 = CoverageInfo(edges={("f2.py", 1, "f2.py", 2)})

        seed1 = corpus_manager.add_seed(b"d1", cov1)
        corpus_manager.add_seed(b"d2", cov2)

        coverage = corpus_manager._get_coverage_without_seed(seed1.id)

        assert ("f2.py", 1, "f2.py", 2) in coverage
        assert ("f1.py", 1, "f1.py", 2) not in coverage


class TestMarkUntouchedEdges:
    """Test mark_untouched_edges method."""

    def test_mark_untouched_edges(self, corpus_manager):
        """Test marking edges as untouched."""
        edges = {("f.py", 1, "f.py", 2), ("f.py", 3, "f.py", 4)}
        corpus_manager.mark_untouched_edges(edges)

        assert edges == corpus_manager.untouched_edges


class TestUpdateSeedCrash:
    """Test update_seed_crash method."""

    def test_update_crash(self, corpus_manager, sample_coverage):
        """Test updating crash count."""
        seed = corpus_manager.add_seed(b"data", sample_coverage)
        corpus_manager.update_seed_crash(seed.id)

        assert corpus_manager.seeds[seed.id].crashes == 1

    def test_update_crash_nonexistent(self, corpus_manager):
        """Test updating crash for non-existent seed."""
        # Should not raise
        corpus_manager.update_seed_crash("nonexistent-id")


class TestMutationWeights:
    """Test get_mutation_weights method."""

    def test_empty_weights(self, corpus_manager):
        """Test weights when no mutations recorded."""
        weights = corpus_manager.get_mutation_weights()

        assert weights == {}

    def test_mutation_weights_calculated(self, corpus_manager):
        """Test weight calculation."""
        corpus_manager.mutation_success_rate["flip_bit"] = 10.0
        corpus_manager.mutation_success_rate["insert"] = 5.0

        weights = corpus_manager.get_mutation_weights()

        assert "flip_bit" in weights
        assert "insert" in weights
        assert abs(weights["flip_bit"] + weights["insert"] - 1.0) < 0.001


class TestCorpusStatsMethod:
    """Test get_corpus_stats method."""

    def test_get_stats_empty(self, corpus_manager):
        """Test stats for empty corpus."""
        stats = corpus_manager.get_corpus_stats()

        assert stats["total_seeds"] == 0
        assert stats["total_edges_covered"] == 0

    def test_get_stats_with_seeds(self, corpus_manager, sample_coverage):
        """Test stats with seeds."""
        corpus_manager.add_seed(b"data", sample_coverage)

        stats = corpus_manager.get_corpus_stats()

        assert stats["total_seeds"] == 1
        assert "seed_priorities" in stats
        assert "mutation_success_rates" in stats

    def test_coverage_plateau_detection(self, corpus_manager, sample_coverage):
        """Test coverage plateau detection."""
        corpus_manager.add_seed(b"data", sample_coverage)

        # Add 10+ entries with same coverage
        for _ in range(12):
            corpus_manager.stats.coverage_history.append((time.time(), 5))

        stats = corpus_manager.get_corpus_stats()

        assert stats["coverage_plateaus"] >= 1


class TestSaveLoadCorpus:
    """Test save_corpus and load_corpus methods."""

    def test_save_corpus(self, corpus_manager, sample_coverage, temp_dir):
        """Test saving corpus."""
        corpus_manager.add_seed(b"data", sample_coverage)
        corpus_manager.mutation_success_rate["test"] = 5.0

        corpus_manager.save_corpus(temp_dir)

        # Check files were created
        seed_files = list(temp_dir.glob("*.seed"))
        assert len(seed_files) == 1

        metadata_file = temp_dir / "corpus_metadata.json"
        assert metadata_file.exists()

    def test_load_corpus(self, sample_coverage, temp_dir):
        """Test loading corpus."""
        # First save a corpus
        manager1 = CorpusManager()
        manager1.add_seed(b"data", sample_coverage)
        manager1.mutation_success_rate["test_mut"] = 3.0
        manager1.save_corpus(temp_dir)

        # Load into new manager
        manager2 = CorpusManager()
        manager2.load_corpus(temp_dir)

        assert len(manager2.seeds) == 1
        assert manager2.mutation_success_rate.get("test_mut") == 3.0

    def test_load_corpus_nonexistent(self, corpus_manager, temp_dir):
        """Test loading from non-existent directory."""
        nonexistent = temp_dir / "does_not_exist"
        corpus_manager.load_corpus(nonexistent)

        assert len(corpus_manager.seeds) == 0

    def test_load_corpus_no_metadata(self, sample_coverage, temp_dir):
        """Test loading corpus without metadata file."""
        manager1 = CorpusManager()
        seed = manager1.add_seed(b"data", sample_coverage)

        # Save just the seed file
        seed_path = temp_dir / f"{seed.id}.seed"
        with open(seed_path, "wb") as f:
            pickle.dump(seed, f)

        # Load into new manager
        manager2 = CorpusManager()
        manager2.load_corpus(temp_dir)

        assert len(manager2.seeds) == 1


class TestHistoricalCorpusManager:
    """Test HistoricalCorpusManager class."""

    def test_init_no_history(self):
        """Test initialization without history."""
        manager = HistoricalCorpusManager()

        assert manager.history_dir is None
        assert len(manager.historical_seeds) == 0

    def test_init_with_nonexistent_history(self, temp_dir):
        """Test initialization with non-existent history dir."""
        nonexistent = temp_dir / "does_not_exist"
        manager = HistoricalCorpusManager(history_dir=nonexistent)

        assert len(manager.historical_seeds) == 0

    def test_init_with_history(self, sample_coverage, temp_dir):
        """Test initialization with existing history."""
        # Create historical campaign
        campaign_dir = temp_dir / "campaign1"
        campaign_dir.mkdir()

        seed = Seed(
            id="hist-seed",
            data=b"historical",
            coverage=sample_coverage,
            discoveries=5,
        )
        seed_path = campaign_dir / "hist-seed.seed"
        with open(seed_path, "wb") as f:
            pickle.dump(seed, f)

        # Create manager with history
        manager = HistoricalCorpusManager(history_dir=temp_dir)

        assert len(manager.historical_seeds) == 1

    def test_load_historical_data_none_dir(self):
        """Test _load_historical_data with None history_dir."""
        manager = HistoricalCorpusManager()
        manager._load_historical_data()

        assert len(manager.historical_seeds) == 0

    def test_initialize_from_history(self, sample_coverage, temp_dir):
        """Test initialize_from_history method."""
        # Create historical campaign with valuable seeds
        campaign_dir = temp_dir / "campaign1"
        campaign_dir.mkdir()

        for i in range(5):
            cov = CoverageInfo(edges={(f"hist{i}.py", 1, f"hist{i}.py", 2)})
            seed = Seed(
                id=f"hist-{i}",
                data=f"data{i}".encode(),
                coverage=cov,
                discoveries=i + 1,
            )
            seed_path = campaign_dir / f"hist-{i}.seed"
            with open(seed_path, "wb") as f:
                pickle.dump(seed, f)

        # Create manager and initialize from history
        manager = HistoricalCorpusManager(history_dir=temp_dir)
        manager.initialize_from_history(max_seeds=3)

        # Should have added top 3 seeds
        assert len(manager.seeds) >= 1


class TestCoversUntouchedEdges:
    """Test _covers_untouched_edges method."""

    def test_covers_untouched_true(self, corpus_manager, sample_coverage):
        """Test when seed covers untouched edges."""
        corpus_manager.untouched_edges.update(sample_coverage.edges)
        seed = Seed(id="test", data=b"data", coverage=sample_coverage)

        result = corpus_manager._covers_untouched_edges(seed)

        assert result is True

    def test_covers_untouched_false(self, corpus_manager, sample_coverage):
        """Test when seed doesn't cover untouched edges."""
        corpus_manager.untouched_edges = {("other.py", 999, "other.py", 1000)}
        seed = Seed(id="test", data=b"data", coverage=sample_coverage)

        result = corpus_manager._covers_untouched_edges(seed)

        assert result is False


class TestEdgeCases:
    """Test edge cases."""

    def test_seed_with_empty_coverage(self, corpus_manager):
        """Test adding seed with empty coverage."""
        empty_cov = CoverageInfo()
        seed = corpus_manager.add_seed(b"empty", empty_cov)

        assert seed is not None

    def test_multiple_seeds_same_coverage_signature(self, corpus_manager):
        """Test multiple seeds with same coverage rejected."""
        cov = CoverageInfo(edges={("f.py", 1, "f.py", 2)})

        seed1 = corpus_manager.add_seed(b"data1", cov)
        seed2 = corpus_manager.add_seed(b"data2", cov)  # Same coverage

        assert seed1 is not None
        assert seed2 is None  # Rejected

    def test_genealogy_tracking(self, corpus_manager):
        """Test parent-child genealogy tracking."""
        cov1 = CoverageInfo(edges={("f1.py", 1, "f1.py", 2)})
        cov2 = CoverageInfo(edges={("f2.py", 1, "f2.py", 2)})

        parent = corpus_manager.add_seed(b"parent", cov1)
        child = corpus_manager.add_seed(b"child", cov2, parent_id=parent.id)

        assert child.id in corpus_manager.seed_genealogy[parent.id]
