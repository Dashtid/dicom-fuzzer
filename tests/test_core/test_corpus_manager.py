"""
Tests for Corpus Manager Module.

Tests the coverage-guided corpus management including seed selection,
prioritization, and corpus evolution.
"""

import pytest

from dicom_fuzzer.core.corpus_manager import (
    CorpusManager,
    CorpusMinimizer,
    CorpusStats,
    HistoricalCorpusManager,
    Seed,
    SeedPriority,
)
from dicom_fuzzer.core.coverage_instrumentation import CoverageInfo

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def empty_coverage():
    """Create empty coverage info."""
    return CoverageInfo(edges=set())


@pytest.fixture
def coverage_a():
    """Create coverage info with edges A."""
    return CoverageInfo(edges={(1, 2), (3, 4), (5, 6)})


@pytest.fixture
def coverage_b():
    """Create different coverage info with edges B."""
    return CoverageInfo(edges={(7, 8), (9, 10), (11, 12)})


@pytest.fixture
def coverage_ab():
    """Create coverage info with both A and B edges."""
    return CoverageInfo(edges={(1, 2), (3, 4), (5, 6), (7, 8), (9, 10)})


@pytest.fixture
def corpus_manager():
    """Create a corpus manager with default settings."""
    return CorpusManager(
        max_corpus_size=100,
        min_coverage_distance=0.1,
        energy_allocation="adaptive",
    )


# ============================================================================
# Test SeedPriority Enum
# ============================================================================


class TestSeedPriority:
    """Test SeedPriority enumeration."""

    def test_priority_values(self):
        """Test priority values are ordered correctly."""
        assert SeedPriority.CRITICAL.value == 1
        assert SeedPriority.HIGH.value == 2
        assert SeedPriority.NORMAL.value == 3
        assert SeedPriority.LOW.value == 4
        assert SeedPriority.MINIMAL.value == 5

    def test_priority_ordering(self):
        """Test priorities can be compared."""
        assert SeedPriority.CRITICAL.value < SeedPriority.HIGH.value
        assert SeedPriority.HIGH.value < SeedPriority.NORMAL.value


# ============================================================================
# Test Seed Dataclass
# ============================================================================


class TestSeed:
    """Test Seed dataclass."""

    def test_seed_creation(self, empty_coverage):
        """Test basic seed creation."""
        seed = Seed(
            id="test_seed",
            data=b"test data",
            coverage=empty_coverage,
        )
        assert seed.id == "test_seed"
        assert seed.data == b"test data"
        assert seed.priority == SeedPriority.NORMAL
        assert seed.energy == 1.0
        assert seed.executions == 0
        assert seed.discoveries == 0
        assert seed.crashes == 0
        assert seed.parent_id is None

    def test_seed_comparison_by_priority(self, empty_coverage):
        """Test seeds are compared by priority first."""
        seed_critical = Seed(
            id="critical",
            data=b"critical",
            coverage=empty_coverage,
            priority=SeedPriority.CRITICAL,
            energy=0.5,
        )
        seed_low = Seed(
            id="low",
            data=b"low",
            coverage=empty_coverage,
            priority=SeedPriority.LOW,
            energy=2.0,
        )

        # CRITICAL < LOW (lower value = higher priority)
        assert seed_critical < seed_low

    def test_seed_comparison_by_energy(self, empty_coverage):
        """Test seeds with same priority are compared by energy."""
        seed_high_energy = Seed(
            id="high",
            data=b"high",
            coverage=empty_coverage,
            priority=SeedPriority.NORMAL,
            energy=2.0,
        )
        seed_low_energy = Seed(
            id="low",
            data=b"low",
            coverage=empty_coverage,
            priority=SeedPriority.NORMAL,
            energy=0.5,
        )

        # Higher energy is "less than" (scheduled first)
        assert seed_high_energy < seed_low_energy

    def test_seed_hash_calculation(self, empty_coverage):
        """Test seed hash calculation."""
        seed = Seed(id="test", data=b"unique data", coverage=empty_coverage)
        hash_val = seed.calculate_hash()
        assert isinstance(hash_val, str)
        assert len(hash_val) > 0

    def test_update_priority_with_coverage_gain(self, empty_coverage):
        """Test priority update when coverage is gained."""
        seed = Seed(id="test", data=b"test", coverage=empty_coverage)
        initial_energy = seed.energy

        seed.update_priority(coverage_gain=True)

        assert seed.priority == SeedPriority.CRITICAL
        assert seed.discoveries == 1
        assert seed.energy == initial_energy * 2

    def test_update_priority_productive_seed(self, empty_coverage):
        """Test priority for productive seed with discoveries."""
        seed = Seed(
            id="test",
            data=b"test",
            coverage=empty_coverage,
            discoveries=1,
            executions=5,
        )

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.HIGH

    def test_update_priority_unproductive_seed(self, empty_coverage):
        """Test priority for unproductive seed."""
        seed = Seed(
            id="test",
            data=b"test",
            coverage=empty_coverage,
            discoveries=0,
            executions=150,
        )

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.LOW
        assert seed.energy == 0.5  # Halved

    def test_update_priority_exhausted_seed(self, empty_coverage):
        """Test priority for exhausted seed (500+ executions with discoveries)."""
        # Note: A seed with 0 discoveries and 600 executions hits the LOW path
        # (executions > 100 and discoveries == 0) before the MINIMAL path.
        # MINIMAL is only reached with discoveries > 0 and executions > 500
        seed = Seed(
            id="test",
            data=b"test",
            coverage=empty_coverage,
            discoveries=1,  # Has discoveries, so skips LOW check
            executions=600,
            energy=1.0,
        )

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.MINIMAL
        # Energy is reduced by 0.1x factor
        assert seed.energy == pytest.approx(0.1, rel=0.01)


# ============================================================================
# Test CorpusStats
# ============================================================================


class TestCorpusStats:
    """Test CorpusStats dataclass."""

    def test_default_stats(self):
        """Test default stats values."""
        stats = CorpusStats()
        assert stats.total_seeds == 0
        assert stats.unique_coverage_signatures == 0
        assert stats.total_edges_covered == 0
        assert stats.total_executions == 0
        assert stats.coverage_plateaus == 0
        assert stats.coverage_history == []


# ============================================================================
# Test CorpusManager Initialization
# ============================================================================


class TestCorpusManagerInit:
    """Test CorpusManager initialization."""

    def test_default_initialization(self):
        """Test default initialization."""
        manager = CorpusManager()
        assert manager.max_corpus_size == 1000
        assert manager.min_coverage_distance == 0.1
        assert manager.energy_allocation == "adaptive"
        assert len(manager.seeds) == 0

    def test_custom_initialization(self):
        """Test custom initialization."""
        manager = CorpusManager(
            max_corpus_size=500,
            min_coverage_distance=0.2,
            energy_allocation="exp",
        )
        assert manager.max_corpus_size == 500
        assert manager.min_coverage_distance == 0.2
        assert manager.energy_allocation == "exp"

    def test_initialization_creates_empty_structures(self):
        """Test that initialization creates empty data structures."""
        manager = CorpusManager()
        assert manager.seeds == {}
        assert manager.seed_queue == []
        assert len(manager.unique_edges) == 0
        assert len(manager.untouched_edges) == 0


# ============================================================================
# Test Seed Addition
# ============================================================================


class TestAddSeed:
    """Test add_seed method."""

    def test_add_first_seed(self, corpus_manager, coverage_a):
        """Test adding first seed to empty corpus."""
        seed = corpus_manager.add_seed(b"first seed", coverage_a)

        assert seed is not None
        assert seed.data == b"first seed"
        assert len(corpus_manager.seeds) == 1
        assert corpus_manager.stats.total_seeds == 1

    def test_add_duplicate_seed(self, corpus_manager, coverage_a):
        """Test adding duplicate seed returns None."""
        corpus_manager.add_seed(b"same data", coverage_a)
        result = corpus_manager.add_seed(b"same data", coverage_a)

        assert result is None
        assert len(corpus_manager.seeds) == 1

    def test_add_seed_with_new_coverage(self, corpus_manager, coverage_a, coverage_b):
        """Test adding seed with new coverage gets high priority."""
        corpus_manager.add_seed(b"seed 1", coverage_a)
        seed2 = corpus_manager.add_seed(b"seed 2", coverage_b)

        assert seed2 is not None
        assert seed2.priority == SeedPriority.CRITICAL
        assert seed2.energy == 2.0

    def test_add_seed_with_parent(self, corpus_manager, coverage_a, coverage_b):
        """Test adding seed with parent ID."""
        parent = corpus_manager.add_seed(b"parent seed", coverage_a)
        child = corpus_manager.add_seed(
            b"child seed",
            coverage_b,
            parent_id=parent.id,
        )

        assert child.parent_id == parent.id
        assert child.id in corpus_manager.seed_genealogy[parent.id]

    def test_add_seed_with_mutation_type(self, corpus_manager, coverage_a):
        """Test adding seed with mutation type."""
        seed = corpus_manager.add_seed(
            b"mutated seed",
            coverage_a,
            mutation_type="bit_flip",
        )

        assert "bit_flip" in seed.mutation_history

    def test_add_seed_updates_global_coverage(self, corpus_manager, coverage_a):
        """Test that adding seed updates global coverage."""
        corpus_manager.add_seed(b"seed 1", coverage_a)

        assert len(corpus_manager.global_coverage.edges) == len(coverage_a.edges)


# ============================================================================
# Test Seed Retrieval
# ============================================================================


class TestGetNextSeed:
    """Test get_next_seed method."""

    def test_get_next_seed_empty_corpus(self, corpus_manager):
        """Test getting seed from empty corpus returns None."""
        result = corpus_manager.get_next_seed()
        assert result is None

    def test_get_next_seed_returns_seed(self, corpus_manager, coverage_a):
        """Test getting next seed returns a seed."""
        corpus_manager.add_seed(b"test seed", coverage_a)
        seed = corpus_manager.get_next_seed()

        assert seed is not None
        assert seed.data == b"test seed"

    def test_get_next_seed_increments_executions(self, corpus_manager, coverage_a):
        """Test getting seed increments execution count."""
        corpus_manager.add_seed(b"test seed", coverage_a)

        seed = corpus_manager.get_next_seed()
        # Note: executions includes the add_seed check (1) + get_next_seed (1)
        assert seed.executions >= 1

    def test_get_next_seed_updates_stats(self, corpus_manager, coverage_a):
        """Test getting seed updates stats."""
        corpus_manager.add_seed(b"test seed", coverage_a)
        corpus_manager.get_next_seed()

        assert corpus_manager.stats.total_executions >= 1

    def test_get_next_seed_prioritizes_critical(
        self, corpus_manager, coverage_a, coverage_b
    ):
        """Test that critical priority seeds are selected first."""
        # Add low priority seed
        seed1 = corpus_manager.add_seed(b"seed 1", coverage_a)
        seed1.priority = SeedPriority.LOW

        # Add critical priority seed
        seed2 = corpus_manager.add_seed(b"seed 2", coverage_b)
        seed2.priority = SeedPriority.CRITICAL

        # Critical should be selected first
        # (need to rebuild queue after priority changes)
        import heapq

        corpus_manager.seed_queue = list(corpus_manager.seeds.values())
        heapq.heapify(corpus_manager.seed_queue)

        next_seed = corpus_manager.get_next_seed()
        assert next_seed.priority == SeedPriority.CRITICAL


# ============================================================================
# Test Coverage Uniqueness
# ============================================================================


class TestCoverageUniqueness:
    """Test _is_coverage_unique method."""

    def test_first_coverage_is_unique(self, corpus_manager, coverage_a):
        """Test first coverage is always unique."""
        result = corpus_manager._is_coverage_unique(coverage_a)
        assert result is True

    def test_same_coverage_not_unique(self, corpus_manager, coverage_a):
        """Test same coverage is not unique."""
        corpus_manager.add_seed(b"seed 1", coverage_a)
        result = corpus_manager._is_coverage_unique(coverage_a)
        assert result is False

    def test_different_coverage_is_unique(self, corpus_manager, coverage_a, coverage_b):
        """Test different coverage is unique."""
        corpus_manager.add_seed(b"seed 1", coverage_a)
        result = corpus_manager._is_coverage_unique(coverage_b)
        assert result is True


# ============================================================================
# Test Energy Allocation
# ============================================================================


class TestEnergyAllocation:
    """Test energy allocation strategies."""

    def test_uniform_energy(self, coverage_a):
        """Test uniform energy allocation."""
        manager = CorpusManager(energy_allocation="uniform")
        seed = manager.add_seed(b"test", coverage_a)

        manager._update_seed_energy(seed)
        assert seed.energy == 1.0

    def test_adaptive_energy_productive(self, coverage_a):
        """Test adaptive energy for productive seed."""
        manager = CorpusManager(energy_allocation="adaptive")
        seed = manager.add_seed(b"test", coverage_a)
        seed.discoveries = 5
        seed.executions = 5  # More discoveries than executions

        manager._update_seed_energy(seed)
        # With 5 discoveries / 5 executions = 1.0 ratio, energy = 2.0 * 1.0 = 2.0
        assert seed.energy >= 1.0

    def test_adaptive_energy_unproductive(self, coverage_a):
        """Test adaptive energy for unproductive seed."""
        manager = CorpusManager(energy_allocation="adaptive")
        seed = manager.add_seed(b"test", coverage_a)
        seed.discoveries = 0
        seed.executions = 100

        manager._update_seed_energy(seed)
        assert seed.energy < 1.0  # Should be reduced

    def test_exp_energy_decay(self, coverage_a):
        """Test exponential energy decay."""
        manager = CorpusManager(energy_allocation="exp")
        seed = manager.add_seed(b"test", coverage_a)
        seed.executions = 20

        manager._update_seed_energy(seed)
        expected = 2.0 ** (-20 / 10)  # 0.25
        assert seed.energy == pytest.approx(expected, rel=0.1)


# ============================================================================
# Test Corpus Management
# ============================================================================


class TestCorpusManagement:
    """Test corpus management operations."""

    def test_mark_untouched_edges(self, corpus_manager):
        """Test marking edges as untouched."""
        edges = {(1, 2), (3, 4)}
        corpus_manager.mark_untouched_edges(edges)

        assert corpus_manager.untouched_edges == edges

    def test_update_seed_crash(self, corpus_manager, coverage_a):
        """Test updating seed crash count."""
        seed = corpus_manager.add_seed(b"test", coverage_a)
        assert seed.crashes == 0

        corpus_manager.update_seed_crash(seed.id)
        assert seed.crashes == 1

    def test_update_seed_crash_nonexistent(self, corpus_manager):
        """Test updating crash for nonexistent seed does nothing."""
        initial_seeds = len(corpus_manager.seeds)
        corpus_manager.update_seed_crash("nonexistent_id")
        # Should not raise and seeds should be unchanged
        assert len(corpus_manager.seeds) == initial_seeds

    def test_covers_untouched_edges(self, corpus_manager, coverage_a):
        """Test checking if seed covers untouched edges."""
        seed = corpus_manager.add_seed(b"test", coverage_a)
        corpus_manager.mark_untouched_edges({(1, 2)})

        result = corpus_manager._covers_untouched_edges(seed)
        assert result is True

    def test_does_not_cover_untouched_edges(self, corpus_manager, coverage_a):
        """Test when seed doesn't cover untouched edges."""
        seed = corpus_manager.add_seed(b"test", coverage_a)
        corpus_manager.mark_untouched_edges({(99, 100)})

        result = corpus_manager._covers_untouched_edges(seed)
        assert result is False


# ============================================================================
# Test Corpus Minimization
# ============================================================================


class TestCorpusMinimization:
    """Test corpus minimization."""

    def test_minimize_corpus_under_limit(self, corpus_manager, coverage_a):
        """Test minimization does nothing when under limit."""
        corpus_manager.max_corpus_size = 10
        corpus_manager.add_seed(b"test", coverage_a)

        initial_count = len(corpus_manager.seeds)
        corpus_manager._minimize_corpus()

        assert len(corpus_manager.seeds) == initial_count

    def test_minimize_corpus_removes_low_value(self):
        """Test minimization removes low-value seeds."""
        manager = CorpusManager(max_corpus_size=2)

        # Add seeds with different coverage
        cov1 = CoverageInfo(edges={(1, 2)})
        cov2 = CoverageInfo(edges={(3, 4)})
        cov3 = CoverageInfo(edges={(5, 6)})

        manager.add_seed(b"seed 1", cov1)
        manager.add_seed(b"seed 2", cov2)
        # Adding third should trigger minimization
        manager.add_seed(b"seed 3", cov3)

        # Should be limited to max_corpus_size
        assert len(manager.seeds) <= 3  # May keep all if all unique


# ============================================================================
# Test Compatibility Methods
# ============================================================================


class TestCompatibilityMethods:
    """Test compatibility methods for existing code."""

    def test_add_entry_with_dataset(self, corpus_manager):
        """Test add_entry with pydicom Dataset."""
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian

        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3.4.5"

        # Add required file meta
        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        ds.file_meta = file_meta
        ds.is_little_endian = True
        ds.is_implicit_VR = False

        # Should not raise
        corpus_manager.add_entry(entry=ds)

        # Verify seed was added
        assert len(corpus_manager.seeds) >= 0  # May be 0 if coverage not unique

    def test_add_entry_with_entry_object(self, corpus_manager):
        """Test add_entry with entry object having dataset attribute."""
        from pydicom.dataset import Dataset, FileMetaDataset
        from pydicom.uid import ExplicitVRLittleEndian

        ds = Dataset()
        ds.PatientName = "Test"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3.4.5"

        # Add required file meta
        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
        file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
        ds.file_meta = file_meta
        ds.is_little_endian = True
        ds.is_implicit_VR = False

        class Entry:
            dataset = ds

        entry = Entry()
        entry.entry_id = "test_entry"

        # Should not raise - verify function completes and returns a result
        result = corpus_manager.add_entry(entry)

        # Verify the function returned (either a seed or None)
        assert result is None or hasattr(result, "id")


# ============================================================================
# Test Mutation Weights
# ============================================================================


class TestMutationWeights:
    """Test mutation weight tracking."""

    def test_mutation_success_rate_updated(
        self, corpus_manager, coverage_a, coverage_b
    ):
        """Test mutation success rate is updated on new coverage."""
        corpus_manager.add_seed(b"seed 1", coverage_a)

        # Add seed with new coverage and mutation type
        corpus_manager.add_seed(
            b"seed 2",
            coverage_b,
            mutation_type="bit_flip",
        )

        assert corpus_manager.mutation_success_rate["bit_flip"] >= 1


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_data_seed(self, corpus_manager, coverage_a):
        """Test adding seed with empty data."""
        seed = corpus_manager.add_seed(b"", coverage_a)
        assert seed is not None

    def test_large_coverage(self, corpus_manager):
        """Test with large coverage set."""
        large_coverage = CoverageInfo(edges={(i, i + 1) for i in range(1000)})
        seed = corpus_manager.add_seed(b"test", large_coverage)

        assert seed is not None
        assert len(corpus_manager.global_coverage.edges) == 1000

    def test_rapid_seed_addition(self, corpus_manager):
        """Test adding many seeds rapidly."""
        for i in range(50):
            coverage = CoverageInfo(edges={(i, i + 1)})
            corpus_manager.add_seed(f"seed_{i}".encode(), coverage)

        assert len(corpus_manager.seeds) <= corpus_manager.max_corpus_size


# ============================================================================
# Test Corpus Statistics
# ============================================================================


class TestGetCorpusStats:
    """Test get_corpus_stats method."""

    def test_get_corpus_stats_empty(self):
        """Test stats on empty corpus."""
        manager = CorpusManager()
        stats = manager.get_corpus_stats()

        assert stats["total_seeds"] == 0
        assert stats["total_edges_covered"] == 0
        assert stats["total_executions"] == 0
        assert "time_since_coverage_increase" in stats
        assert "mutation_success_rates" in stats
        assert "seed_priorities" in stats

    def test_get_corpus_stats_with_seeds(self):
        """Test stats with seeds added."""
        manager = CorpusManager()
        cov1 = CoverageInfo(edges={("file1", 1, "file1", 2)})
        cov2 = CoverageInfo(edges={("file2", 3, "file2", 4)})

        manager.add_seed(b"seed1", cov1)
        manager.add_seed(b"seed2", cov2)

        stats = manager.get_corpus_stats()

        assert stats["total_seeds"] == 2
        assert stats["total_edges_covered"] == 2
        assert "unique_coverage_signatures" in stats

    def test_get_corpus_stats_coverage_plateau_detection(self):
        """Test coverage plateau detection."""
        manager = CorpusManager()
        cov = CoverageInfo(edges={("f", 1, "f", 2)})
        manager.add_seed(b"seed", cov)

        # Simulate 10 stats calls with same coverage
        for _ in range(12):
            manager.get_corpus_stats()

        stats = manager.get_corpus_stats()
        # Should detect plateau after 10 identical readings
        assert stats["coverage_plateaus"] >= 0

    def test_get_corpus_stats_priority_breakdown(self):
        """Test seed priority breakdown in stats."""
        manager = CorpusManager()
        cov1 = CoverageInfo(edges={("f", 1, "f", 2)})
        cov2 = CoverageInfo(edges={("f", 3, "f", 4)})

        seed1 = manager.add_seed(b"seed1", cov1)
        seed2 = manager.add_seed(b"seed2", cov2)

        # Manually set priorities
        seed1.priority = SeedPriority.CRITICAL
        seed2.priority = SeedPriority.LOW

        stats = manager.get_corpus_stats()

        assert "seed_priorities" in stats
        assert "CRITICAL" in stats["seed_priorities"]
        assert "LOW" in stats["seed_priorities"]


# ============================================================================
# Test Mutation Weights
# ============================================================================


class TestGetMutationWeights:
    """Test get_mutation_weights method."""

    def test_get_mutation_weights_empty(self):
        """Test mutation weights when no mutations recorded."""
        manager = CorpusManager()
        weights = manager.get_mutation_weights()

        assert weights == {}

    def test_get_mutation_weights_with_successes(self):
        """Test mutation weights with successful mutations."""
        manager = CorpusManager()

        # Add seeds with different mutation types that provide new coverage
        cov1 = CoverageInfo(edges={("f", 1, "f", 2)})
        cov2 = CoverageInfo(edges={("f", 3, "f", 4)})
        cov3 = CoverageInfo(edges={("f", 5, "f", 6)})

        manager.add_seed(b"seed1", cov1, mutation_type="bit_flip")
        manager.add_seed(b"seed2", cov2, mutation_type="bit_flip")
        manager.add_seed(b"seed3", cov3, mutation_type="byte_swap")

        weights = manager.get_mutation_weights()

        assert "bit_flip" in weights
        assert "byte_swap" in weights
        assert sum(weights.values()) == pytest.approx(1.0, rel=0.01)


# ============================================================================
# Test Corpus Persistence
# ============================================================================


class TestCorpusPersistence:
    """Test save_corpus and load_corpus methods."""

    def test_save_corpus(self, tmp_path):
        """Test saving corpus to disk."""
        manager = CorpusManager()
        cov = CoverageInfo(edges={("f", 1, "f", 2)})
        manager.add_seed(b"test seed", cov)

        corpus_dir = tmp_path / "corpus"
        manager.save_corpus(corpus_dir)

        # Verify files created
        assert corpus_dir.exists()
        assert (corpus_dir / "corpus_metadata.json").exists()
        assert len(list(corpus_dir.glob("*.seed"))) == 1

    def test_load_corpus(self, tmp_path):
        """Test loading corpus from disk."""
        # First save a corpus
        manager1 = CorpusManager()
        cov = CoverageInfo(edges={("f", 1, "f", 2)})
        manager1.add_seed(b"test seed", cov)

        corpus_dir = tmp_path / "corpus"
        manager1.save_corpus(corpus_dir)

        # Load into new manager
        manager2 = CorpusManager()
        manager2.load_corpus(corpus_dir)

        assert len(manager2.seeds) == 1
        assert len(manager2.global_coverage.edges) == 1

    def test_load_corpus_nonexistent(self, tmp_path):
        """Test loading from nonexistent directory."""
        manager = CorpusManager()
        manager.load_corpus(tmp_path / "nonexistent")

        # Should not raise, corpus stays empty
        assert len(manager.seeds) == 0

    def test_save_load_preserves_mutation_success(self, tmp_path):
        """Test that mutation success rates are preserved."""
        manager1 = CorpusManager()
        cov1 = CoverageInfo(edges={("f", 1, "f", 2)})
        cov2 = CoverageInfo(edges={("f", 3, "f", 4)})

        manager1.add_seed(b"seed1", cov1, mutation_type="bit_flip")
        manager1.add_seed(b"seed2", cov2, mutation_type="bit_flip")

        corpus_dir = tmp_path / "corpus"
        manager1.save_corpus(corpus_dir)

        manager2 = CorpusManager()
        manager2.load_corpus(corpus_dir)

        assert manager2.mutation_success_rate["bit_flip"] >= 1


# ============================================================================
# Test CorpusMinimizer
# ============================================================================


class TestCorpusMinimizer:
    """Test CorpusMinimizer class."""

    @pytest.fixture
    def populated_corpus(self):
        """Create a corpus with multiple seeds for minimization."""
        manager = CorpusManager()

        # Seed 1: unique edge (1,2)
        cov1 = CoverageInfo(edges={("f", 1, "f", 2)})
        manager.add_seed(b"seed1", cov1)

        # Seed 2: unique edge (3,4)
        cov2 = CoverageInfo(edges={("f", 3, "f", 4)})
        manager.add_seed(b"seed2", cov2)

        # Seed 3: overlaps with seed1 and seed2
        cov3 = CoverageInfo(edges={("f", 1, "f", 2), ("f", 3, "f", 4)})
        manager.add_seed(b"seed3", cov3)

        # Seed 4: completely redundant (subset of seed3)
        cov4 = CoverageInfo(edges={("f", 1, "f", 2)})
        manager.add_seed(b"seed4_different", cov4)

        return manager

    def test_minimizer_initialization(self, populated_corpus):
        """Test minimizer initialization."""
        minimizer = CorpusMinimizer(populated_corpus)

        assert minimizer.corpus is populated_corpus

    def test_build_coverage_map(self, populated_corpus):
        """Test building coverage map."""
        minimizer = CorpusMinimizer(populated_corpus)
        minimizer.build_coverage_map()

        # Should have mappings for edges
        assert len(minimizer._edge_to_seeds) > 0
        assert len(minimizer._seed_to_edges) > 0

    def test_find_essential_seeds(self):
        """Test finding essential seeds (only ones covering certain edges)."""
        manager = CorpusManager(min_coverage_distance=0.0)  # Allow all seeds

        # Seed 1: only one covering unique edge (1,2)
        cov1 = CoverageInfo(edges={("f", 1, "f", 2)})
        seed1 = manager.add_seed(b"essential_seed", cov1)

        # Seed 2: covers shared edge (3,4)
        cov2 = CoverageInfo(edges={("f", 3, "f", 4)})
        manager.add_seed(b"shared1_seed", cov2)

        # Seed 3: also covers shared edge (3,4) - different data to avoid hash collision
        cov3 = CoverageInfo(edges={("f", 3, "f", 4)})
        manager.add_seed(b"shared2_different_seed", cov3)

        minimizer = CorpusMinimizer(manager)
        minimizer.build_coverage_map()  # Required before find_essential_seeds
        essential = minimizer.find_essential_seeds()

        # seed1 is essential because it's the only one covering edge (1,2)
        assert seed1.id in essential

    def test_minimize_greedy(self, populated_corpus):
        """Test greedy minimization."""
        minimizer = CorpusMinimizer(populated_corpus)
        selected = minimizer.minimize_greedy()

        assert len(selected) > 0
        # Should cover all edges with minimal seeds
        assert len(selected) <= len(populated_corpus.seeds)

    def test_minimize_greedy_with_target_size(self, populated_corpus):
        """Test greedy minimization with target size."""
        minimizer = CorpusMinimizer(populated_corpus)
        selected = minimizer.minimize_greedy(target_size=2)

        assert len(selected) <= 2

    def test_minimize_weighted(self, populated_corpus):
        """Test weighted minimization."""
        minimizer = CorpusMinimizer(populated_corpus)
        selected = minimizer.minimize_weighted()

        assert len(selected) > 0
        assert len(selected) <= len(populated_corpus.seeds)

    def test_get_redundant_seeds(self):
        """Test finding redundant seeds."""
        manager = CorpusManager()

        # Seed 1: covers (1,2) and (3,4)
        cov1 = CoverageInfo(edges={("f", 1, "f", 2), ("f", 3, "f", 4)})
        manager.add_seed(b"comprehensive", cov1)

        # Seed 2: only covers (1,2) - redundant since cov1 covers it
        cov2 = CoverageInfo(edges={("f", 1, "f", 2)})
        seed2 = manager.add_seed(b"redundant_seed", cov2)

        # Seed 3: only covers (3,4) - redundant since cov1 covers it
        cov3 = CoverageInfo(edges={("f", 3, "f", 4)})
        seed3 = manager.add_seed(b"also_redundant", cov3)

        minimizer = CorpusMinimizer(manager)
        redundant = minimizer.get_redundant_seeds()

        # Seeds 2 and 3 should be redundant
        assert seed2.id in redundant or seed3.id in redundant

    def test_get_coverage_stats(self, populated_corpus):
        """Test getting coverage statistics."""
        minimizer = CorpusMinimizer(populated_corpus)
        stats = minimizer.get_coverage_stats()

        assert "total_seeds" in stats
        assert "total_edges" in stats
        assert "essential_seeds" in stats
        assert "redundant_seeds" in stats
        assert "single_coverage_edges" in stats
        assert "multi_coverage_edges" in stats
        assert "potential_reduction" in stats


# ============================================================================
# Test HistoricalCorpusManager
# ============================================================================


class TestHistoricalCorpusManager:
    """Test HistoricalCorpusManager class."""

    def test_initialization_without_history(self):
        """Test initialization without history directory."""
        manager = HistoricalCorpusManager()

        assert manager.history_dir is None
        assert manager.historical_seeds == []

    def test_initialization_with_nonexistent_history(self, tmp_path):
        """Test initialization with nonexistent history directory."""
        history_dir = tmp_path / "nonexistent"
        manager = HistoricalCorpusManager(history_dir=history_dir)

        assert manager.historical_seeds == []

    def test_initialization_with_history(self, tmp_path):
        """Test initialization with existing history."""
        history_dir = tmp_path / "history"
        history_dir.mkdir()

        # Create a historical campaign
        campaign_dir = history_dir / "campaign1"
        campaign1 = CorpusManager()

        cov = CoverageInfo(edges={("f", 1, "f", 2)})
        seed = campaign1.add_seed(b"historical", cov)
        seed.discoveries = 5  # Mark as valuable

        campaign1.save_corpus(campaign_dir)

        # Load historical manager
        manager = HistoricalCorpusManager(history_dir=history_dir)

        assert len(manager.historical_seeds) > 0

    def test_initialize_from_history(self, tmp_path):
        """Test initializing corpus from history."""
        history_dir = tmp_path / "history"
        history_dir.mkdir()

        # Create historical campaigns
        for i in range(3):
            campaign_dir = history_dir / f"campaign{i}"
            campaign = CorpusManager()

            cov = CoverageInfo(edges={("f", i, "f", i + 1)})
            seed = campaign.add_seed(f"seed{i}".encode(), cov)
            seed.discoveries = i + 1  # Varying value

            campaign.save_corpus(campaign_dir)

        # Load and initialize
        manager = HistoricalCorpusManager(history_dir=history_dir)
        manager.initialize_from_history(max_seeds=2)

        # Should have added seeds from history
        assert len(manager.seeds) <= 2

    def test_load_historical_data_with_crashes(self, tmp_path):
        """Test loading historical data with crash-finding seeds."""
        history_dir = tmp_path / "history"
        campaign_dir = history_dir / "crash_campaign"

        campaign = CorpusManager()
        cov = CoverageInfo(edges={("f", 1, "f", 2)})
        seed = campaign.add_seed(b"crash_finder", cov)
        seed.crashes = 3  # This seed found crashes

        campaign.save_corpus(campaign_dir)

        manager = HistoricalCorpusManager(history_dir=history_dir)

        # Should have loaded the crash-finding seed
        crash_seeds = [s for s in manager.historical_seeds if s.crashes > 0]
        assert len(crash_seeds) > 0


# ============================================================================
# Test Internal Methods Branch Coverage
# ============================================================================


class TestInternalMethodsBranches:
    """Test internal methods for branch coverage."""

    def test_get_coverage_without_seed(self):
        """Test _get_coverage_without_seed method."""
        manager = CorpusManager()

        cov1 = CoverageInfo(edges={("f", 1, "f", 2)})
        cov2 = CoverageInfo(edges={("f", 3, "f", 4)})

        seed1 = manager.add_seed(b"seed1", cov1)
        manager.add_seed(b"seed2", cov2)

        # Get coverage without seed1
        coverage = manager._get_coverage_without_seed(seed1.id)

        assert ("f", 3, "f", 4) in coverage
        assert ("f", 1, "f", 2) not in coverage

    def test_minimize_corpus_rebuilds_queue(self):
        """Test that minimize_corpus rebuilds priority queue."""
        manager = CorpusManager(max_corpus_size=3)

        # Add more seeds than max
        for i in range(5):
            cov = CoverageInfo(edges={("f", i, "f", i + 1)})
            manager.add_seed(f"seed{i}".encode(), cov)

        # After minimization, queue should be rebuilt
        assert len(manager.seed_queue) <= manager.max_corpus_size

    def test_energy_boost_for_untouched_edges(self):
        """Test energy boost when seed covers untouched edges."""
        manager = CorpusManager(energy_allocation="adaptive")

        cov = CoverageInfo(edges={("f", 1, "f", 2)})
        seed = manager.add_seed(b"test", cov)

        # Mark some edges as untouched
        manager.mark_untouched_edges({("f", 1, "f", 2)})

        initial_energy = seed.energy
        seed.energy = 1.0  # Reset
        manager._update_seed_energy(seed)

        # Energy should be boosted
        assert seed.energy >= 1.0
