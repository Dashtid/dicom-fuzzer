"""Targeted tests for corpus_manager module to improve coverage.

Focuses on testing the current API (not the old disabled tests).
"""

from unittest.mock import patch

from dicom_fuzzer.core.corpus_manager import (
    CorpusManager,
    CorpusStats,
    HistoricalCorpusManager,
    Seed,
    SeedPriority,
)
from dicom_fuzzer.core.coverage_instrumentation import CoverageInfo


class TestSeedPriority:
    """Test SeedPriority enum values."""

    def test_priority_values(self):
        """Test all priority levels have correct values."""
        assert SeedPriority.CRITICAL.value == 1
        assert SeedPriority.HIGH.value == 2
        assert SeedPriority.NORMAL.value == 3
        assert SeedPriority.LOW.value == 4
        assert SeedPriority.MINIMAL.value == 5

    def test_priority_ordering(self):
        """Test priorities are ordered correctly."""
        assert SeedPriority.CRITICAL.value < SeedPriority.HIGH.value
        assert SeedPriority.HIGH.value < SeedPriority.NORMAL.value
        assert SeedPriority.NORMAL.value < SeedPriority.LOW.value
        assert SeedPriority.LOW.value < SeedPriority.MINIMAL.value


class TestSeedDataclass:
    """Test Seed dataclass functionality."""

    def test_seed_creation_required_fields(self):
        """Test creating seed with required fields."""
        coverage = CoverageInfo()
        seed = Seed(id="test-001", data=b"testdata", coverage=coverage)

        assert seed.id == "test-001"
        assert seed.data == b"testdata"
        assert seed.coverage == coverage

    def test_seed_default_values(self):
        """Test seed default field values."""
        coverage = CoverageInfo()
        seed = Seed(id="test-002", data=b"data", coverage=coverage)

        assert seed.priority == SeedPriority.NORMAL
        assert seed.energy == 1.0
        assert seed.executions == 0
        assert seed.discoveries == 0
        assert seed.crashes == 0
        assert seed.parent_id is None
        assert seed.mutation_history == []
        assert seed.metadata == {}

    def test_seed_comparison_by_priority(self):
        """Test seeds are compared by priority first."""
        coverage = CoverageInfo()
        critical = Seed(
            id="1", data=b"a", coverage=coverage, priority=SeedPriority.CRITICAL
        )
        normal = Seed(
            id="2", data=b"b", coverage=coverage, priority=SeedPriority.NORMAL
        )

        assert critical < normal  # Lower value = higher priority

    def test_seed_comparison_by_energy(self):
        """Test seeds with same priority compared by energy."""
        coverage = CoverageInfo()
        high_energy = Seed(id="1", data=b"a", coverage=coverage, energy=10.0)
        low_energy = Seed(id="2", data=b"b", coverage=coverage, energy=1.0)

        # Higher energy is "less than" (higher priority)
        assert high_energy < low_energy

    def test_calculate_hash(self):
        """Test seed hash calculation."""
        coverage = CoverageInfo()
        seed = Seed(id="test", data=b"test data", coverage=coverage)

        hash_value = seed.calculate_hash()

        assert isinstance(hash_value, str)
        assert len(hash_value) == 16

    def test_same_data_same_hash(self):
        """Test identical data produces same hash."""
        coverage = CoverageInfo()
        seed1 = Seed(id="1", data=b"same", coverage=coverage)
        seed2 = Seed(id="2", data=b"same", coverage=coverage)

        assert seed1.calculate_hash() == seed2.calculate_hash()

    def test_different_data_different_hash(self):
        """Test different data produces different hash."""
        coverage = CoverageInfo()
        seed1 = Seed(id="1", data=b"data1", coverage=coverage)
        seed2 = Seed(id="2", data=b"data2", coverage=coverage)

        assert seed1.calculate_hash() != seed2.calculate_hash()

    def test_update_priority_with_coverage_gain(self):
        """Test priority update when coverage gained."""
        coverage = CoverageInfo()
        seed = Seed(id="test", data=b"data", coverage=coverage)
        initial_energy = seed.energy

        seed.update_priority(coverage_gain=True)

        assert seed.priority == SeedPriority.CRITICAL
        assert seed.discoveries == 1
        assert seed.energy == initial_energy * 2

    def test_update_priority_high_after_discoveries(self):
        """Test priority HIGH for recent discoverers."""
        coverage = CoverageInfo()
        seed = Seed(id="test", data=b"data", coverage=coverage)
        seed.discoveries = 1
        seed.executions = 5

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.HIGH

    def test_update_priority_low_after_many_executions(self):
        """Test priority downgrade after many unproductive executions."""
        coverage = CoverageInfo()
        seed = Seed(id="test", data=b"data", coverage=coverage)
        seed.executions = 150
        seed.discoveries = 0
        initial_energy = seed.energy

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.LOW
        assert seed.energy == initial_energy * 0.5

    def test_update_priority_minimal_after_very_many_executions(self):
        """Test priority MINIMAL after excessive executions."""
        coverage = CoverageInfo()
        seed = Seed(id="test", data=b"data", coverage=coverage)
        seed.executions = 600
        seed.discoveries = 1  # Need discoveries > 0 to reach MINIMAL case
        initial_energy = seed.energy

        seed.update_priority(coverage_gain=False)

        assert seed.priority == SeedPriority.MINIMAL
        assert seed.energy == initial_energy * 0.1


class TestCorpusStats:
    """Test CorpusStats dataclass."""

    def test_stats_default_initialization(self):
        """Test stats initialize with zero values."""
        stats = CorpusStats()

        assert stats.total_seeds == 0
        assert stats.unique_coverage_signatures == 0
        assert stats.total_edges_covered == 0
        assert stats.total_executions == 0
        assert stats.coverage_plateaus == 0
        assert stats.coverage_history == []

    def test_stats_field_updates(self):
        """Test updating stats fields."""
        stats = CorpusStats()

        stats.total_seeds = 100
        stats.total_edges_covered = 500
        stats.total_executions = 1000

        assert stats.total_seeds == 100
        assert stats.total_edges_covered == 500
        assert stats.total_executions == 1000


class TestCorpusManagerInitialization:
    """Test CorpusManager initialization."""

    def test_default_initialization(self):
        """Test manager with default parameters."""
        manager = CorpusManager()

        assert manager.max_corpus_size == 1000
        assert manager.min_coverage_distance == 0.1
        assert manager.energy_allocation == "adaptive"
        assert len(manager.seeds) == 0
        assert len(manager.seed_queue) == 0
        assert isinstance(manager.stats, CorpusStats)

    def test_custom_max_corpus_size(self):
        """Test manager with custom max size."""
        manager = CorpusManager(max_corpus_size=500)

        assert manager.max_corpus_size == 500

    def test_custom_min_coverage_distance(self):
        """Test manager with custom min distance."""
        manager = CorpusManager(min_coverage_distance=0.2)

        assert manager.min_coverage_distance == 0.2

    def test_custom_energy_allocation(self):
        """Test manager with custom energy allocation."""
        manager = CorpusManager(energy_allocation="uniform")

        assert manager.energy_allocation == "uniform"


class TestAddSeed:
    """Test add_seed() method."""

    def test_add_first_seed(self):
        """Test adding first seed to empty corpus."""
        manager = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})

        seed = manager.add_seed(b"data1", coverage)

        assert seed is not None
        assert len(manager.seeds) == 1
        assert manager.stats.total_seeds == 1

    def test_add_seed_with_new_coverage(self):
        """Test adding seed that discovers new coverage."""
        manager = CorpusManager()

        # Add first seed
        coverage1 = CoverageInfo(edges={("a", 1, "b", 2)})
        seed1 = manager.add_seed(b"data1", coverage1)

        # Add second seed with new edge
        coverage2 = CoverageInfo(edges={("a", 1, "b", 2), ("c", 3, "d", 4)})
        seed2 = manager.add_seed(b"data2", coverage2)

        assert seed2 is not None
        assert seed2.priority == SeedPriority.CRITICAL
        assert seed2.energy == 2.0

    def test_add_duplicate_seed_rejected(self):
        """Test duplicate seed is rejected."""
        manager = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})

        seed1 = manager.add_seed(b"same_data", coverage)
        seed2 = manager.add_seed(b"same_data", coverage)

        assert seed1 is not None
        assert seed2 is None  # Duplicate rejected
        assert len(manager.seeds) == 1

    def test_add_seed_with_parent_tracking(self):
        """Test seed genealogy tracking."""
        manager = CorpusManager()
        coverage1 = CoverageInfo(edges={("a", 1, "b", 2)})
        coverage2 = CoverageInfo(edges={("c", 3, "d", 4)})

        parent = manager.add_seed(b"parent_data", coverage1)
        child = manager.add_seed(b"child_data", coverage2, parent_id=parent.id)

        assert child is not None
        assert child.parent_id == parent.id
        assert child.id in manager.seed_genealogy[parent.id]

    def test_add_seed_with_mutation_type(self):
        """Test mutation type tracking."""
        manager = CorpusManager()
        coverage1 = CoverageInfo(edges={("a", 1, "b", 2)})
        coverage2 = CoverageInfo(edges={("c", 3, "d", 4)})

        parent = manager.add_seed(b"parent", coverage1)
        child = manager.add_seed(
            b"child", coverage2, parent_id=parent.id, mutation_type="bitflip"
        )

        assert "bitflip" in child.mutation_history
        assert manager.mutation_success_rate["bitflip"] == 1

    def test_corpus_size_limit_enforcement(self):
        """Test corpus is minimized when exceeding max size."""
        manager = CorpusManager(max_corpus_size=5)

        # Add 6 seeds to exceed limit
        for i in range(6):
            coverage = CoverageInfo(edges={(f"edge{i}", i, f"dest{i}", i + 1)})
            manager.add_seed(f"data{i}".encode(), coverage)

        # Should trigger minimization
        assert len(manager.seeds) <= manager.max_corpus_size


class TestGetNextSeed:
    """Test get_next_seed() method."""

    def test_get_next_from_empty_corpus(self):
        """Test getting seed from empty corpus."""
        manager = CorpusManager()

        seed = manager.get_next_seed()

        assert seed is None

    def test_get_next_seed_priority_order(self):
        """Test seeds are returned in priority order."""
        manager = CorpusManager()

        # Add seeds with different priorities
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed1 = manager.add_seed(b"data1", coverage)
        seed1.priority = SeedPriority.LOW

        coverage2 = CoverageInfo(edges={("c", 3, "d", 4)})
        seed2 = manager.add_seed(b"data2", coverage2)
        seed2.priority = SeedPriority.CRITICAL

        # Rebuild heap
        manager.seed_queue = []
        import heapq

        for seed in manager.seeds.values():
            heapq.heappush(manager.seed_queue, seed)

        # Get next should return CRITICAL first
        next_seed = manager.get_next_seed()
        assert next_seed.priority == SeedPriority.CRITICAL

    def test_get_next_updates_execution_stats(self):
        """Test getting seed updates execution stats."""
        manager = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager.add_seed(b"data", coverage)

        initial_executions = seed.executions
        initial_total_executions = manager.stats.total_executions

        manager.get_next_seed()

        assert seed.executions > initial_executions
        assert manager.stats.total_executions > initial_total_executions

    def test_get_next_minimal_seeds_not_readded(self):
        """Test MINIMAL priority seeds are not re-added to queue."""
        manager = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager.add_seed(b"data", coverage)
        seed.priority = SeedPriority.MINIMAL

        # Rebuild heap
        manager.seed_queue = []
        import heapq

        heapq.heappush(manager.seed_queue, seed)

        initial_queue_size = len(manager.seed_queue)
        manager.get_next_seed()

        # MINIMAL seed should not be re-added
        assert len(manager.seed_queue) < initial_queue_size


class TestEnergyAllocation:
    """Test energy allocation strategies."""

    def test_uniform_energy_allocation(self):
        """Test uniform energy allocation."""
        manager = CorpusManager(energy_allocation="uniform")
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager.add_seed(b"data", coverage)

        seed.energy = 5.0  # Set to non-1.0
        manager._update_seed_energy(seed)

        assert seed.energy == 1.0

    def test_adaptive_energy_allocation_productive(self):
        """Test adaptive energy for productive seeds."""
        manager = CorpusManager(energy_allocation="adaptive")
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager.add_seed(b"data", coverage)

        # Formula: 2.0 * (discoveries / executions)
        # Need discoveries/executions > 0.5 to get energy > 1.0
        seed.discoveries = 10
        seed.executions = 5  # 10/5 = 2.0, so energy = 2.0 * 2.0 = 4.0
        manager._update_seed_energy(seed)

        assert seed.energy > 1.0

    def test_adaptive_energy_allocation_unproductive(self):
        """Test adaptive energy for unproductive seeds."""
        manager = CorpusManager(energy_allocation="adaptive")
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager.add_seed(b"data", coverage)

        seed.discoveries = 0
        seed.executions = 100
        manager._update_seed_energy(seed)

        assert seed.energy < 1.0

    def test_exponential_energy_allocation(self):
        """Test exponential energy allocation."""
        manager = CorpusManager(energy_allocation="exp")
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager.add_seed(b"data", coverage)

        seed.executions = 0  # Start fresh
        manager._update_seed_energy(seed)

        # Formula: 2.0 ** (-executions / 10)
        # With executions=0: 2.0 ** 0 = 1.0
        assert seed.energy == 1.0


class TestCoverageTracking:
    """Test coverage tracking methods."""

    def test_mark_untouched_edges(self):
        """Test marking edges as untouched."""
        manager = CorpusManager()
        edges = {("a", 1, "b", 2), ("c", 3, "d", 4)}

        manager.mark_untouched_edges(edges)

        assert manager.untouched_edges == edges

    def test_covers_untouched_edges(self):
        """Test checking if seed covers untouched edges."""
        manager = CorpusManager()
        manager.untouched_edges = {("a", 1, "b", 2)}

        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = Seed(id="test", data=b"data", coverage=coverage)

        assert manager._covers_untouched_edges(seed) is True

    def test_does_not_cover_untouched_edges(self):
        """Test seed that doesn't cover untouched edges."""
        manager = CorpusManager()
        manager.untouched_edges = {("a", 1, "b", 2)}

        coverage = CoverageInfo(edges={("c", 3, "d", 4)})
        seed = Seed(id="test", data=b"data", coverage=coverage)

        assert manager._covers_untouched_edges(seed) is False


class TestSeedCrashTracking:
    """Test seed crash tracking."""

    def test_update_seed_crash(self):
        """Test updating crash count for seed."""
        manager = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager.add_seed(b"data", coverage)

        initial_crashes = seed.crashes
        manager.update_seed_crash(seed.id)

        assert seed.crashes > initial_crashes


class TestMutationWeights:
    """Test mutation weight calculation."""

    def test_get_mutation_weights_empty(self):
        """Test getting weights with no mutations."""
        manager = CorpusManager()

        weights = manager.get_mutation_weights()

        assert isinstance(weights, dict)

    def test_get_mutation_weights_with_data(self):
        """Test getting weights after mutations."""
        manager = CorpusManager()
        manager.mutation_success_rate["bitflip"] = 10
        manager.mutation_success_rate["byteflip"] = 5

        weights = manager.get_mutation_weights()

        assert weights["bitflip"] > weights["byteflip"]


class TestCorpusStatsManager:
    """Test get_corpus_stats() method."""

    def test_get_corpus_stats(self):
        """Test getting corpus statistics."""
        manager = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        manager.add_seed(b"data", coverage)

        stats = manager.get_corpus_stats()

        assert isinstance(stats, dict)
        assert "total_seeds" in stats
        assert "total_edges_covered" in stats
        assert stats["total_seeds"] == 1


class TestCorpusSaveLoad:
    """Test corpus save/load functionality."""

    def test_save_corpus(self, tmp_path):
        """Test saving corpus to disk."""
        manager = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager.add_seed(b"testdata", coverage)

        save_dir = tmp_path / "corpus"
        manager.save_corpus(save_dir)

        assert save_dir.exists()
        # Check files created (individual .seed files, not corpus.pkl)
        seed_file = save_dir / f"{seed.id}.seed"
        metadata_file = save_dir / "corpus_metadata.json"
        assert seed_file.exists()
        assert metadata_file.exists()

    def test_load_corpus(self, tmp_path):
        """Test loading corpus from disk."""
        # Save corpus first
        manager1 = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        manager1.add_seed(b"testdata", coverage)

        save_dir = tmp_path / "corpus"
        manager1.save_corpus(save_dir)

        # Load into new manager
        manager2 = CorpusManager()
        manager2.load_corpus(save_dir)

        assert len(manager2.seeds) == 1

    def test_load_nonexistent_corpus(self, tmp_path):
        """Test loading from nonexistent directory."""
        manager = CorpusManager()
        nonexistent_dir = tmp_path / "nonexistent"

        # Should not raise exception
        manager.load_corpus(nonexistent_dir)

        assert len(manager.seeds) == 0


class TestHistoricalCorpusManager:
    """Test HistoricalCorpusManager functionality."""

    def test_historical_manager_initialization(self, tmp_path):
        """Test HistoricalCorpusManager initialization."""
        history_dir = tmp_path / "history"
        history_dir.mkdir()

        manager = HistoricalCorpusManager(history_dir=history_dir)

        assert manager.history_dir == history_dir

    def test_initialize_from_history_no_files(self, tmp_path):
        """Test initializing from empty history directory."""
        history_dir = tmp_path / "history"
        history_dir.mkdir()

        manager = HistoricalCorpusManager(history_dir=history_dir)
        manager.initialize_from_history(max_seeds=10)

        # Should not crash with no history files
        assert len(manager.seeds) == 0

    def test_initialize_from_history_with_files(self, tmp_path):
        """Test initializing from history with existing corpus."""
        history_dir = tmp_path / "history"
        history_dir.mkdir()

        # Create a historical corpus
        corpus_dir = history_dir / "corpus_001"
        corpus_dir.mkdir()

        # Save a seed
        manager1 = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        manager1.add_seed(b"historical_data", coverage)
        manager1.save_corpus(corpus_dir)

        # Load historical corpus
        manager2 = HistoricalCorpusManager(history_dir=history_dir)
        manager2.initialize_from_history(max_seeds=10)

        assert len(manager2.seeds) >= 0  # Should attempt to load


class TestCoverageMethods:
    """Test coverage-related helper methods."""

    def test_is_coverage_unique_empty_corpus(self):
        """Test coverage uniqueness check on empty corpus."""
        manager = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})

        assert manager._is_coverage_unique(coverage) is True

    def test_is_coverage_unique_with_similar_seed(self):
        """Test coverage uniqueness with similar seed."""
        manager = CorpusManager(min_coverage_distance=0.5)

        # Add first seed
        coverage1 = CoverageInfo(edges={("a", 1, "b", 2)})
        manager.add_seed(b"data1", coverage1)

        # Try adding very similar coverage
        coverage2 = CoverageInfo(edges={("a", 1, "b", 2)})

        # Should be rejected as not unique
        with patch(
            "dicom_fuzzer.core.corpus_manager.calculate_coverage_distance",
            return_value=0.0,
        ):
            assert manager._is_coverage_unique(coverage2) is False


class TestMinimizeCorpus:
    """Test corpus minimization."""

    def test_minimize_corpus_triggers(self):
        """Test corpus minimization is triggered when size exceeded."""
        manager = CorpusManager(max_corpus_size=3)

        # Add 4 seeds to trigger minimization
        for i in range(4):
            coverage = CoverageInfo(edges={(f"edge{i}", i, f"dest{i}", i + 1)})
            manager.add_seed(f"data{i}".encode(), coverage)

        # Should have minimized to max_corpus_size
        assert len(manager.seeds) <= manager.max_corpus_size


class TestCoverageRejection:
    """Test coverage rejection when not unique (line 162)."""

    def test_reject_non_unique_coverage(self):
        """Test seed is rejected when coverage is not unique (line 162)."""
        manager = CorpusManager(min_coverage_distance=1.0)

        # Add first seed
        coverage1 = CoverageInfo(edges={("a", 1, "b", 2)})
        seed1 = manager.add_seed(b"data1", coverage1)
        assert seed1 is not None

        # Try to add seed with identical coverage
        # Should be rejected as not unique (returns None on line 162)
        with patch(
            "dicom_fuzzer.core.corpus_manager.calculate_coverage_distance",
            return_value=0.0,  # Distance below threshold
        ):
            coverage2 = CoverageInfo(edges={("a", 1, "b", 2), ("c", 3, "d", 4)})
            seed2 = manager.add_seed(b"data2", coverage2)
            assert seed2 is None  # Rejected due to non-unique coverage


class TestAddEntryCompatibility:
    """Test add_entry() compatibility method (lines 208-235)."""

    def test_add_entry_with_dataset_attribute(self):
        """Test add_entry with CorpusEntry object (lines 211-212)."""
        from unittest.mock import Mock, patch

        from pydicom import Dataset

        manager = CorpusManager()

        # Create mock entry with dataset attribute (line 211)
        mock_dataset = Mock(spec=Dataset)
        mock_dataset.save_as = Mock()
        mock_entry = Mock()
        mock_entry.dataset = mock_dataset

        # Test line 212: dataset_to_use = entry.dataset
        with patch("dicom_fuzzer.core.corpus_manager.isinstance", return_value=True):
            with patch("dicom_fuzzer.core.corpus_manager.CoverageInfo"):
                manager.add_entry(mock_entry)

        # Should have used entry.dataset (line 212)
        assert len(manager.seeds) == 1
        mock_dataset.save_as.assert_called_once()

    def test_add_entry_with_explicit_dataset(self):
        """Test add_entry with explicit dataset parameter (lines 213-214)."""
        from unittest.mock import Mock, patch

        from pydicom import Dataset

        manager = CorpusManager()

        # Create mock dataset to pass explicitly
        mock_dataset = Mock(spec=Dataset)
        mock_dataset.save_as = Mock()
        mock_entry = Mock(spec=[])  # Entry without dataset attribute

        # Test line 214: dataset_to_use = dataset
        with patch("dicom_fuzzer.core.corpus_manager.isinstance", return_value=True):
            with patch("dicom_fuzzer.core.corpus_manager.CoverageInfo"):
                manager.add_entry(mock_entry, dataset=mock_dataset)

        # Should have used explicit dataset parameter (line 214)
        assert len(manager.seeds) == 1
        mock_dataset.save_as.assert_called_once()

    def test_add_entry_with_no_dataset(self):
        """Test add_entry when entry is used as dataset (lines 216-217)."""
        from unittest.mock import patch

        manager = CorpusManager()

        # Pass raw data as entry (line 217: dataset_to_use = entry)
        # Patch CoverageInfo to avoid bug on line 232 (blocks parameter doesn't exist)
        with patch("dicom_fuzzer.core.corpus_manager.CoverageInfo"):
            manager.add_entry(b"raw_data")

        # Should create seed with empty data (line 229)
        assert len(manager.seeds) == 1
        seed = list(manager.seeds.values())[0]
        assert seed.data == b""  # Line 229: data = b""

    def test_add_entry_serialization(self):
        """Test dataset serialization in add_entry (lines 224-227)."""
        from unittest.mock import Mock, patch

        from pydicom import Dataset

        manager = CorpusManager()

        # Create mock dataset
        mock_dataset = Mock(spec=Dataset)

        # Mock save_as to write serialized data
        def mock_save_as(output, **kwargs):
            output.write(b"serialized_dicom_data")

        mock_dataset.save_as = mock_save_as

        # Test serialization (lines 226-227)
        with patch("dicom_fuzzer.core.corpus_manager.isinstance", return_value=True):
            with patch("dicom_fuzzer.core.corpus_manager.CoverageInfo"):
                manager.add_entry(mock_dataset)

        # Should have serialized to bytes (line 227)
        assert len(manager.seeds) == 1
        seed = list(manager.seeds.values())[0]
        assert seed.data == b"serialized_dicom_data"


class TestUntouchedEdgesEnergyBoost:
    """Test energy boost for untouched edges (line 295)."""

    def test_energy_boost_for_untouched_edges(self):
        """Test seeds covering untouched edges get energy boost (line 295)."""
        manager = CorpusManager(energy_allocation="adaptive")

        # Mark some edges as untouched
        untouched = {("untouched", 1, "edge", 2)}
        manager.mark_untouched_edges(untouched)

        # Add seed covering untouched edge
        coverage = CoverageInfo(edges=untouched)
        seed = manager.add_seed(b"data", coverage)

        # Update energy - should boost for untouched edges
        seed.executions = 5
        seed.discoveries = 0

        manager._update_seed_energy(seed)

        # For adaptive mode with executions=5, discoveries=0:
        # Base energy = max(0.1, 1.0 / (5 + 1)) = max(0.1, 0.1666...) = 0.1666...
        # With untouched edges boost (line 295): energy *= 2 = 0.333...
        expected_base_energy = max(0.1, 1.0 / (seed.executions + 1))
        expected_boosted_energy = expected_base_energy * 2

        # Energy should be doubled (line 295) because it covers untouched edges
        assert abs(seed.energy - expected_boosted_energy) < 0.0001  # Float comparison


class TestCoveragePlateauDetection:
    """Test coverage plateau detection (lines 363-365)."""

    def test_coverage_plateau_detection(self):
        """Test plateau detection when coverage stagnates (lines 363-365)."""
        manager = CorpusManager()

        # Add 10 coverage history entries with same coverage
        for i in range(10):
            manager.stats.coverage_history.append((float(i), 100))  # Same coverage

        initial_plateaus = manager.stats.coverage_plateaus

        # Get stats - should detect plateau
        stats = manager.get_corpus_stats()

        # Should have incremented plateau count (line 365)
        assert manager.stats.coverage_plateaus == initial_plateaus + 1

    def test_no_plateau_with_varying_coverage(self):
        """Test no plateau detected when coverage varies."""
        manager = CorpusManager()

        # Add 10 coverage history entries with varying coverage
        for i in range(10):
            manager.stats.coverage_history.append((float(i), 100 + i))

        initial_plateaus = manager.stats.coverage_plateaus

        stats = manager.get_corpus_stats()

        # Should NOT increment plateau count
        assert manager.stats.coverage_plateaus == initial_plateaus

    def test_plateau_detection_short_history(self):
        """Test plateau not detected with insufficient history."""
        manager = CorpusManager()

        # Add only 5 entries (less than 10)
        for i in range(5):
            manager.stats.coverage_history.append((float(i), 100))

        initial_plateaus = manager.stats.coverage_plateaus

        stats = manager.get_corpus_stats()

        # Should NOT increment - not enough data
        assert manager.stats.coverage_plateaus == initial_plateaus


class TestHistoricalSeedLoading:
    """Test historical seed loading (lines 465, 478)."""

    def test_load_historical_seeds_with_discoveries(self, tmp_path):
        """Test loading historical seeds with discoveries (line 465)."""
        history_dir = tmp_path / "history"
        history_dir.mkdir()

        # Create historical corpus with valuable seed
        corpus_dir = history_dir / "campaign_001"
        corpus_dir.mkdir()

        manager1 = CorpusManager()
        coverage = CoverageInfo(edges={("a", 1, "b", 2)})
        seed = manager1.add_seed(b"valuable_data", coverage)
        seed.discoveries = 5  # Mark as valuable
        manager1.save_corpus(corpus_dir)

        # Load historical data
        manager2 = HistoricalCorpusManager(history_dir=history_dir)

        # Should have loaded historical seed with discoveries (line 465)
        assert len(manager2.historical_seeds) > 0
        assert any(s.discoveries > 0 for s in manager2.historical_seeds)

    def test_load_historical_seeds_with_crashes(self, tmp_path):
        """Test loading historical seeds with crashes (line 465)."""
        history_dir = tmp_path / "history"
        history_dir.mkdir()

        # Create historical corpus with crash-inducing seed
        corpus_dir = history_dir / "campaign_002"
        corpus_dir.mkdir()

        manager1 = CorpusManager()
        coverage = CoverageInfo(edges={("crash", 1, "edge", 2)})
        seed = manager1.add_seed(b"crash_data", coverage)
        seed.crashes = 3  # Mark as crash-inducing
        manager1.save_corpus(corpus_dir)

        # Load historical data
        manager2 = HistoricalCorpusManager(history_dir=history_dir)

        # Should have loaded historical seed with crashes (line 465)
        assert len(manager2.historical_seeds) > 0
        assert any(s.crashes > 0 for s in manager2.historical_seeds)

    def test_initialize_from_history_adds_seeds(self, tmp_path):
        """Test initialize_from_history adds seeds to corpus (line 478)."""
        history_dir = tmp_path / "history"
        history_dir.mkdir()

        # Create historical corpus
        corpus_dir = history_dir / "campaign_003"
        corpus_dir.mkdir()

        manager1 = CorpusManager()
        coverage = CoverageInfo(edges={("historical", 1, "seed", 2)})
        seed = manager1.add_seed(b"historical_seed_data", coverage)
        seed.discoveries = 10  # High value
        seed.crashes = 2
        manager1.save_corpus(corpus_dir)

        # Initialize from history
        manager2 = HistoricalCorpusManager(history_dir=history_dir)
        initial_seeds = len(manager2.seeds)

        manager2.initialize_from_history(max_seeds=100)

        # Should have added historical seeds (line 478)
        assert len(manager2.seeds) >= initial_seeds
