"""
Comprehensive tests for corpus management (coverage-guided fuzzing).

Tests the CorpusEntry and CorpusManager classes which manage a corpus
of interesting test cases for coverage-guided fuzzing.
"""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from pydicom.dataset import Dataset

from core.corpus import CorpusEntry, CorpusManager


@pytest.fixture
def temp_corpus_dir():
    """Create a temporary directory for corpus storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_dataset():
    """Create a sample DICOM dataset for testing."""
    from pydicom.dataset import FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian

    # Create file meta information
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5.6.7.8.10"

    # Create dataset
    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST001"
    ds.Modality = "CT"
    ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.10"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    return ds


@pytest.fixture
def mock_coverage():
    """Create a mock coverage snapshot."""
    coverage = Mock()
    coverage.lines_covered = {1, 2, 3, 4, 5}
    coverage.branches_covered = {(1, 2), (2, 3), (3, 4)}
    coverage.coverage_hash = Mock(return_value="hash123")
    return coverage


class TestCorpusEntry:
    """Test the CorpusEntry dataclass."""

    def test_entry_creation(self, sample_dataset, mock_coverage):
        """Test creating a corpus entry with all parameters."""
        entry = CorpusEntry(
            entry_id="test001",
            dataset=sample_dataset,
            coverage=mock_coverage,
            fitness_score=0.75,
            generation=2,
            parent_id="test000",
            crash_triggered=True,
        )

        assert entry.entry_id == "test001"
        assert entry.dataset == sample_dataset
        assert entry.coverage == mock_coverage
        assert entry.fitness_score == 0.75
        assert entry.generation == 2
        assert entry.parent_id == "test000"
        assert entry.crash_triggered is True
        assert isinstance(entry.timestamp, datetime)
        assert isinstance(entry.metadata, dict)

    def test_entry_defaults(self, sample_dataset):
        """Test corpus entry with default values."""
        entry = CorpusEntry(entry_id="test002", dataset=sample_dataset)

        assert entry.coverage is None
        assert entry.fitness_score == 0.0
        assert entry.generation == 0
        assert entry.parent_id is None
        assert entry.crash_triggered is False
        assert len(entry.metadata) == 0

    def test_to_dict_with_coverage(self, sample_dataset, mock_coverage):
        """Test converting entry to dictionary with coverage."""
        entry = CorpusEntry(
            entry_id="test003",
            dataset=sample_dataset,
            coverage=mock_coverage,
            fitness_score=0.85,
            generation=5,
            parent_id="test002",
            crash_triggered=True,
            metadata={"key": "value"},
        )

        entry_dict = entry.to_dict()

        assert entry_dict["entry_id"] == "test003"
        assert entry_dict["fitness_score"] == 0.85
        assert entry_dict["generation"] == 5
        assert entry_dict["parent_id"] == "test002"
        assert entry_dict["crash_triggered"] is True
        assert isinstance(entry_dict["timestamp"], str)
        assert entry_dict["metadata"] == {"key": "value"}
        assert entry_dict["coverage_lines"] == 5

    def test_to_dict_without_coverage(self, sample_dataset):
        """Test converting entry to dictionary without coverage."""
        entry = CorpusEntry(entry_id="test004", dataset=sample_dataset)

        entry_dict = entry.to_dict()

        assert entry_dict["coverage_lines"] == 0


class TestCorpusManagerInitialization:
    """Test CorpusManager initialization."""

    def test_initialization_creates_directory(self, temp_corpus_dir):
        """Test that initialization creates the corpus directory."""
        corpus_dir = temp_corpus_dir / "corpus"
        assert not corpus_dir.exists()

        manager = CorpusManager(corpus_dir)

        assert corpus_dir.exists()
        assert manager.corpus_dir == corpus_dir
        assert manager.max_corpus_size == 1000  # default
        assert manager.min_fitness_threshold == 0.1  # default

    def test_initialization_with_custom_parameters(self, temp_corpus_dir):
        """Test initialization with custom parameters."""
        manager = CorpusManager(
            temp_corpus_dir, max_corpus_size=500, min_fitness_threshold=0.2
        )

        assert manager.max_corpus_size == 500
        assert manager.min_fitness_threshold == 0.2

    def test_initialization_empty_corpus(self, temp_corpus_dir):
        """Test initialization with empty corpus."""
        manager = CorpusManager(temp_corpus_dir)

        assert len(manager.corpus) == 0
        assert len(manager.coverage_map) == 0
        assert manager.total_added == 0
        assert manager.total_rejected == 0
        assert manager.total_evicted == 0


class TestCorpusManagerAddEntry:
    """Test adding entries to the corpus."""

    def test_add_entry_basic(self, temp_corpus_dir, sample_dataset):
        """Test adding a basic entry without coverage."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)

        result = manager.add_entry("entry1", sample_dataset)

        assert result is True
        assert len(manager.corpus) == 1
        assert "entry1" in manager.corpus
        assert manager.total_added == 1

    def test_add_entry_with_coverage(
        self, temp_corpus_dir, sample_dataset, mock_coverage
    ):
        """Test adding entry with coverage information."""
        manager = CorpusManager(temp_corpus_dir)

        result = manager.add_entry("entry2", sample_dataset, coverage=mock_coverage)

        assert result is True
        entry = manager.corpus["entry2"]
        assert entry.coverage == mock_coverage

    def test_add_entry_with_parent(self, temp_corpus_dir, sample_dataset):
        """Test adding entry with parent ID."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)

        # Add parent
        manager.add_entry("parent", sample_dataset)

        # Add child
        result = manager.add_entry("child", sample_dataset, parent_id="parent")

        assert result is True
        assert manager.corpus["child"].generation == 1
        assert manager.corpus["child"].parent_id == "parent"

    def test_add_crash_triggering_entry(self, temp_corpus_dir, sample_dataset):
        """Test adding crash-triggering entry always succeeds."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.9)

        # Even with low fitness, crash-triggering entries are added
        result = manager.add_entry(
            "crash", sample_dataset, crash_triggered=True, parent_id=None
        )

        assert result is True
        assert manager.corpus["crash"].crash_triggered is True

    def test_reject_low_fitness_entry(self, temp_corpus_dir, sample_dataset):
        """Test rejecting entry with fitness below threshold."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.5)

        with patch.object(manager, "_calculate_fitness", return_value=0.3):
            result = manager.add_entry("low_fit", sample_dataset)

        assert result is False
        assert len(manager.corpus) == 0
        assert manager.total_rejected == 1

    def test_reject_duplicate_coverage(
        self, temp_corpus_dir, sample_dataset, mock_coverage
    ):
        """Test rejecting entry with duplicate coverage."""
        manager = CorpusManager(temp_corpus_dir)

        # Add first entry
        manager.add_entry("first", sample_dataset, coverage=mock_coverage)

        # Try to add duplicate coverage
        result = manager.add_entry("second", sample_dataset, coverage=mock_coverage)

        # Should be rejected (duplicate coverage, not better fitness)
        assert result is False
        assert len(manager.corpus) == 1
        assert manager.total_rejected == 1

    def test_replace_lower_fitness_duplicate(
        self, temp_corpus_dir, sample_dataset, mock_coverage
    ):
        """Test replacing entry with same coverage but higher fitness."""
        manager = CorpusManager(temp_corpus_dir)

        # Add first entry with low fitness
        with patch.object(manager, "_calculate_fitness", return_value=0.3):
            manager.add_entry("low", sample_dataset, coverage=mock_coverage)

        # Add second entry with higher fitness (same coverage)
        with patch.object(manager, "_calculate_fitness", return_value=0.8):
            result = manager.add_entry("high", sample_dataset, coverage=mock_coverage)

        # Higher fitness should be accepted
        assert result is True


class TestCorpusManagerRetrieval:
    """Test retrieving entries from corpus."""

    def test_get_entry_exists(self, temp_corpus_dir, sample_dataset):
        """Test retrieving an existing entry."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)
        manager.add_entry("test", sample_dataset)

        entry = manager.get_entry("test")

        assert entry is not None
        assert entry.entry_id == "test"

    def test_get_entry_not_exists(self, temp_corpus_dir):
        """Test retrieving non-existent entry."""
        manager = CorpusManager(temp_corpus_dir)

        entry = manager.get_entry("nonexistent")

        assert entry is None

    def test_get_best_entries(self, temp_corpus_dir, sample_dataset):
        """Test getting best entries sorted by fitness."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)

        # Add entries with different fitness scores
        with patch.object(manager, "_calculate_fitness", return_value=0.9):
            manager.add_entry("high", sample_dataset)
        with patch.object(manager, "_calculate_fitness", return_value=0.5):
            manager.add_entry("medium", sample_dataset)
        with patch.object(manager, "_calculate_fitness", return_value=0.2):
            manager.add_entry("low", sample_dataset)

        best = manager.get_best_entries(count=2)

        assert len(best) == 2
        assert best[0].entry_id == "high"
        assert best[1].entry_id == "medium"

    def test_get_best_entries_empty_corpus(self, temp_corpus_dir):
        """Test getting best entries from empty corpus."""
        manager = CorpusManager(temp_corpus_dir)

        best = manager.get_best_entries(count=5)

        assert len(best) == 0

    def test_get_random_entry(self, temp_corpus_dir, sample_dataset):
        """Test getting a random entry."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)
        manager.add_entry("entry1", sample_dataset)
        manager.add_entry("entry2", sample_dataset)

        entry = manager.get_random_entry()

        assert entry is not None
        assert entry.entry_id in ["entry1", "entry2"]

    def test_get_random_entry_empty_corpus(self, temp_corpus_dir):
        """Test getting random entry from empty corpus."""
        manager = CorpusManager(temp_corpus_dir)

        entry = manager.get_random_entry()

        assert entry is None


class TestCorpusManagerStatistics:
    """Test corpus statistics and management."""

    def test_get_statistics(self, temp_corpus_dir, sample_dataset):
        """Test getting corpus statistics."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)
        manager.add_entry("entry1", sample_dataset)
        manager.add_entry("entry2", sample_dataset)

        stats = manager.get_statistics()

        assert stats["total_entries"] == 2
        assert stats["total_added"] == 2
        assert stats["total_rejected"] == 0
        assert stats["total_evicted"] == 0
        assert stats["max_size"] == 1000
        assert isinstance(stats["avg_fitness"], float)
        assert stats["max_generation"] >= 0
        assert stats["unique_coverage_patterns"] >= 0

    def test_statistics_empty_corpus(self, temp_corpus_dir):
        """Test statistics for empty corpus."""
        manager = CorpusManager(temp_corpus_dir)

        stats = manager.get_statistics()

        assert stats["total_entries"] == 0
        assert stats["avg_fitness"] == 0.0
        assert stats["max_generation"] == 0
        assert stats["unique_coverage_patterns"] == 0

    def test_clear_corpus(self, temp_corpus_dir, sample_dataset):
        """Test clearing the corpus."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)
        manager.add_entry("entry1", sample_dataset)
        manager.add_entry("entry2", sample_dataset)

        manager.clear()

        assert len(manager.corpus) == 0
        assert len(manager.coverage_map) == 0
        # Statistics are reset by clear()
        assert manager.total_added == 0
        assert manager.total_rejected == 0
        assert manager.total_evicted == 0


class TestCorpusManagerPersistence:
    """Test corpus persistence (save/load)."""

    def test_save_and_load_corpus(self, temp_corpus_dir, sample_dataset):
        """Test saving and loading corpus from disk."""
        # Create manager and add entry
        manager1 = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)
        manager1.add_entry("persistent", sample_dataset)

        # Create new manager (should load existing corpus)
        manager2 = CorpusManager(temp_corpus_dir)

        assert len(manager2.corpus) == 1
        assert "persistent" in manager2.corpus

    def test_load_nonexistent_corpus(self, temp_corpus_dir):
        """Test loading corpus when none exists."""
        manager = CorpusManager(temp_corpus_dir)

        # Should not raise error, just start with empty corpus
        assert len(manager.corpus) == 0


class TestCorpusManagerEviction:
    """Test corpus eviction when max size reached."""

    def test_evict_lowest_fitness(self, temp_corpus_dir, sample_dataset):
        """Test evicting lowest fitness entry when corpus is full."""
        manager = CorpusManager(
            temp_corpus_dir, max_corpus_size=2, min_fitness_threshold=0.0
        )

        # Add entries with different fitness
        with patch.object(manager, "_calculate_fitness", return_value=0.9):
            manager.add_entry("high", sample_dataset)
        with patch.object(manager, "_calculate_fitness", return_value=0.5):
            manager.add_entry("medium", sample_dataset)

        # Corpus is now full, add another with higher fitness
        with patch.object(manager, "_calculate_fitness", return_value=0.7):
            manager.add_entry("new_high", sample_dataset)

        # Lowest fitness entry should be evicted
        assert len(manager.corpus) == 2
        assert "medium" not in manager.corpus
        assert "high" in manager.corpus
        assert "new_high" in manager.corpus
        assert manager.total_evicted == 1


class TestCorpusManagerFitnessCalculation:
    """Test fitness calculation logic."""

    def test_fitness_with_coverage(
        self, temp_corpus_dir, sample_dataset, mock_coverage
    ):
        """Test fitness calculation includes coverage information."""
        manager = CorpusManager(temp_corpus_dir)

        fitness = manager._calculate_fitness(sample_dataset, mock_coverage, False)

        # Fitness should be positive with coverage
        assert fitness > 0.0
        assert 0.0 <= fitness <= 1.0

    def test_fitness_without_coverage(self, temp_corpus_dir, sample_dataset):
        """Test fitness calculation without coverage."""
        manager = CorpusManager(temp_corpus_dir)

        fitness = manager._calculate_fitness(sample_dataset, None, False)

        # Should still calculate some baseline fitness
        assert fitness >= 0.0

    def test_fitness_with_crash(self, temp_corpus_dir, sample_dataset):
        """Test that crash-triggering entries get high fitness."""
        manager = CorpusManager(temp_corpus_dir)

        fitness = manager._calculate_fitness(sample_dataset, None, True)

        # Crash-triggering should have high fitness
        assert fitness >= 0.8


class TestCorpusManagerIntegration:
    """Integration tests for complete workflows."""

    def test_full_fuzzing_workflow(self, temp_corpus_dir, sample_dataset):
        """Test a complete fuzzing workflow with corpus management."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.0)

        # Add seed corpus
        manager.add_entry("seed1", sample_dataset)

        # Get random entry for mutation
        parent = manager.get_random_entry()
        assert parent is not None

        # Add mutated entry
        mutated_ds = sample_dataset.copy()
        mutated_ds.PatientID = "MUTATED001"
        manager.add_entry("mut1", mutated_ds, parent_id=parent.entry_id)

        # Verify lineage
        child = manager.get_entry("mut1")
        assert child.parent_id == parent.entry_id
        assert child.generation == parent.generation + 1

    def test_corpus_grows_to_max_size(self, temp_corpus_dir, sample_dataset):
        """Test that corpus respects max size limit."""
        max_size = 10
        manager = CorpusManager(
            temp_corpus_dir, max_corpus_size=max_size, min_fitness_threshold=0.0
        )

        # Add more entries than max size
        for i in range(max_size + 5):
            ds = sample_dataset.copy()
            ds.PatientID = f"TEST{i:03d}"
            manager.add_entry(f"entry{i}", ds)

        # Corpus should not exceed max size
        assert len(manager.corpus) <= max_size
        assert manager.total_evicted > 0

    def test_statistics_tracking(self, temp_corpus_dir, sample_dataset):
        """Test that statistics are correctly tracked over time."""
        manager = CorpusManager(temp_corpus_dir, min_fitness_threshold=0.5)

        # Add good entries
        with patch.object(manager, "_calculate_fitness", return_value=0.8):
            manager.add_entry("good1", sample_dataset)
            manager.add_entry("good2", sample_dataset)

        # Try to add bad entries
        with patch.object(manager, "_calculate_fitness", return_value=0.3):
            manager.add_entry("bad1", sample_dataset)
            manager.add_entry("bad2", sample_dataset)

        stats = manager.get_statistics()
        assert stats["total_added"] == 2  # only good entries added
        assert stats["total_rejected"] == 2  # bad entries rejected
