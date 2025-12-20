"""Comprehensive tests for dicom_fuzzer.core.corpus module.

Tests corpus management for coverage-guided fuzzing including CorpusEntry
and CorpusManager classes.
"""

from datetime import UTC, datetime

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset

from dicom_fuzzer.core.corpus import CorpusEntry, CorpusManager
from dicom_fuzzer.core.coverage_tracker import CoverageSnapshot


@pytest.fixture
def sample_dataset():
    """Create a sample DICOM dataset."""
    ds = Dataset()
    ds.PatientName = "Test^Patient"
    ds.PatientID = "12345"
    ds.Modality = "CT"
    ds.StudyInstanceUID = "1.2.3.4.5"
    ds.SeriesInstanceUID = "1.2.3.4.5.6"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7"
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = ds.SOPClassUID
    file_meta.MediaStorageSOPInstanceUID = ds.SOPInstanceUID
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"
    ds.file_meta = file_meta

    return ds


@pytest.fixture
def sample_coverage():
    """Create a sample coverage snapshot."""
    return CoverageSnapshot(
        lines_covered={("file1.py", 10), ("file1.py", 20), ("file2.py", 30)},
        branches_covered={("file1.py", 10, 1), ("file1.py", 20, 0)},
        test_case_id="test_case_1",
    )


class TestCorpusEntry:
    """Tests for CorpusEntry dataclass."""

    def test_basic_creation(self, sample_dataset):
        """Test basic CorpusEntry creation."""
        entry = CorpusEntry(
            entry_id="test_entry_1",
            dataset=sample_dataset,
            fitness_score=0.5,
        )
        assert entry.entry_id == "test_entry_1"
        assert entry.dataset == sample_dataset
        assert entry.fitness_score == 0.5
        assert entry.generation == 0
        assert entry.parent_id is None
        assert entry.crash_triggered is False

    def test_entry_with_coverage(self, sample_dataset, sample_coverage):
        """Test CorpusEntry with coverage snapshot."""
        entry = CorpusEntry(
            entry_id="test_entry_2",
            dataset=sample_dataset,
            coverage=sample_coverage,
            fitness_score=0.8,
        )
        assert entry.coverage == sample_coverage
        assert entry.fitness_score == 0.8

    def test_entry_with_parent(self, sample_dataset):
        """Test CorpusEntry with parent reference."""
        entry = CorpusEntry(
            entry_id="child_entry",
            dataset=sample_dataset,
            parent_id="parent_entry",
            generation=1,
        )
        assert entry.parent_id == "parent_entry"
        assert entry.generation == 1

    def test_crash_triggered_entry(self, sample_dataset):
        """Test crash-triggering CorpusEntry."""
        entry = CorpusEntry(
            entry_id="crash_entry",
            dataset=sample_dataset,
            crash_triggered=True,
        )
        assert entry.crash_triggered is True

    def test_timestamp_auto_set(self, sample_dataset):
        """Test that timestamp is auto-set."""
        before = datetime.now(UTC)
        entry = CorpusEntry(entry_id="timed_entry", dataset=sample_dataset)
        after = datetime.now(UTC)

        assert before <= entry.timestamp <= after

    def test_metadata_field(self, sample_dataset):
        """Test metadata dictionary field."""
        entry = CorpusEntry(
            entry_id="meta_entry",
            dataset=sample_dataset,
            metadata={"custom_key": "custom_value"},
        )
        assert entry.metadata["custom_key"] == "custom_value"

    def test_get_dataset_with_direct_dataset(self, sample_dataset):
        """Test get_dataset returns cached dataset."""
        entry = CorpusEntry(entry_id="direct_entry", dataset=sample_dataset)
        result = entry.get_dataset()
        assert result == sample_dataset

    def test_get_dataset_lazy_loading(self, sample_dataset, tmp_path):
        """Test get_dataset lazy loads from path."""
        # Save dataset to file
        dcm_path = tmp_path / "test.dcm"
        sample_dataset.save_as(str(dcm_path), write_like_original=False)

        # Create entry with path only (no dataset)
        entry = CorpusEntry(
            entry_id="lazy_entry",
            dataset=None,
            _dataset_path=dcm_path,
        )

        # First access should lazy load
        result = entry.get_dataset()
        assert result is not None
        assert result.PatientName == sample_dataset.PatientName

    def test_get_dataset_caching(self, sample_dataset, tmp_path):
        """Test that lazy-loaded dataset is cached."""
        dcm_path = tmp_path / "test.dcm"
        sample_dataset.save_as(str(dcm_path), write_like_original=False)

        entry = CorpusEntry(
            entry_id="cache_entry",
            dataset=None,
            _dataset_path=dcm_path,
        )

        result1 = entry.get_dataset()
        result2 = entry.get_dataset()
        assert result1 is result2  # Same object (cached)

    def test_get_dataset_missing_path(self):
        """Test get_dataset returns None when no dataset or path."""
        entry = CorpusEntry(entry_id="empty_entry", dataset=None)
        result = entry.get_dataset()
        assert result is None

    def test_get_dataset_invalid_path(self, tmp_path):
        """Test get_dataset handles invalid file path gracefully."""
        entry = CorpusEntry(
            entry_id="invalid_entry",
            dataset=None,
            _dataset_path=tmp_path / "nonexistent.dcm",
        )
        result = entry.get_dataset()
        assert result is None

    def test_set_dataset(self, sample_dataset):
        """Test set_dataset method."""
        entry = CorpusEntry(entry_id="set_entry", dataset=None)
        entry.set_dataset(sample_dataset)
        assert entry.get_dataset() == sample_dataset

    def test_set_dataset_with_path(self, sample_dataset, tmp_path):
        """Test set_dataset with path."""
        dcm_path = tmp_path / "stored.dcm"
        entry = CorpusEntry(entry_id="path_entry", dataset=None)
        entry.set_dataset(sample_dataset, path=dcm_path)
        assert entry._dataset_path == dcm_path

    def test_data_property(self, sample_dataset):
        """Test data property returns bytes."""
        entry = CorpusEntry(entry_id="bytes_entry", dataset=sample_dataset)
        data = entry.data
        assert isinstance(data, bytes)
        assert len(data) > 0
        # Verify it's valid DICOM by reading back
        import io

        loaded = pydicom.dcmread(io.BytesIO(data))
        assert loaded.PatientName == sample_dataset.PatientName

    def test_data_property_empty_dataset(self):
        """Test data property returns empty bytes when no dataset."""
        entry = CorpusEntry(entry_id="empty_data_entry", dataset=None)
        data = entry.data
        assert data == b""


class TestCorpusManager:
    """Tests for CorpusManager class."""

    @pytest.fixture
    def corpus_manager(self, tmp_path):
        """Create a CorpusManager instance."""
        return CorpusManager(
            corpus_dir=tmp_path / "corpus",
            max_corpus_size=100,
            min_fitness_threshold=0.1,
        )

    def test_initialization(self, corpus_manager, tmp_path):
        """Test CorpusManager initialization."""
        assert corpus_manager.corpus_dir == tmp_path / "corpus"
        assert corpus_manager.max_corpus_size == 100
        assert corpus_manager.min_fitness_threshold == 0.1
        assert corpus_manager.size() == 0

    def test_add_entry_new_api(self, corpus_manager, sample_dataset, sample_coverage):
        """Test add_entry with new API (individual parameters)."""
        result = corpus_manager.add_entry(
            entry_id="new_entry",
            dataset=sample_dataset,
            coverage=sample_coverage,
        )
        assert result is True
        assert corpus_manager.size() == 1

    def test_add_entry_old_api(self, corpus_manager, sample_dataset):
        """Test add_entry with CorpusEntry object (backward compatibility)."""
        entry = CorpusEntry(
            entry_id="old_entry",
            dataset=sample_dataset,
            fitness_score=0.5,
        )
        result = corpus_manager.add_entry(entry)
        assert result is True
        assert corpus_manager.size() == 1

    def test_add_entry_requires_dataset(self, corpus_manager):
        """Test add_entry raises error without dataset."""
        with pytest.raises(ValueError, match="dataset is required"):
            corpus_manager.add_entry(entry_id="no_dataset", dataset=None)

    def test_add_entry_crash_triggered(self, corpus_manager, sample_dataset):
        """Test crash-triggered entries are always added."""
        result = corpus_manager.add_entry(
            entry_id="crash_entry",
            dataset=sample_dataset,
            crash_triggered=True,
        )
        assert result is True
        entry = corpus_manager.get_entry("crash_entry")
        assert entry.fitness_score == 1.0  # Crashes get max fitness

    def test_add_entry_low_fitness_rejected(self, tmp_path, sample_dataset):
        """Test low-fitness entries are rejected."""
        manager = CorpusManager(
            corpus_dir=tmp_path / "corpus",
            min_fitness_threshold=0.5,  # High threshold
        )
        # Entry without coverage has low fitness (~0.1)
        result = manager.add_entry(
            entry_id="low_fitness",
            dataset=sample_dataset,
            coverage=None,  # No coverage = low fitness
        )
        assert result is False
        assert manager.total_rejected == 1

    def test_add_entry_generation_tracking(
        self, corpus_manager, sample_dataset, sample_coverage
    ):
        """Test generation is tracked from parent."""
        # Add parent
        corpus_manager.add_entry(
            entry_id="parent", dataset=sample_dataset, coverage=sample_coverage
        )

        # Create different coverage for child (to avoid duplicate rejection)
        child_coverage = CoverageSnapshot(
            lines_covered={("file3.py", 40), ("file3.py", 50)},
            branches_covered={("file3.py", 40, 1)},
            test_case_id="child_test",
        )

        # Add child with parent reference
        corpus_manager.add_entry(
            entry_id="child",
            dataset=sample_dataset,
            coverage=child_coverage,
            parent_id="parent",
        )

        child_entry = corpus_manager.get_entry("child")
        assert child_entry.generation == 1

    def test_get_best_entries(self, corpus_manager, sample_dataset):
        """Test get_best_entries returns highest fitness."""
        # Add entries with different fitness scores
        for i in range(5):
            coverage = CoverageSnapshot(
                lines_covered={(f"file{i}.py", j) for j in range(i * 10)},
                branches_covered=set(),
                test_case_id=f"test_{i}",
            )
            corpus_manager.add_entry(
                entry_id=f"entry_{i}",
                dataset=sample_dataset,
                coverage=coverage if i > 0 else None,
                crash_triggered=(i == 4),  # Last one is crash
            )

        best = corpus_manager.get_best_entries(count=3)
        assert len(best) == 3
        # First should be crash (fitness=1.0)
        assert best[0].crash_triggered is True
        # Should be sorted by fitness descending
        for i in range(len(best) - 1):
            assert best[i].fitness_score >= best[i + 1].fitness_score

    def test_get_best_seed(self, corpus_manager, sample_dataset):
        """Test get_best_seed returns single best entry."""
        corpus_manager.add_entry(
            entry_id="entry_1", dataset=sample_dataset, crash_triggered=True
        )
        corpus_manager.add_entry(entry_id="entry_2", dataset=sample_dataset)

        best = corpus_manager.get_best_seed()
        assert best is not None
        assert best.crash_triggered is True  # Should be the crash entry

    def test_get_best_seed_empty_corpus(self, corpus_manager):
        """Test get_best_seed returns None for empty corpus."""
        result = corpus_manager.get_best_seed()
        assert result is None

    def test_get_random_entry(self, corpus_manager, sample_dataset):
        """Test get_random_entry returns an entry."""
        corpus_manager.add_entry(entry_id="entry_1", dataset=sample_dataset)
        corpus_manager.add_entry(entry_id="entry_2", dataset=sample_dataset)

        result = corpus_manager.get_random_entry()
        assert result is not None
        assert result.entry_id in ["entry_1", "entry_2"]

    def test_get_random_entry_empty_corpus(self, corpus_manager):
        """Test get_random_entry returns None for empty corpus."""
        result = corpus_manager.get_random_entry()
        assert result is None

    def test_get_entry(self, corpus_manager, sample_dataset):
        """Test get_entry by ID."""
        corpus_manager.add_entry(entry_id="specific_entry", dataset=sample_dataset)

        result = corpus_manager.get_entry("specific_entry")
        assert result is not None
        assert result.entry_id == "specific_entry"

    def test_get_entry_not_found(self, corpus_manager):
        """Test get_entry returns None for unknown ID."""
        result = corpus_manager.get_entry("nonexistent")
        assert result is None

    def test_size(self, corpus_manager, sample_dataset):
        """Test size method."""
        assert corpus_manager.size() == 0

        corpus_manager.add_entry(entry_id="entry_1", dataset=sample_dataset)
        assert corpus_manager.size() == 1

        corpus_manager.add_entry(entry_id="entry_2", dataset=sample_dataset)
        assert corpus_manager.size() == 2

    def test_eviction_when_full(self, tmp_path, sample_dataset):
        """Test lowest fitness entries are evicted when corpus is full."""
        manager = CorpusManager(
            corpus_dir=tmp_path / "corpus",
            max_corpus_size=3,
            min_fitness_threshold=0.0,  # Accept all
        )

        # Add 4 entries to a corpus with max_size=3
        for i in range(4):
            coverage = CoverageSnapshot(
                lines_covered={(f"file{i}.py", j) for j in range(i * 5)},
                branches_covered=set(),
                test_case_id=f"test_{i}",
            )
            manager.add_entry(
                entry_id=f"entry_{i}",
                dataset=sample_dataset,
                coverage=coverage if i > 0 else None,
            )

        assert manager.size() <= 3
        assert manager.total_evicted >= 1

    def test_get_statistics(self, corpus_manager, sample_dataset, sample_coverage):
        """Test get_statistics method."""
        corpus_manager.add_entry(
            entry_id="entry_1", dataset=sample_dataset, coverage=sample_coverage
        )
        corpus_manager.add_entry(
            entry_id="entry_2",
            dataset=sample_dataset,
            crash_triggered=True,
        )

        stats = corpus_manager.get_statistics()

        assert stats["total_entries"] == 2
        assert stats["max_size"] == 100
        assert stats["total_added"] == 2
        assert stats["total_rejected"] == 0
        assert stats["total_evicted"] == 0
        assert stats["avg_fitness"] > 0

    def test_clear(self, corpus_manager, sample_dataset):
        """Test clear method removes all entries."""
        corpus_manager.add_entry(entry_id="entry_1", dataset=sample_dataset)
        corpus_manager.add_entry(entry_id="entry_2", dataset=sample_dataset)
        assert corpus_manager.size() == 2

        corpus_manager.clear()

        assert corpus_manager.size() == 0
        assert corpus_manager.total_added == 0
        assert corpus_manager.total_rejected == 0

    def test_persistence(self, tmp_path, sample_dataset):
        """Test corpus persists to disk and can be reloaded."""
        corpus_dir = tmp_path / "persistent_corpus"

        # Create and populate corpus
        manager1 = CorpusManager(corpus_dir=corpus_dir)
        manager1.add_entry(entry_id="persistent_entry", dataset=sample_dataset)
        assert manager1.size() == 1

        # Create new manager pointing to same directory
        manager2 = CorpusManager(corpus_dir=corpus_dir)

        # Should have loaded the entry
        assert manager2.size() == 1
        loaded_entry = manager2.get_entry("persistent_entry")
        assert loaded_entry is not None

    def test_duplicate_coverage_rejection(
        self, corpus_manager, sample_dataset, sample_coverage
    ):
        """Test duplicate coverage is rejected."""
        # Add first entry
        corpus_manager.add_entry(
            entry_id="original",
            dataset=sample_dataset,
            coverage=sample_coverage,
        )

        # Try to add entry with same coverage
        result = corpus_manager.add_entry(
            entry_id="duplicate",
            dataset=sample_dataset,
            coverage=sample_coverage,
        )

        assert result is False
        assert corpus_manager.total_rejected == 1
