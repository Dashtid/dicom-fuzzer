"""Unit Tests for StudyCorpusManager.

Tests the StudyCorpusManager class for managing 3D DICOM studies
as atomic corpus units for fuzzing.
"""

import json
import tempfile
from pathlib import Path

import pytest
from pydicom.dataset import FileDataset, FileMetaDataset

from dicom_fuzzer.core.study_corpus import (
    CrashInfo,
    SeriesInfo,
    StudyCorpusEntry,
    StudyCorpusManager,
    create_study_corpus,
)


def create_test_dicom_file(
    filepath: Path, series_uid: str, modality: str = "CT"
) -> None:
    """Create a minimal valid DICOM file for testing."""
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = f"1.2.3.4.{hash(str(filepath)) % 10000}"
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

    ds = FileDataset(
        str(filepath),
        {},
        file_meta=file_meta,
        preamble=b"\x00" * 128,
    )
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.StudyInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.SeriesInstanceUID = series_uid
    ds.PatientID = "TEST_PATIENT"
    ds.Modality = modality
    ds.StudyDate = "20231215"
    ds.StudyDescription = "Test Study"
    ds.SeriesDescription = f"Test Series {modality}"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.SamplesPerPixel = 1
    ds.PixelData = bytes(64 * 64 * 2)

    ds.save_as(filepath)


@pytest.fixture
def temp_corpus_dir():
    """Create a temporary corpus directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_study_dir(temp_corpus_dir):
    """Create a sample study directory with DICOM files."""
    study_dir = temp_corpus_dir / "sample_study"
    study_dir.mkdir()

    # Create 5 slices in 2 series
    for i in range(3):
        create_test_dicom_file(
            study_dir / f"ct_slice_{i}.dcm",
            series_uid="1.2.3.4.100.1",
            modality="CT",
        )
    for i in range(2):
        create_test_dicom_file(
            study_dir / f"mr_slice_{i}.dcm",
            series_uid="1.2.3.4.100.2",
            modality="MR",
        )

    return study_dir


@pytest.fixture
def empty_study_dir(temp_corpus_dir):
    """Create an empty study directory."""
    empty_dir = temp_corpus_dir / "empty_study"
    empty_dir.mkdir()
    return empty_dir


class TestCrashInfoDataclass:
    """Test CrashInfo dataclass."""

    def test_crash_info_creation(self):
        """Test creating a CrashInfo."""
        crash = CrashInfo(
            crash_id="abc123",
            crash_type="ACCESS_VIOLATION",
            timestamp="2023-12-15T10:30:00",
            trigger_slice="slice_42.dcm",
            exit_code=-1073741819,
            notes="Stack overflow detected",
        )

        assert crash.crash_id == "abc123"
        assert crash.crash_type == "ACCESS_VIOLATION"
        assert crash.trigger_slice == "slice_42.dcm"
        assert crash.exit_code == -1073741819

    def test_crash_info_minimal(self):
        """Test CrashInfo with minimal fields."""
        crash = CrashInfo(
            crash_id="def456",
            crash_type="HEAP_CORRUPTION",
            timestamp="2023-12-15T10:30:00",
        )

        assert crash.crash_id == "def456"
        assert crash.trigger_slice is None
        assert crash.exit_code is None
        assert crash.notes is None

    def test_crash_info_to_dict(self):
        """Test CrashInfo serialization."""
        crash = CrashInfo(
            crash_id="abc123",
            crash_type="ACCESS_VIOLATION",
            timestamp="2023-12-15T10:30:00",
        )
        result = crash.to_dict()

        assert isinstance(result, dict)
        assert result["crash_id"] == "abc123"
        assert result["crash_type"] == "ACCESS_VIOLATION"


class TestSeriesInfoDataclass:
    """Test SeriesInfo dataclass."""

    def test_series_info_creation(self):
        """Test creating a SeriesInfo."""
        series = SeriesInfo(
            series_uid="1.2.3.4.100.1",
            modality="CT",
            slice_count=50,
            is_multiframe=False,
            description="Axial CT",
        )

        assert series.series_uid == "1.2.3.4.100.1"
        assert series.modality == "CT"
        assert series.slice_count == 50
        assert series.is_multiframe is False
        assert series.description == "Axial CT"

    def test_series_info_to_dict(self):
        """Test SeriesInfo serialization."""
        series = SeriesInfo(
            series_uid="1.2.3.4.100.1",
            modality="MR",
            slice_count=100,
        )
        result = series.to_dict()

        assert isinstance(result, dict)
        assert result["modality"] == "MR"
        assert result["slice_count"] == 100


class TestStudyCorpusEntry:
    """Test StudyCorpusEntry dataclass."""

    def test_entry_creation(self):
        """Test creating a StudyCorpusEntry."""
        entry = StudyCorpusEntry(
            study_id="study_abc123",
            study_dir="/path/to/study",
            study_uid="1.2.3.4.5.6.7.8.9",
            patient_id="PAT001",
            total_slices=100,
            modalities=["CT", "MR"],
            priority=2,
        )

        assert entry.study_id == "study_abc123"
        assert entry.total_slices == 100
        assert entry.priority == 2

    def test_study_path_property(self):
        """Test study_path property."""
        entry = StudyCorpusEntry(
            study_id="test",
            study_dir="/some/path/to/study",
            study_uid="1.2.3",
        )

        assert entry.study_path == Path("/some/path/to/study")

    def test_crash_count_property(self):
        """Test crash_count property."""
        entry = StudyCorpusEntry(
            study_id="test",
            study_dir="/path",
            study_uid="1.2.3",
            crashes_triggered=[
                CrashInfo("a", "TYPE1", "2023-01-01"),
                CrashInfo("b", "TYPE2", "2023-01-02"),
            ],
        )

        assert entry.crash_count == 2

    def test_is_crash_triggering_property(self):
        """Test is_crash_triggering property."""
        entry_no_crash = StudyCorpusEntry(
            study_id="test1",
            study_dir="/path",
            study_uid="1.2.3",
        )
        assert entry_no_crash.is_crash_triggering is False

        entry_with_crash = StudyCorpusEntry(
            study_id="test2",
            study_dir="/path",
            study_uid="1.2.4",
            crashes_triggered=[CrashInfo("a", "TYPE1", "2023-01-01")],
        )
        assert entry_with_crash.is_crash_triggering is True


class TestStudyCorpusManagerInit:
    """Test StudyCorpusManager initialization."""

    def test_init_creates_directories(self, temp_corpus_dir):
        """Test that init creates required directories."""
        corpus_dir = temp_corpus_dir / "new_corpus"
        manager = StudyCorpusManager(corpus_dir)

        assert corpus_dir.exists()
        assert (corpus_dir / "studies").exists()
        assert len(manager.studies) == 0

    def test_factory_function(self, temp_corpus_dir):
        """Test create_study_corpus factory."""
        manager = create_study_corpus(temp_corpus_dir / "factory_corpus")

        assert isinstance(manager, StudyCorpusManager)

    def test_init_loads_existing_index(self, temp_corpus_dir):
        """Test that init loads existing index."""
        # Create and save a corpus
        manager1 = StudyCorpusManager(temp_corpus_dir)
        manager1.studies["test_id"] = StudyCorpusEntry(
            study_id="test_id",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.4",
            total_slices=10,
        )
        manager1.save_index()

        # Create new manager - should load existing
        manager2 = StudyCorpusManager(temp_corpus_dir, auto_load=True)
        assert "test_id" in manager2.studies


class TestStudyCorpusManagerAddStudy:
    """Test adding studies to corpus."""

    def test_add_study_basic(self, temp_corpus_dir, sample_study_dir):
        """Test adding a study to corpus."""
        corpus_dir = temp_corpus_dir / "corpus"
        manager = StudyCorpusManager(corpus_dir)

        entry = manager.add_study(sample_study_dir)

        assert entry is not None
        assert entry.study_id in manager.studies
        assert entry.total_slices == 5
        assert "CT" in entry.modalities
        assert "MR" in entry.modalities
        assert len(entry.series_list) == 2

    def test_add_study_with_priority(self, temp_corpus_dir, sample_study_dir):
        """Test adding study with custom priority."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        entry = manager.add_study(sample_study_dir, priority=1)

        assert entry.priority == 1

    def test_add_study_no_copy(self, temp_corpus_dir, sample_study_dir):
        """Test adding study without copying files."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        entry = manager.add_study(sample_study_dir, copy_to_corpus=False)

        # Study dir should point to original location
        assert entry.study_dir == str(sample_study_dir)

    def test_add_study_copies_files(self, temp_corpus_dir, sample_study_dir):
        """Test that files are copied to corpus."""
        corpus_dir = temp_corpus_dir / "corpus"
        manager = StudyCorpusManager(corpus_dir)

        entry = manager.add_study(sample_study_dir, copy_to_corpus=True)

        # Files should be in corpus directory
        corpus_study_dir = Path(entry.study_dir)
        assert corpus_study_dir.is_relative_to(corpus_dir)
        assert corpus_study_dir.exists()
        assert len(list(corpus_study_dir.glob("*.dcm"))) == 5

    def test_add_duplicate_study_returns_existing(
        self, temp_corpus_dir, sample_study_dir
    ):
        """Test adding same study twice returns existing entry."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        entry1 = manager.add_study(sample_study_dir)
        entry2 = manager.add_study(sample_study_dir)

        assert entry1.study_id == entry2.study_id
        assert len(manager.studies) == 1

    def test_add_nonexistent_directory_raises(self, temp_corpus_dir):
        """Test adding nonexistent directory raises error."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        with pytest.raises(ValueError, match="not found"):
            manager.add_study(temp_corpus_dir / "does_not_exist")

    def test_add_empty_study_raises(self, temp_corpus_dir, empty_study_dir):
        """Test adding empty study directory raises error."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        with pytest.raises(ValueError, match="No DICOM files"):
            manager.add_study(empty_study_dir)


class TestStudyCorpusManagerGetRemove:
    """Test getting and removing studies."""

    def test_get_study_existing(self, temp_corpus_dir, sample_study_dir):
        """Test getting an existing study."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir)

        result = manager.get_study(added.study_id)

        assert result is not None
        assert result.study_id == added.study_id

    def test_get_study_nonexistent(self, temp_corpus_dir):
        """Test getting nonexistent study returns None."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        result = manager.get_study("nonexistent_id")

        assert result is None

    def test_remove_study_basic(self, temp_corpus_dir, sample_study_dir):
        """Test removing a study."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir)

        result = manager.remove_study(added.study_id)

        assert result is True
        assert added.study_id not in manager.studies

    def test_remove_study_with_files(self, temp_corpus_dir, sample_study_dir):
        """Test removing study with file deletion."""
        corpus_dir = temp_corpus_dir / "corpus"
        manager = StudyCorpusManager(corpus_dir)
        added = manager.add_study(sample_study_dir, copy_to_corpus=True)
        study_path = Path(added.study_dir)

        assert study_path.exists()

        result = manager.remove_study(added.study_id, delete_files=True)

        assert result is True
        assert not study_path.exists()

    def test_remove_nonexistent_returns_false(self, temp_corpus_dir):
        """Test removing nonexistent study returns False."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        result = manager.remove_study("nonexistent")

        assert result is False


class TestStudyCorpusManagerPriority:
    """Test priority-based study selection."""

    def test_get_next_study_empty_corpus(self, temp_corpus_dir):
        """Test get_next_study with empty corpus."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        result = manager.get_next_study()

        assert result is None

    def test_get_next_study_single(self, temp_corpus_dir, sample_study_dir):
        """Test get_next_study with single study."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir)

        result = manager.get_next_study()

        assert result is not None
        assert result.study_id == added.study_id

    def test_get_next_study_priority_order(self, temp_corpus_dir):
        """Test that higher priority studies come first."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        # Add studies with different priorities (manually to avoid directory issues)
        manager.studies["high"] = StudyCorpusEntry(
            study_id="high",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.1",
            priority=1,
        )
        manager.studies["low"] = StudyCorpusEntry(
            study_id="low",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.2",
            priority=5,
        )
        manager.studies["medium"] = StudyCorpusEntry(
            study_id="medium",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.3",
            priority=3,
        )

        result = manager.get_next_study()

        # High priority (1) should come first
        assert result.study_id == "high"

    def test_update_priority_on_crash(self, temp_corpus_dir, sample_study_dir):
        """Test priority boost on crash."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir, priority=3)

        manager.update_priority(added.study_id, crash_found=True)

        # Priority should be boosted (lowered)
        assert manager.studies[added.study_id].priority == 2

    def test_update_priority_explicit(self, temp_corpus_dir, sample_study_dir):
        """Test explicit priority update."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir, priority=3)

        manager.update_priority(added.study_id, new_priority=1)

        assert manager.studies[added.study_id].priority == 1

    def test_update_priority_clamps_value(self, temp_corpus_dir, sample_study_dir):
        """Test priority is clamped to valid range."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir)

        manager.update_priority(added.study_id, new_priority=10)
        assert manager.studies[added.study_id].priority == 5

        manager.update_priority(added.study_id, new_priority=-5)
        assert manager.studies[added.study_id].priority == 1

    def test_prioritize_studies_order(self, temp_corpus_dir):
        """Test prioritize_studies ordering."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        manager.studies["a"] = StudyCorpusEntry(
            study_id="a",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.1",
            priority=3,
        )
        manager.studies["b"] = StudyCorpusEntry(
            study_id="b",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.2",
            priority=1,
        )

        ordered = manager.prioritize_studies()

        assert ordered[0].study_id == "b"  # Priority 1 first
        assert ordered[1].study_id == "a"  # Priority 3 second


class TestStudyCorpusManagerCrashes:
    """Test crash recording."""

    def test_record_crash_basic(self, temp_corpus_dir, sample_study_dir):
        """Test recording a crash."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir)

        crash = manager.record_crash(
            added.study_id,
            crash_type="ACCESS_VIOLATION",
            trigger_slice="slice_3.dcm",
            exit_code=-1073741819,
        )

        assert crash is not None
        assert crash.crash_type == "ACCESS_VIOLATION"
        assert len(manager.studies[added.study_id].crashes_triggered) == 1

    def test_record_crash_updates_priority(self, temp_corpus_dir, sample_study_dir):
        """Test that recording crash updates priority."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir, priority=3)

        manager.record_crash(added.study_id, crash_type="HEAP_CORRUPTION")

        # Priority should be boosted
        assert manager.studies[added.study_id].priority < 3

    def test_record_crash_nonexistent_study_raises(self, temp_corpus_dir):
        """Test recording crash for nonexistent study raises."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        with pytest.raises(ValueError, match="Study not found"):
            manager.record_crash("nonexistent", crash_type="CRASH")

    def test_record_mutation(self, temp_corpus_dir, sample_study_dir):
        """Test recording mutations."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir)

        manager.record_mutation(added.study_id, "frame_count_mismatch")
        manager.record_mutation(added.study_id, "dimension_overflow")
        # Duplicate should not be added
        manager.record_mutation(added.study_id, "frame_count_mismatch")

        mutations = manager.studies[added.study_id].mutations_applied
        assert len(mutations) == 2
        assert "frame_count_mismatch" in mutations
        assert "dimension_overflow" in mutations

    def test_get_crash_summary(self, temp_corpus_dir, sample_study_dir):
        """Test getting crash summary."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir)

        manager.record_crash(added.study_id, crash_type="ACCESS_VIOLATION")
        manager.record_crash(added.study_id, crash_type="ACCESS_VIOLATION")
        manager.record_crash(added.study_id, crash_type="HEAP_CORRUPTION")

        summary = manager.get_crash_summary()

        assert "ACCESS_VIOLATION" in summary
        assert "HEAP_CORRUPTION" in summary
        assert len(summary["ACCESS_VIOLATION"]) == 2
        assert len(summary["HEAP_CORRUPTION"]) == 1


class TestStudyCorpusManagerPersistence:
    """Test save/load functionality."""

    def test_save_and_load_index(self, temp_corpus_dir, sample_study_dir):
        """Test saving and loading corpus index."""
        corpus_dir = temp_corpus_dir / "corpus"
        manager1 = StudyCorpusManager(corpus_dir)
        added = manager1.add_study(sample_study_dir, copy_to_corpus=False)
        manager1.record_crash(added.study_id, crash_type="TEST_CRASH")
        manager1.record_mutation(added.study_id, "test_mutation")
        manager1.save_index()

        # Create new manager and load
        manager2 = StudyCorpusManager(corpus_dir, auto_load=True)

        assert added.study_id in manager2.studies
        loaded = manager2.studies[added.study_id]
        assert loaded.total_slices == 5
        assert len(loaded.crashes_triggered) == 1
        assert "test_mutation" in loaded.mutations_applied

    def test_load_preserves_series_info(self, temp_corpus_dir, sample_study_dir):
        """Test that series info is preserved after load."""
        corpus_dir = temp_corpus_dir / "corpus"
        manager1 = StudyCorpusManager(corpus_dir)
        added = manager1.add_study(sample_study_dir, copy_to_corpus=False)
        manager1.save_index()

        manager2 = StudyCorpusManager(corpus_dir, auto_load=True)
        loaded = manager2.studies[added.study_id]

        assert len(loaded.series_list) == 2
        modalities = {s.modality for s in loaded.series_list}
        assert "CT" in modalities
        assert "MR" in modalities

    def test_index_file_format(self, temp_corpus_dir, sample_study_dir):
        """Test index file JSON format."""
        corpus_dir = temp_corpus_dir / "corpus"
        manager = StudyCorpusManager(corpus_dir)
        manager.add_study(sample_study_dir, copy_to_corpus=False)
        manager.save_index()

        with open(corpus_dir / "study_corpus_index.json") as f:
            data = json.load(f)

        assert "version" in data
        assert "study_count" in data
        assert "studies" in data
        assert data["study_count"] == 1


class TestStudyCorpusManagerStatistics:
    """Test statistics methods."""

    def test_get_modality_distribution(self, temp_corpus_dir, sample_study_dir):
        """Test modality distribution."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        manager.add_study(sample_study_dir, copy_to_corpus=False)

        distribution = manager.get_modality_distribution()

        assert "CT" in distribution
        assert "MR" in distribution

    def test_get_statistics(self, temp_corpus_dir, sample_study_dir):
        """Test corpus statistics."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir, copy_to_corpus=False)
        manager.record_crash(added.study_id, crash_type="CRASH")

        stats = manager.get_statistics()

        assert stats["study_count"] == 1
        assert stats["total_slices"] == 5
        assert stats["total_crashes"] == 1
        assert stats["crash_triggering_studies"] == 1
        assert stats["average_slices_per_study"] == 5.0

    def test_list_studies(self, temp_corpus_dir, sample_study_dir):
        """Test listing studies."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        manager.add_study(sample_study_dir, copy_to_corpus=False)

        studies = manager.list_studies()

        assert len(studies) == 1
        assert "study_id" in studies[0]
        assert "total_slices" in studies[0]
        assert "modalities" in studies[0]


class TestStudyCorpusManagerBranchCoverage:
    """Additional tests for branch coverage in StudyCorpusManager."""

    def test_init_no_auto_load(self, temp_corpus_dir):
        """Test init with auto_load=False skips loading."""
        # Create an index file first
        corpus_dir = temp_corpus_dir / "corpus"
        manager1 = StudyCorpusManager(corpus_dir)
        manager1.studies["test"] = StudyCorpusEntry(
            study_id="test",
            study_dir=str(corpus_dir),
            study_uid="1.2.3",
        )
        manager1.save_index()

        # New manager with auto_load=False
        manager2 = StudyCorpusManager(corpus_dir, auto_load=False)
        assert len(manager2.studies) == 0

    def test_get_next_study_crash_triggering_priority(self, temp_corpus_dir):
        """Test crash-triggering studies get priority boost."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        # Add non-crash study with priority 2
        manager.studies["normal"] = StudyCorpusEntry(
            study_id="normal",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.1",
            priority=2,
        )

        # Add crash-triggering study with priority 3 (lower initial priority)
        manager.studies["crasher"] = StudyCorpusEntry(
            study_id="crasher",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.2",
            priority=3,
            crashes_triggered=[CrashInfo("a", "CRASH", "2023-01-01")],
        )

        result = manager.get_next_study()
        # Crash-triggering study should get priority boost
        assert result.study_id == "crasher"

    def test_get_next_study_invalid_last_tested_format(self, temp_corpus_dir):
        """Test get_next_study with invalid last_tested datetime format."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        manager.studies["invalid_date"] = StudyCorpusEntry(
            study_id="invalid_date",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.1",
            priority=3,
            last_tested="not-a-valid-datetime",  # Invalid format
        )

        # Should not raise, just use recency_penalty = 0
        result = manager.get_next_study()
        assert result is not None
        assert result.study_id == "invalid_date"

    def test_get_next_study_never_tested_highest_priority(self, temp_corpus_dir):
        """Test never-tested studies get highest priority."""
        from datetime import datetime

        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        # Study that was recently tested
        manager.studies["tested"] = StudyCorpusEntry(
            study_id="tested",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.1",
            priority=2,
            last_tested=datetime.now().isoformat(),
        )

        # Study that was never tested
        manager.studies["untested"] = StudyCorpusEntry(
            study_id="untested",
            study_dir=str(temp_corpus_dir),
            study_uid="1.2.3.2",
            priority=3,  # Lower initial priority
            last_tested=None,
        )

        result = manager.get_next_study()
        # Never-tested should have higher priority despite higher numeric priority
        assert result.study_id == "untested"

    def test_update_priority_nonexistent_study(self, temp_corpus_dir):
        """Test update_priority for nonexistent study logs warning."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        # Should not raise, just log warning
        manager.update_priority("nonexistent_id", crash_found=True)

    def test_update_priority_no_crash_no_new_priority(
        self, temp_corpus_dir, sample_study_dir
    ):
        """Test update_priority without crash or new_priority just updates test_count."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")
        added = manager.add_study(sample_study_dir, priority=3)

        initial_priority = manager.studies[added.study_id].priority
        manager.update_priority(added.study_id)

        # Priority should stay the same
        assert manager.studies[added.study_id].priority == initial_priority
        assert manager.studies[added.study_id].test_count == 1

    def test_record_mutation_nonexistent_study(self, temp_corpus_dir):
        """Test record_mutation for nonexistent study does nothing."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        # Should not raise, just skip
        manager.record_mutation("nonexistent", "some_mutation")

    def test_load_index_nonexistent_file(self, temp_corpus_dir):
        """Test load_index with nonexistent file logs warning."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus", auto_load=False)

        # Delete index file if it exists
        index_path = temp_corpus_dir / "corpus" / "study_corpus_index.json"
        if index_path.exists():
            index_path.unlink()

        # Should not raise, just log warning
        manager.load_index()
        assert len(manager.studies) == 0

    def test_load_index_invalid_json(self, temp_corpus_dir):
        """Test load_index with invalid JSON raises error."""
        corpus_dir = temp_corpus_dir / "corpus"
        manager = StudyCorpusManager(corpus_dir, auto_load=False)

        # Write invalid JSON
        index_path = corpus_dir / "study_corpus_index.json"
        index_path.write_text("{ invalid json }")

        with pytest.raises(json.JSONDecodeError):
            manager.load_index()

    def test_remove_study_delete_files_not_in_corpus(self, temp_corpus_dir):
        """Test remove_study with delete_files=True but path outside corpus."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        # Add study with path outside corpus directory
        external_path = temp_corpus_dir / "external"
        external_path.mkdir()

        manager.studies["external"] = StudyCorpusEntry(
            study_id="external",
            study_dir=str(external_path),
            study_uid="1.2.3",
        )

        # Should remove from index but not delete files (path not relative to corpus)
        result = manager.remove_study("external", delete_files=True)

        assert result is True
        assert "external" not in manager.studies
        # External directory should still exist
        assert external_path.exists()

    def test_get_statistics_empty_corpus(self, temp_corpus_dir):
        """Test get_statistics with empty corpus."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        stats = manager.get_statistics()

        assert stats["study_count"] == 0
        assert stats["total_slices"] == 0
        assert stats["average_slices_per_study"] == 0

    def test_list_studies_long_uid_truncation(self, temp_corpus_dir):
        """Test list_studies truncates long study UIDs."""
        manager = StudyCorpusManager(temp_corpus_dir / "corpus")

        # Add study with very long UID
        long_uid = "1.2.3." + "4" * 100
        manager.studies["long_uid"] = StudyCorpusEntry(
            study_id="long_uid",
            study_dir=str(temp_corpus_dir),
            study_uid=long_uid,
            total_slices=10,
        )

        studies = manager.list_studies()

        # UID should be truncated
        assert len(studies[0]["study_uid"]) <= 43  # 40 + "..."
