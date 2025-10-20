"""Real-world tests for fuzzing_session module.

Tests the fuzzing session tracker with real DICOM files and actual workflows.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

import pytest
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import ImplicitVRLittleEndian

from dicom_fuzzer.core.fuzzing_session import (
    CrashRecord,
    FuzzedFileRecord,
    FuzzingSession,
    MutationRecord,
)


@pytest.fixture
def temp_session_dirs(tmp_path):
    """Create temporary directories for session testing."""
    output_dir = tmp_path / "output"
    reports_dir = tmp_path / "reports"
    crashes_dir = tmp_path / "crashes"

    return {
        "output": output_dir,
        "reports": reports_dir,
        "crashes": crashes_dir,
        "base": tmp_path,
    }


@pytest.fixture
def sample_dicom_file(tmp_path):
    """Create a sample DICOM file for testing."""
    from pydicom.uid import generate_uid

    # Create file meta information with all required elements
    file_meta = Dataset()
    file_meta.TransferSyntaxUID = ImplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    # Create the FileDataset instance
    filename = tmp_path / "test_sample.dcm"
    ds = FileDataset(str(filename), {}, file_meta=file_meta, preamble=b"\0" * 128)

    # Add required DICOM elements
    ds.PatientName = "Test^Patient"
    ds.PatientID = "TEST123"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"

    # Save the file
    ds.save_as(filename, write_like_original=False)

    return filename


class TestFuzzingSessionInitialization:
    """Test FuzzingSession initialization."""

    def test_initialization_default_dirs(self, temp_session_dirs):
        """Test creating session with default directories."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        assert session.session_name == "test_session"
        assert session.session_id.startswith("test_session_")
        assert session.start_time is not None
        assert isinstance(session.start_time, datetime)

    def test_initialization_creates_directories(self, temp_session_dirs):
        """Test that initialization creates required directories."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        assert session.output_dir.exists()
        assert session.reports_dir.exists()
        assert session.crashes_dir.exists()

    def test_initialization_stats(self, temp_session_dirs):
        """Test that initialization sets up statistics."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        assert session.stats["files_fuzzed"] == 0
        assert session.stats["mutations_applied"] == 0
        assert session.stats["crashes"] == 0
        assert session.stats["hangs"] == 0
        assert session.stats["successes"] == 0

    def test_initialization_empty_collections(self, temp_session_dirs):
        """Test that collections are initialized empty."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        assert len(session.fuzzed_files) == 0
        assert len(session.crashes) == 0
        assert session.current_file_record is None


class TestFileFuzzingWorkflow:
    """Test file fuzzing workflow."""

    def test_start_file_fuzzing(self, temp_session_dirs, sample_dicom_file):
        """Test starting file fuzzing."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )

        assert file_id is not None
        assert file_id.startswith("fuzz_")
        assert session.current_file_record is not None
        assert session.stats["files_fuzzed"] == 1

    def test_start_file_fuzzing_extracts_metadata(
        self, temp_session_dirs, sample_dicom_file
    ):
        """Test that metadata is extracted from source file."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )

        assert session.current_file_record.source_metadata is not None
        assert "PatientID" in session.current_file_record.source_metadata
        assert session.current_file_record.source_metadata["PatientID"] == "TEST123"

    def test_record_mutation(self, temp_session_dirs, sample_dicom_file):
        """Test recording mutations."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )

        session.record_mutation(
            strategy_name="bit_flip",
            mutation_type="flip_bits",
            target_tag="(0010,0010)",
            target_element="PatientName",
            original_value="Test^Patient",
            mutated_value="Xest^Patient",
        )

        assert len(session.current_file_record.mutations) == 1
        assert session.stats["mutations_applied"] == 1

    def test_record_mutation_without_active_session(self, temp_session_dirs):
        """Test that recording mutation without active session raises error."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        with pytest.raises(RuntimeError, match="No active file fuzzing session"):
            session.record_mutation(
                strategy_name="bit_flip",
                mutation_type="flip_bits",
            )

    def test_end_file_fuzzing(self, temp_session_dirs, sample_dicom_file):
        """Test ending file fuzzing."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        # Create actual output file
        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        shutil.copy(sample_dicom_file, output_file)

        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )

        session.end_file_fuzzing(output_file=output_file, success=True)

        assert session.current_file_record is None
        assert file_id in session.fuzzed_files
        assert session.fuzzed_files[file_id].file_hash != ""

    def test_end_file_fuzzing_without_active_session(self, temp_session_dirs):
        """Test that ending without active session raises error."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        with pytest.raises(RuntimeError, match="No active file fuzzing session"):
            session.end_file_fuzzing(
                output_file=Path("dummy.dcm"),
                success=True,
            )


class TestMutationRecordDataclass:
    """Test MutationRecord dataclass."""

    def test_mutation_record_creation(self):
        """Test creating mutation record."""
        record = MutationRecord(
            mutation_id="mut_1",
            strategy_name="bit_flip",
            timestamp=datetime.now(),
            target_tag="(0010,0010)",
            target_element="PatientName",
            mutation_type="flip_bits",
            original_value="Test",
            mutated_value="Xest",
        )

        assert record.mutation_id == "mut_1"
        assert record.strategy_name == "bit_flip"
        assert record.mutation_type == "flip_bits"

    def test_mutation_record_to_dict(self):
        """Test converting mutation record to dictionary."""
        timestamp = datetime.now()
        record = MutationRecord(
            mutation_id="mut_1",
            strategy_name="bit_flip",
            timestamp=timestamp,
        )

        data = record.to_dict()

        assert isinstance(data, dict)
        assert data["mutation_id"] == "mut_1"
        assert data["strategy_name"] == "bit_flip"
        assert data["timestamp"] == timestamp.isoformat()


class TestFuzzedFileRecordDataclass:
    """Test FuzzedFileRecord dataclass."""

    def test_fuzzed_file_record_creation(self):
        """Test creating fuzzed file record."""
        record = FuzzedFileRecord(
            file_id="fuzz_001",
            source_file="/path/to/source.dcm",
            output_file="/path/to/output.dcm",
            timestamp=datetime.now(),
            file_hash="abc123",
            severity="moderate",
        )

        assert record.file_id == "fuzz_001"
        assert record.source_file == "/path/to/source.dcm"
        assert record.severity == "moderate"

    def test_fuzzed_file_record_to_dict(self):
        """Test converting fuzzed file record to dictionary."""
        timestamp = datetime.now()
        mutation = MutationRecord(
            mutation_id="mut_1",
            strategy_name="bit_flip",
            timestamp=timestamp,
        )

        record = FuzzedFileRecord(
            file_id="fuzz_001",
            source_file="/path/to/source.dcm",
            output_file="/path/to/output.dcm",
            timestamp=timestamp,
            file_hash="abc123",
            severity="moderate",
            mutations=[mutation],
        )

        data = record.to_dict()

        assert isinstance(data, dict)
        assert data["file_id"] == "fuzz_001"
        assert len(data["mutations"]) == 1
        assert isinstance(data["mutations"][0], dict)


class TestTestResults:
    """Test recording test results."""

    def test_record_test_result_success(self, temp_session_dirs, sample_dicom_file):
        """Test recording successful test result."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        session.record_test_result(file_id, "success")

        assert session.fuzzed_files[file_id].test_result == "success"
        assert session.stats["successes"] == 1

    def test_record_test_result_crash(self, temp_session_dirs, sample_dicom_file):
        """Test recording crash test result."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        session.record_test_result(file_id, "crash", return_code=-11)

        assert session.fuzzed_files[file_id].test_result == "crash"
        assert session.stats["crashes"] == 1

    def test_record_test_result_unknown_file(self, temp_session_dirs):
        """Test recording result for unknown file raises error."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        with pytest.raises(KeyError, match="Unknown file ID"):
            session.record_test_result("nonexistent_id", "success")

    def test_mark_test_result_alias(self, temp_session_dirs, sample_dicom_file):
        """Test mark_test_result is an alias for record_test_result."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        session.mark_test_result(file_id, "success")

        assert session.fuzzed_files[file_id].test_result == "success"


class TestCrashRecording:
    """Test crash recording functionality."""

    def test_record_crash_basic(self, temp_session_dirs, sample_dicom_file):
        """Test recording a basic crash."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        # Create actual output file
        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        shutil.copy(sample_dicom_file, output_file)

        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        crash = session.record_crash(
            file_id=file_id,
            crash_type="crash",
            severity="high",
            return_code=-11,
        )

        assert crash is not None
        assert isinstance(crash, CrashRecord)
        assert crash.crash_type == "crash"
        assert crash.severity == "high"
        assert len(session.crashes) == 1

    def test_record_crash_with_exception(self, temp_session_dirs, sample_dicom_file):
        """Test recording crash with exception details."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        shutil.copy(sample_dicom_file, output_file)

        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        crash = session.record_crash(
            file_id=file_id,
            crash_type="exception",
            severity="high",
            exception_type="ValueError",
            exception_message="Invalid DICOM tag",
            stack_trace="Traceback (most recent call last):\n  ...",
        )

        assert crash.exception_type == "ValueError"
        assert crash.exception_message == "Invalid DICOM tag"
        assert crash.stack_trace is not None

    def test_record_crash_creates_artifacts(self, temp_session_dirs, sample_dicom_file):
        """Test that crash recording creates artifacts."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        shutil.copy(sample_dicom_file, output_file)

        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        crash = session.record_crash(
            file_id=file_id,
            crash_type="crash",
            severity="high",
        )

        # Check crash log was created
        assert crash.crash_log_path is not None
        assert Path(crash.crash_log_path).exists()

        # Check preserved sample was created
        assert crash.preserved_sample_path is not None
        assert Path(crash.preserved_sample_path).exists()

    def test_record_crash_with_mutations(self, temp_session_dirs, sample_dicom_file):
        """Test crash recording captures mutation sequence."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        shutil.copy(sample_dicom_file, output_file)

        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )

        session.record_mutation("bit_flip", "flip_bits")
        session.record_mutation("dictionary", "replace")

        session.end_file_fuzzing(output_file=output_file, success=True)

        crash = session.record_crash(
            file_id=file_id,
            crash_type="crash",
            severity="high",
        )

        assert len(crash.mutation_sequence) == 2
        assert crash.mutation_sequence[0] == ("bit_flip", "flip_bits")
        assert crash.mutation_sequence[1] == ("dictionary", "replace")

    def test_record_crash_unknown_file(self, temp_session_dirs):
        """Test recording crash for unknown file raises error."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        with pytest.raises(KeyError, match="Unknown file ID"):
            session.record_crash(
                file_id="nonexistent_id",
                crash_type="crash",
                severity="high",
            )


class TestSessionReporting:
    """Test session reporting functionality."""

    def test_generate_session_report(self, temp_session_dirs, sample_dicom_file):
        """Test generating session report."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        report = session.generate_session_report()

        assert "session_info" in report
        assert "statistics" in report
        assert "fuzzed_files" in report
        assert "crashes" in report

    def test_session_report_structure(self, temp_session_dirs, sample_dicom_file):
        """Test session report has correct structure."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        report = session.generate_session_report()

        assert report["session_info"]["session_id"] == session.session_id
        assert report["session_info"]["session_name"] == "test_session"
        assert "start_time" in report["session_info"]
        assert "end_time" in report["session_info"]
        assert "duration_seconds" in report["session_info"]

    def test_save_session_report(self, temp_session_dirs, sample_dicom_file):
        """Test saving session report to JSON."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        report_path = session.save_session_report()

        assert report_path.exists()
        assert report_path.suffix == ".json"

        # Verify JSON is valid
        with open(report_path, "r") as f:
            data = json.load(f)
            assert "session_info" in data

    def test_save_session_report_custom_path(
        self, temp_session_dirs, sample_dicom_file
    ):
        """Test saving session report to custom path."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.end_file_fuzzing(output_file=output_file, success=True)

        custom_path = temp_session_dirs["base"] / "custom_report.json"
        report_path = session.save_session_report(json_path=custom_path)

        assert report_path == custom_path
        assert custom_path.exists()

    def test_get_session_summary(self, temp_session_dirs, sample_dicom_file):
        """Test getting session summary."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )
        session.record_mutation("bit_flip", "flip_bits")
        session.end_file_fuzzing(output_file=output_file, success=True)

        summary = session.get_session_summary()

        assert summary["session_id"] == session.session_id
        assert summary["session_name"] == "test_session"
        assert summary["total_files"] == 1
        assert summary["total_mutations"] == 1
        assert "duration" in summary
        assert "files_per_minute" in summary


class TestHelperMethods:
    """Test helper methods."""

    def test_extract_metadata(self, temp_session_dirs, sample_dicom_file):
        """Test extracting DICOM metadata."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        metadata = session._extract_metadata(sample_dicom_file)

        assert "PatientName" in metadata
        assert "PatientID" in metadata
        assert metadata["PatientID"] == "TEST123"

    def test_extract_metadata_nonexistent_file(self, temp_session_dirs):
        """Test extracting metadata from nonexistent file."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        metadata = session._extract_metadata(Path("/nonexistent/file.dcm"))

        assert isinstance(metadata, dict)
        assert len(metadata) == 0

    def test_calculate_file_hash(self, temp_session_dirs, sample_dicom_file):
        """Test calculating file hash."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        hash1 = session._calculate_file_hash(sample_dicom_file)
        hash2 = session._calculate_file_hash(sample_dicom_file)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex digest length

    def test_value_to_string_none(self, temp_session_dirs):
        """Test converting None value to string."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        result = session._value_to_string(None)

        assert result is None

    def test_value_to_string_bytes(self, temp_session_dirs):
        """Test converting bytes value to string."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        result = session._value_to_string(b"\x01\x02\x03")

        assert result == "010203"

    def test_value_to_string_bytes_truncated(self, temp_session_dirs):
        """Test converting long bytes value to truncated string."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        long_bytes = b"\x00" * 100
        result = session._value_to_string(long_bytes)

        assert "truncated" in result
        assert "100 bytes" in result


class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    def test_complete_fuzzing_workflow(self, temp_session_dirs, sample_dicom_file):
        """Test complete end-to-end fuzzing workflow."""
        session = FuzzingSession(
            session_name="test_campaign",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        # Fuzz first file
        output_file1 = temp_session_dirs["output"] / "fuzzed_001.dcm"
        shutil.copy(sample_dicom_file, output_file1)

        file_id1 = session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file1,
            severity="moderate",
        )
        session.record_mutation("bit_flip", "flip_bits", target_tag="(0010,0010)")
        session.end_file_fuzzing(output_file=output_file1, success=True)
        session.record_test_result(file_id1, "success")

        # Fuzz second file
        output_file2 = temp_session_dirs["output"] / "fuzzed_002.dcm"
        shutil.copy(sample_dicom_file, output_file2)

        file_id2 = session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file2,
            severity="aggressive",
        )
        session.record_mutation("dictionary", "replace", target_tag="(0010,0020)")
        session.end_file_fuzzing(output_file=output_file2, success=True)

        # Record crash for second file
        session.record_crash(
            file_id=file_id2,
            crash_type="crash",
            severity="high",
            return_code=-11,
        )

        # Generate report
        report = session.generate_session_report()

        assert report["statistics"]["files_fuzzed"] == 2
        assert report["statistics"]["mutations_applied"] == 2
        assert report["statistics"]["successes"] == 1
        assert report["statistics"]["crashes"] == 1
        assert len(report["fuzzed_files"]) == 2
        assert len(report["crashes"]) == 1

    def test_multiple_mutations_per_file(self, temp_session_dirs, sample_dicom_file):
        """Test recording multiple mutations for single file."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_session_dirs["output"]),
            reports_dir=str(temp_session_dirs["reports"]),
        )

        output_file = temp_session_dirs["output"] / "fuzzed_001.dcm"
        shutil.copy(sample_dicom_file, output_file)

        session.start_file_fuzzing(
            source_file=sample_dicom_file,
            output_file=output_file,
            severity="moderate",
        )

        # Record multiple mutations
        session.record_mutation("bit_flip", "flip_bits")
        session.record_mutation("dictionary", "replace")
        session.record_mutation("structure", "delete_tag")

        session.end_file_fuzzing(output_file=output_file, success=True)

        assert len(session.fuzzed_files[file_id].mutations) == 3
        assert session.stats["mutations_applied"] == 3
