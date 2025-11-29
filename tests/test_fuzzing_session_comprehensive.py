"""Comprehensive tests for dicom_fuzzer.core.fuzzing_session module.

This test suite provides thorough coverage of fuzzing session tracking,
mutation recording, crash logging, and report generation.
"""

import json
from datetime import datetime
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.fuzzing_session import (
    CrashRecord,
    FuzzedFileRecord,
    FuzzingSession,
    MutationRecord,
)


class TestMutationRecord:
    """Test suite for MutationRecord dataclass."""

    def test_initialization_required_fields(self):
        """Test MutationRecord with required fields."""
        timestamp = datetime.now()
        mutation = MutationRecord(
            mutation_id="mut_001",
            strategy_name="bit_flip",
            timestamp=timestamp,
        )

        assert mutation.mutation_id == "mut_001"
        assert mutation.strategy_name == "bit_flip"
        assert mutation.timestamp == timestamp

    def test_initialization_with_optional_fields(self):
        """Test MutationRecord with all fields."""
        timestamp = datetime.now()
        mutation = MutationRecord(
            mutation_id="mut_002",
            strategy_name="metadata_fuzzer",
            timestamp=timestamp,
            target_tag="(0010,0010)",
            target_element="PatientName",
            mutation_type="replace",
            original_value="John Doe",
            mutated_value="AAAA",
            parameters={"intensity": "high"},
        )

        assert mutation.target_tag == "(0010,0010)"
        assert mutation.target_element == "PatientName"
        assert mutation.mutation_type == "replace"
        assert mutation.original_value == "John Doe"
        assert mutation.mutated_value == "AAAA"
        assert mutation.parameters == {"intensity": "high"}

    def test_to_dict_serialization(self):
        """Test mutation record to_dict conversion."""
        timestamp = datetime(2025, 1, 1, 12, 0, 0)
        mutation = MutationRecord(
            mutation_id="mut_003",
            strategy_name="header_fuzzer",
            timestamp=timestamp,
            target_tag="(0008,0060)",
            mutation_type="flip_bits",
        )

        result = mutation.to_dict()

        assert result["mutation_id"] == "mut_003"
        assert result["strategy_name"] == "header_fuzzer"
        assert result["timestamp"] == "2025-01-01T12:00:00"
        assert result["target_tag"] == "(0008,0060)"


class TestFuzzedFileRecord:
    """Test suite for FuzzedFileRecord dataclass."""

    def test_initialization_required_fields(self):
        """Test FuzzedFileRecord with required fields."""
        timestamp = datetime.now()
        record = FuzzedFileRecord(
            file_id="file_001",
            source_file="/input/test.dcm",
            output_file="/output/fuzz_001.dcm",
            timestamp=timestamp,
            file_hash="abc123",
            severity="medium",
        )

        assert record.file_id == "file_001"
        assert record.source_file == "/input/test.dcm"
        assert record.output_file == "/output/fuzz_001.dcm"
        assert record.file_hash == "abc123"
        assert record.severity == "medium"

    def test_initialization_defaults(self):
        """Test FuzzedFileRecord default values."""
        record = FuzzedFileRecord(
            file_id="file_002",
            source_file="/input/test.dcm",
            output_file="/output/fuzz_002.dcm",
            timestamp=datetime.now(),
            file_hash="def456",
            severity="low",
        )

        assert record.mutations == []
        assert record.source_metadata == {}
        assert record.fuzzed_metadata == {}
        assert record.test_result is None
        assert record.crash_details is None

    def test_add_mutations(self):
        """Test adding mutations to file record."""
        record = FuzzedFileRecord(
            file_id="file_003",
            source_file="/test.dcm",
            output_file="/fuzz.dcm",
            timestamp=datetime.now(),
            file_hash="hash",
            severity="high",
        )

        mutation = MutationRecord(
            mutation_id="mut_001",
            strategy_name="test_strategy",
            timestamp=datetime.now(),
        )
        record.mutations.append(mutation)

        assert len(record.mutations) == 1
        assert record.mutations[0].mutation_id == "mut_001"

    def test_to_dict_serialization(self):
        """Test file record to_dict conversion."""
        timestamp = datetime(2025, 1, 1, 12, 0, 0)
        mutation = MutationRecord(
            mutation_id="mut_001",
            strategy_name="test",
            timestamp=timestamp,
        )

        record = FuzzedFileRecord(
            file_id="file_004",
            source_file="/source.dcm",
            output_file="/output.dcm",
            timestamp=timestamp,
            file_hash="hash123",
            severity="critical",
            mutations=[mutation],
            source_metadata={"key": "value"},
        )

        result = record.to_dict()

        assert result["file_id"] == "file_004"
        assert result["timestamp"] == "2025-01-01T12:00:00"
        assert len(result["mutations"]) == 1
        assert result["source_metadata"] == {"key": "value"}


class TestCrashRecord:
    """Test suite for CrashRecord dataclass."""

    def test_initialization_required_fields(self):
        """Test CrashRecord with required fields."""
        timestamp = datetime.now()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=timestamp,
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/path/to/fuzz.dcm",
        )

        assert crash.crash_id == "crash_001"
        assert crash.crash_type == "crash"
        assert crash.severity == "high"
        assert crash.fuzzed_file_id == "file_001"
        assert crash.fuzzed_file_path == "/path/to/fuzz.dcm"

    def test_initialization_with_optional_fields(self):
        """Test CrashRecord with all fields."""
        crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="exception",
            severity="critical",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/fuzz.dcm",
            return_code=-11,
            exception_type="SegmentationFault",
            exception_message="Segmentation fault at 0x1234",
            stack_trace="Stack trace here",
            crash_log_path="/logs/crash.log",
            preserved_sample_path="/crashes/crash.dcm",
            reproduction_command='viewer "/crashes/crash.dcm"',
            mutation_sequence=[("bit_flip", "flip"), ("header", "replace")],
        )

        assert crash.return_code == -11
        assert crash.exception_type == "SegmentationFault"
        assert crash.stack_trace == "Stack trace here"
        assert len(crash.mutation_sequence) == 2

    def test_to_dict_serialization(self):
        """Test crash record to_dict conversion."""
        timestamp = datetime(2025, 1, 1, 12, 0, 0)
        crash = CrashRecord(
            crash_id="crash_003",
            timestamp=timestamp,
            crash_type="hang",
            severity="medium",
            fuzzed_file_id="file_003",
            fuzzed_file_path="/fuzz.dcm",
            return_code=124,
        )

        result = crash.to_dict()

        assert result["crash_id"] == "crash_003"
        assert result["timestamp"] == "2025-01-01T12:00:00"
        assert result["crash_type"] == "hang"
        assert result["return_code"] == 124


class TestFuzzingSessionInitialization:
    """Test suite for FuzzingSession initialization."""

    def test_initialization_default_params(self, tmp_path):
        """Test FuzzingSession with default parameters."""
        with patch("dicom_fuzzer.core.fuzzing_session.Path") as mock_path:
            mock_path.return_value.mkdir = Mock()
            session = FuzzingSession(
                session_name="test_session",
                output_dir=str(tmp_path / "output"),
                reports_dir=str(tmp_path / "reports"),
            crashes_dir=str(tmp_path / "crashes"),
            )

            assert session.session_name == "test_session"
            assert session.session_id.startswith("test_session_")
            assert isinstance(session.start_time, datetime)

    def test_directories_created(self, tmp_path):
        """Test that required directories are created."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        assert session.output_dir.exists()
        assert session.reports_dir.exists()
        assert session.crashes_dir.exists()

    def test_initial_statistics(self, tmp_path):
        """Test initial statistics are zero."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        assert session.stats["files_fuzzed"] == 0
        assert session.stats["mutations_applied"] == 0
        assert session.stats["crashes"] == 0
        assert session.stats["hangs"] == 0
        assert session.stats["successes"] == 0

    def test_empty_collections(self, tmp_path):
        """Test empty fuzzed files and crashes collections."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        assert len(session.fuzzed_files) == 0
        assert len(session.crashes) == 0
        assert session.current_file_record is None


class TestFileFuzzingTracking:
    """Test suite for file fuzzing tracking."""

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_start_file_fuzzing(self, mock_extract, tmp_path):
        """Test starting file fuzzing tracking."""
        mock_extract.return_value = {"PatientID": "12345"}

        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        source = tmp_path / "source.dcm"
        source.touch()
        output = tmp_path / "output.dcm"

        file_id = session.start_file_fuzzing(source, output, "medium")

        assert file_id.startswith("fuzz_")
        assert session.current_file_record is not None
        assert session.current_file_record.file_id == file_id
        assert session.stats["files_fuzzed"] == 1

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_record_mutation(self, mock_extract, tmp_path):
        """Test recording a mutation."""
        mock_extract.return_value = {}
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        source = tmp_path / "source.dcm"
        source.touch()
        session.start_file_fuzzing(source, tmp_path / "output.dcm", "low")

        session.record_mutation(
            strategy_name="bit_flip",
            mutation_type="flip",
            target_tag="(0010,0010)",
            original_value="Original",
            mutated_value="Mutated",
        )

        assert len(session.current_file_record.mutations) == 1
        assert session.stats["mutations_applied"] == 1
        assert session.current_file_record.mutations[0].strategy_name == "bit_flip"

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_record_mutation_without_active_session(self, mock_extract, tmp_path):
        """Test recording mutation without active session raises error."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        with pytest.raises(RuntimeError, match="No active file fuzzing session"):
            session.record_mutation("test_strategy", "test_type")

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._calculate_file_hash")
    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_end_file_fuzzing(self, mock_extract, mock_hash, tmp_path):
        """Test ending file fuzzing tracking."""
        mock_extract.return_value = {"key": "value"}
        mock_hash.return_value = "abc123hash"

        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        source = tmp_path / "source.dcm"
        source.touch()
        output = tmp_path / "output.dcm"
        output.touch()

        file_id = session.start_file_fuzzing(source, output, "high")
        session.end_file_fuzzing(output, success=True)

        assert session.current_file_record is None
        assert file_id in session.fuzzed_files
        assert session.fuzzed_files[file_id].file_hash == "abc123hash"


class TestTestResultRecording:
    """Test suite for test result recording."""

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_record_test_result_success(self, mock_extract, tmp_path):
        """Test recording success result."""
        mock_extract.return_value = {}
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        source = tmp_path / "source.dcm"
        source.touch()
        file_id = session.start_file_fuzzing(source, tmp_path / "output.dcm", "low")
        session.end_file_fuzzing(tmp_path / "output.dcm", success=False)

        session.record_test_result(file_id, "success")

        assert session.fuzzed_files[file_id].test_result == "success"
        assert session.stats["successes"] == 1

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_record_test_result_crash(self, mock_extract, tmp_path):
        """Test recording crash result."""
        mock_extract.return_value = {}
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        source = tmp_path / "source.dcm"
        source.touch()
        file_id = session.start_file_fuzzing(source, tmp_path / "output.dcm", "high")
        session.end_file_fuzzing(tmp_path / "output.dcm", success=False)

        session.record_test_result(file_id, "crash", error_code=-11)

        assert session.fuzzed_files[file_id].test_result == "crash"
        assert session.stats["crashes"] == 1

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_record_test_result_unknown_file(self, mock_extract, tmp_path):
        """Test recording result for unknown file raises error."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        with pytest.raises(KeyError, match="Unknown file ID"):
            session.record_test_result("nonexistent_id", "success")


class TestCrashRecording:
    """Test suite for crash recording."""

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._create_crash_log")
    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_record_crash_basic(self, mock_extract, mock_log, tmp_path):
        """Test recording a basic crash."""
        mock_extract.return_value = {}
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        source = tmp_path / "source.dcm"
        source.touch()
        output = tmp_path / "output.dcm"
        output.touch()

        file_id = session.start_file_fuzzing(source, output, "high")
        session.end_file_fuzzing(output, success=True)

        crash = session.record_crash(
            file_id=file_id,
            crash_type="crash",
            severity="critical",
            return_code=-11,
        )

        assert crash.crash_id.startswith("crash_")
        assert crash.crash_type == "crash"
        assert crash.severity == "critical"
        assert len(session.crashes) == 1

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._create_crash_log")
    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_record_crash_with_details(self, mock_extract, mock_log, tmp_path):
        """Test recording crash with full details."""
        mock_extract.return_value = {}
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        source = tmp_path / "source.dcm"
        source.touch()
        output = tmp_path / "output.dcm"
        output.touch()

        file_id = session.start_file_fuzzing(source, output, "high")
        session.end_file_fuzzing(output, success=True)

        crash = session.record_crash(
            file_id=file_id,
            crash_type="exception",
            severity="high",
            exception_type="SegmentationFault",
            exception_message="Segfault at 0x1234",
            stack_trace="Stack trace here",
            viewer_path="/usr/bin/viewer",
        )

        assert crash.exception_type == "SegmentationFault"
        assert crash.reproduction_command is not None
        assert "/usr/bin/viewer" in crash.reproduction_command


class TestReportGeneration:
    """Test suite for report generation."""

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_generate_session_report(self, mock_extract, tmp_path):
        """Test generating session report."""
        mock_extract.return_value = {}
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        report = session.generate_session_report()

        assert "session_info" in report
        assert "statistics" in report
        assert "fuzzed_files" in report
        assert "crashes" in report
        assert report["session_info"]["session_name"] == "test"

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_save_session_report(self, mock_extract, tmp_path):
        """Test saving session report to JSON."""
        mock_extract.return_value = {}
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        report_path = session.save_session_report()

        assert report_path.exists()
        assert report_path.suffix == ".json"

        # Verify JSON is valid
        with open(report_path) as f:
            data = json.load(f)
            assert "session_info" in data

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_get_session_summary(self, mock_extract, tmp_path):
        """Test getting session summary."""
        mock_extract.return_value = {}
        session = FuzzingSession(
            session_name="test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        summary = session.get_session_summary()

        assert "session_id" in summary
        assert "duration" in summary
        assert "total_files" in summary
        assert "files_per_minute" in summary
        assert summary["session_name"] == "test"


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._create_crash_log")
    @patch("dicom_fuzzer.core.fuzzing_session.FuzzingSession._extract_metadata")
    def test_complete_fuzzing_workflow(self, mock_extract, mock_log, tmp_path):
        """Test complete fuzzing workflow."""
        mock_extract.return_value = {"PatientID": "12345"}
        session = FuzzingSession(
            session_name="integration_test",
            output_dir=str(tmp_path / "output"),
            reports_dir=str(tmp_path / "reports"),
        crashes_dir=str(tmp_path / "crashes"),
        )

        # Create test files
        source = tmp_path / "source.dcm"
        source.touch()
        output = tmp_path / "output.dcm"
        output.touch()

        # Start fuzzing
        file_id = session.start_file_fuzzing(source, output, "high")

        # Record mutations
        session.record_mutation("bit_flip", "flip", target_tag="(0010,0010)")
        session.record_mutation("header_fuzzer", "replace")

        # End fuzzing
        session.end_file_fuzzing(output, success=True)

        # Record test result
        session.record_test_result(file_id, "crash")

        # Record crash
        session.record_crash(file_id=file_id, crash_type="crash", severity="high")

        # Generate report
        report = session.generate_session_report()

        # Verify complete workflow
        assert session.stats["files_fuzzed"] == 1
        assert session.stats["mutations_applied"] == 2
        assert len(session.crashes) == 1
        assert len(report["fuzzed_files"]) == 1
