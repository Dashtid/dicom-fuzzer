"""
Tests for FuzzingSession - Complete Traceability System

Tests comprehensive session tracking including mutation recording,
crash preservation, and report generation.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from core.fuzzing_session import (
    CrashRecord,
    FuzzedFileRecord,
    FuzzingSession,
    MutationRecord,
)


class TestMutationRecord:
    """Test MutationRecord data class."""

    def test_mutation_record_creation(self):
        """Test creating a mutation record."""
        mutation = MutationRecord(
            mutation_id="mut_1",
            strategy_name="BitFlipper",
            timestamp=datetime.now(),
            target_tag="(0010,0010)",
            target_element="PatientName",
            mutation_type="flip_bits",
            original_value="John Doe",
            mutated_value="John\x00Doe",
            parameters={"flip_count": 3},
        )

        assert mutation.mutation_id == "mut_1"
        assert mutation.strategy_name == "BitFlipper"
        assert mutation.mutation_type == "flip_bits"
        assert mutation.parameters["flip_count"] == 3

    def test_mutation_record_to_dict(self):
        """Test mutation record serialization."""
        mutation = MutationRecord(
            mutation_id="mut_1",
            strategy_name="TestStrategy",
            timestamp=datetime.now(),
            mutation_type="test",
        )

        data = mutation.to_dict()

        assert isinstance(data, dict)
        assert data["mutation_id"] == "mut_1"
        assert data["strategy_name"] == "TestStrategy"
        assert isinstance(data["timestamp"], str)  # ISO format


class TestFuzzedFileRecord:
    """Test FuzzedFileRecord data class."""

    def test_fuzzed_file_record_creation(self):
        """Test creating a fuzzed file record."""
        record = FuzzedFileRecord(
            file_id="fuzz_001",
            source_file="input/test.dcm",
            output_file="output/fuzzed_test.dcm",
            timestamp=datetime.now(),
            file_hash="abc123",
            severity="moderate",
        )

        assert record.file_id == "fuzz_001"
        assert record.severity == "moderate"
        assert len(record.mutations) == 0  # Default empty list

    def test_fuzzed_file_with_mutations(self):
        """Test file record with mutations."""
        mutation = MutationRecord(
            mutation_id="mut_1",
            strategy_name="Test",
            timestamp=datetime.now(),
            mutation_type="test",
        )

        record = FuzzedFileRecord(
            file_id="fuzz_001",
            source_file="input/test.dcm",
            output_file="output/test.dcm",
            timestamp=datetime.now(),
            file_hash="hash",
            severity="moderate",
            mutations=[mutation],
        )

        assert len(record.mutations) == 1
        assert record.mutations[0].strategy_name == "Test"


class TestCrashRecord:
    """Test CrashRecord data class."""

    def test_crash_record_creation(self):
        """Test creating a crash record."""
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="fuzz_001",
            fuzzed_file_path="output/fuzzed.dcm",
            return_code=-1,
            exception_message="Segmentation fault",
        )

        assert crash.crash_id == "crash_001"
        assert crash.severity == "high"
        assert crash.return_code == -1

    def test_crash_record_to_dict(self):
        """Test crash record serialization."""
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="critical",
            fuzzed_file_id="fuzz_001",
            fuzzed_file_path="test.dcm",
        )

        data = crash.to_dict()

        assert isinstance(data, dict)
        assert data["crash_id"] == "crash_001"
        assert data["severity"] == "critical"
        assert isinstance(data["timestamp"], str)


class TestFuzzingSession:
    """Test FuzzingSession complete workflow."""

    @pytest.fixture
    def temp_dirs(self):
        """Create temporary directories for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            output_dir = tmp_path / "output"
            reports_dir = tmp_path / "reports"
            crashes_dir = tmp_path / "crashes"

            output_dir.mkdir()
            reports_dir.mkdir()
            crashes_dir.mkdir()

            yield {
                "output": output_dir,
                "reports": reports_dir,
                "crashes": crashes_dir,
            }

    def test_session_initialization(self, temp_dirs):
        """Test session initialization."""
        session = FuzzingSession(
            session_name="test_session",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        assert "test_session" in session.session_id
        assert session.session_name == "test_session"
        assert len(session.fuzzed_files) == 0
        assert len(session.crashes) == 0

    def test_file_fuzzing_lifecycle(self, temp_dirs):
        """Test complete file fuzzing lifecycle."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Start fuzzing
        source_file = Path("input/test.dcm")
        output_file = temp_dirs["output"] / "fuzzed.dcm"

        file_id = session.start_file_fuzzing(
            source_file=source_file,
            output_file=output_file,
            severity="moderate",
        )

        assert file_id.startswith("fuzz_")
        assert file_id in session.fuzzed_files

        # Record mutation
        session.record_mutation(
            strategy_name="BitFlipper",
            mutation_type="flip_bits",
            target_tag="(0010,0010)",
            original_value="Test",
            mutated_value="T\x00st",
        )

        # End fuzzing
        output_file.write_text("dummy")  # Create file
        session.end_file_fuzzing(output_file, success=True)

        # Verify
        record = session.fuzzed_files[file_id]
        assert len(record.mutations) == 1
        assert record.file_hash != ""  # Hash calculated
        assert record.mutations[0].strategy_name == "BitFlipper"

    def test_mutation_recording(self, temp_dirs):
        """Test mutation recording."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Start file
        file_id = session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=Path("out.dcm"),
            severity="moderate",
        )

        # Record multiple mutations
        session.record_mutation(strategy_name="Mut1", mutation_type="type1")
        session.record_mutation(strategy_name="Mut2", mutation_type="type2")
        session.record_mutation(strategy_name="Mut3", mutation_type="type3")

        # Verify
        record = session.fuzzed_files[file_id]
        assert len(record.mutations) == 3
        assert session.stats["mutations_applied"] == 3

    def test_crash_recording(self, temp_dirs):
        """Test crash recording with artifact preservation."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Create fuzzed file
        file_id = session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=temp_dirs["output"] / "fuzzed.dcm",
            severity="moderate",
        )

        # Create actual file
        (temp_dirs["output"] / "fuzzed.dcm").write_text("dummy")

        session.end_file_fuzzing(temp_dirs["output"] / "fuzzed.dcm", success=True)

        # Record crash
        crash = session.record_crash(
            file_id=file_id,
            crash_type="crash",
            severity="high",
            return_code=-1,
            exception_message="Test crash",
            viewer_path="C:/Test/viewer.exe",
        )

        # Verify crash preserved
        assert crash.crash_id.startswith("crash_")
        assert Path(crash.preserved_sample_path).exists()
        assert Path(crash.crash_log_path).exists()
        assert crash.reproduction_command is not None
        assert len(session.crashes) == 1

    def test_session_report_generation(self, temp_dirs):
        """Test session report generation."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Add some data
        session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=temp_dirs["output"] / "out.dcm",
            severity="moderate",
        )

        session.record_mutation(strategy_name="Test", mutation_type="test")

        (temp_dirs["output"] / "out.dcm").write_text("dummy")
        session.end_file_fuzzing(temp_dirs["output"] / "out.dcm", success=True)

        # Generate report
        report = session.generate_session_report()

        assert "session_info" in report
        assert "statistics" in report
        assert "fuzzed_files" in report
        assert report["statistics"]["files_fuzzed"] == 1
        assert report["statistics"]["mutations_applied"] == 1

    def test_save_session_report(self, temp_dirs):
        """Test saving session report to file."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Save report
        report_path = session.save_session_report()

        assert report_path.exists()
        assert report_path.suffix == ".json"

        # Verify content
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "session_info" in data
        assert data["session_info"]["session_name"] == "test"

    def test_statistics_tracking(self, temp_dirs):
        """Test statistics are tracked correctly."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Process multiple files
        for i in range(3):
            current_file_id = session.start_file_fuzzing(
                source_file=Path(f"test{i}.dcm"),
                output_file=temp_dirs["output"] / f"out{i}.dcm",
                severity="moderate",
            )

            # Add mutations
            for j in range(2):
                session.record_mutation(strategy_name=f"Mut{j}", mutation_type="test")

            (temp_dirs["output"] / f"out{i}.dcm").write_text("dummy")
            session.end_file_fuzzing(temp_dirs["output"] / f"out{i}.dcm", success=True)

            # Record test result
            if i == 0:
                session.record_test_result(current_file_id, "crash")
            elif i == 1:
                session.record_test_result(current_file_id, "hang")
            else:
                session.record_test_result(current_file_id, "success")

        # Verify stats
        assert session.stats["files_fuzzed"] == 3
        assert session.stats["mutations_applied"] == 6
        assert session.stats["crashes"] == 1
        assert session.stats["hangs"] == 1
        assert session.stats["successes"] == 1

    def test_metadata_extraction(self, temp_dirs):
        """Test DICOM metadata extraction."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Note: Without real DICOM file, metadata will be empty or error
        # This tests the error handling
        metadata = session._extract_metadata(Path("nonexistent.dcm"))

        assert isinstance(metadata, dict)
        # Should handle missing file gracefully

    def test_file_hash_calculation(self, temp_dirs):
        """Test file hash calculation."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Create test file
        test_file = temp_dirs["output"] / "test.txt"
        test_file.write_text("test content")

        hash_val = session._calculate_file_hash(test_file)

        assert isinstance(hash_val, str)
        assert len(hash_val) == 64  # SHA256 hex digest length

    def test_crash_log_creation(self, temp_dirs):
        """Test crash log file creation."""
        session = FuzzingSession(
            session_name="test",
            output_dir=str(temp_dirs["output"]),
            reports_dir=str(temp_dirs["reports"]),
        )

        # Create file record
        file_record = FuzzedFileRecord(
            file_id="fuzz_001",
            source_file="test.dcm",
            output_file="out.dcm",
            timestamp=datetime.now(),
            file_hash="hash",
            severity="moderate",
            mutations=[
                MutationRecord(
                    mutation_id="mut_1",
                    strategy_name="Test",
                    timestamp=datetime.now(),
                    mutation_type="test",
                )
            ],
        )

        # Create crash log
        log_path = session.crashes_dir / "test_crash.log"
        session._create_crash_log(
            log_path=log_path,
            file_record=file_record,
            crash_type="crash",
            return_code=-1,
            exception_type="SegFault",
            exception_message="Test crash",
            stack_trace="line 1\nline 2",
        )

        assert log_path.exists()

        # Verify content
        content = log_path.read_text(encoding="utf-8")
        assert "CRASH REPORT" in content
        assert "fuzz_001" in content
        assert "Test crash" in content
