"""
Integration tests for FuzzingSession - Complete End-to-End Workflows

These tests verify full fuzzing session workflows including:
- Complete mutation tracking pipelines
- Crash recording and preservation
- Report generation with all components
- Error recovery and edge cases
"""

import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pydicom
import pytest
from pydicom.dataset import Dataset

from core.fuzzing_session import (
    CrashRecord,
    FuzzedFileRecord,
    FuzzingSession,
    MutationRecord,
)


@pytest.fixture
def temp_workspace():
    """Create a temporary workspace for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        workspace = Path(tmpdir)
        (workspace / "input").mkdir()
        (workspace / "output").mkdir()
        (workspace / "reports").mkdir()
        (workspace / "crashes").mkdir()

        # Create a sample DICOM file with proper file meta information
        from pydicom.dataset import FileDataset, FileMetaDataset
        import pydicom.uid

        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        file_meta.MediaStorageSOPInstanceUID = "1.2.3.4.5"
        file_meta.ImplementationClassUID = "1.2.3.4"
        file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian

        ds = FileDataset(None, {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyDate = "20240101"
        ds.Modality = "CT"
        ds.SOPInstanceUID = "1.2.3.4.5"
        ds.StudyInstanceUID = "1.2.3.4.5.6"
        ds.SeriesInstanceUID = "1.2.3.4.5.6.7"

        sample_file = workspace / "input" / "sample.dcm"
        ds.save_as(str(sample_file))

        yield workspace


@pytest.fixture
def fuzzing_session(temp_workspace):
    """Create a fuzzing session with temp directories."""
    session = FuzzingSession(
        session_name="test_session",
        output_dir=str(temp_workspace / "output"),
        reports_dir=str(temp_workspace / "reports"),
    )
    # Override crashes_dir to use temp workspace
    session.crashes_dir = temp_workspace / "crashes" / session.session_id
    session.crashes_dir.mkdir(parents=True, exist_ok=True)
    return session


class TestFuzzingSessionIntegration:
    """Integration tests for complete fuzzing workflows."""

    def test_complete_fuzzing_workflow(self, fuzzing_session, temp_workspace):
        """Test a complete fuzzing workflow from start to finish."""
        source_file = temp_workspace / "input" / "sample.dcm"
        output_file = temp_workspace / "output" / "fuzzed_001.dcm"

        # Start file fuzzing
        file_id = fuzzing_session.start_file_fuzzing(
            source_file=source_file,
            output_file=output_file,
            severity="moderate"
        )

        assert file_id is not None
        assert fuzzing_session.current_file_record is not None
        assert fuzzing_session.stats["files_fuzzed"] == 1

        # Record multiple mutations
        mutations = [
            {
                "strategy_name": "BitFlipper",
                "mutation_type": "flip_bits",
                "target_tag": "(0010,0010)",
                "target_element": "PatientName",
                "original_value": "Test^Patient",
                "mutated_value": "Test\x00Patient",
            },
            {
                "strategy_name": "ValueInjector",
                "mutation_type": "sql_injection",
                "target_tag": "(0010,0020)",
                "target_element": "PatientID",
                "original_value": "12345",
                "mutated_value": "12345' OR '1'='1",
            },
            {
                "strategy_name": "PixelFuzzer",
                "mutation_type": "corrupt_pixels",
                "target_element": "PixelData",
                "parameters": {"corruption_rate": 0.1},
            }
        ]

        for mutation_data in mutations:
            fuzzing_session.record_mutation(**mutation_data)

        assert len(fuzzing_session.current_file_record.mutations) == 3
        assert fuzzing_session.stats["mutations_applied"] == 3

        # Create the actual fuzzed file
        ds = pydicom.dcmread(str(source_file))
        ds.PatientName = "Test\x00Patient"
        ds.PatientID = "12345' OR '1'='1"
        ds.save_as(str(output_file))

        # End file fuzzing
        fuzzing_session.end_file_fuzzing(output_file, success=True)

        # Verify file record is complete
        file_record = fuzzing_session.fuzzed_files[file_id]
        assert file_record.file_hash != ""
        assert len(file_record.fuzzed_metadata) > 0
        assert fuzzing_session.current_file_record is None  # Should be cleared

    def test_crash_recording_workflow(self, fuzzing_session, temp_workspace):
        """Test recording and preserving crash information."""
        source_file = temp_workspace / "input" / "sample.dcm"
        output_file = temp_workspace / "output" / "crash_trigger.dcm"

        # Create a fuzzed file that "causes" a crash
        file_id = fuzzing_session.start_file_fuzzing(
            source_file=source_file,
            output_file=output_file,
            severity="aggressive"
        )

        # Record mutations
        fuzzing_session.record_mutation(
            strategy_name="HeaderCorruptor",
            mutation_type="corrupt_header",
            target_element="FileMetaInfo",
            original_value="DICM",
            mutated_value="XXXX",
        )

        # Create the fuzzed file
        shutil.copy(str(source_file), str(output_file))

        fuzzing_session.end_file_fuzzing(output_file)

        # Simulate a crash
        crash_record = fuzzing_session.record_crash(
            file_id=file_id,
            crash_type="crash",
            exception_type="SegmentationFault",
            exception_message="Access violation at 0x00000000",
            stack_trace="at DicomParser.ParseHeader()\nat DicomViewer.LoadFile()\nat main()",
            viewer_path="dicom_viewer.exe",
        )
        crash_id = crash_record.crash_id

        # Verify crash was recorded
        assert len(fuzzing_session.crashes) == 1
        assert fuzzing_session.stats["crashes"] == 1

        crash_record = fuzzing_session.crashes[0]
        assert crash_record.crash_id == crash_id
        assert crash_record.fuzzed_file_id == file_id
        assert crash_record.exception_type == "SegmentationFault"

        # Verify artifact preservation
        # The crash log should exist
        assert Path(crash_record.crash_log_path).exists()
        # The preserved sample should exist
        assert Path(crash_record.preserved_sample_path).exists()

    def test_multiple_file_sessions(self, fuzzing_session, temp_workspace):
        """Test handling multiple file fuzzing sessions."""
        source_file = temp_workspace / "input" / "sample.dcm"

        file_ids = []

        # Fuzz multiple files
        for i in range(5):
            output_file = temp_workspace / "output" / f"fuzzed_{i:03d}.dcm"

            file_id = fuzzing_session.start_file_fuzzing(
                source_file=source_file,
                output_file=output_file,
                severity="moderate"
            )

            # Record different mutations for each file
            for j in range(i + 1):
                fuzzing_session.record_mutation(
                    strategy_name=f"Strategy{j}",
                    mutation_type="test",
                    original_value=f"original_{j}",
                    mutated_value=f"mutated_{j}",
                )

            # Create the file
            shutil.copy(str(source_file), str(output_file))

            fuzzing_session.end_file_fuzzing(output_file)
            file_ids.append(file_id)

        # Verify all files were tracked
        assert fuzzing_session.stats["files_fuzzed"] == 5
        assert fuzzing_session.stats["mutations_applied"] == 15  # 1+2+3+4+5
        assert len(fuzzing_session.fuzzed_files) == 5

        # Verify each file has correct mutation count
        for i, file_id in enumerate(file_ids):
            file_record = fuzzing_session.fuzzed_files[file_id]
            assert len(file_record.mutations) == i + 1

    def test_report_generation(self, fuzzing_session, temp_workspace):
        """Test comprehensive report generation."""
        source_file = temp_workspace / "input" / "sample.dcm"

        # Create a complex session with multiple files and crashes
        for i in range(3):
            output_file = temp_workspace / "output" / f"file_{i}.dcm"
            file_id = fuzzing_session.start_file_fuzzing(
                source_file, output_file, "moderate"
            )

            fuzzing_session.record_mutation(
                strategy_name="TestStrategy",
                mutation_type="test",
                original_value=f"orig_{i}",
                mutated_value=f"mut_{i}",
            )

            shutil.copy(str(source_file), str(output_file))
            fuzzing_session.end_file_fuzzing(output_file)

            # Simulate crash for first file
            if i == 0:
                fuzzing_session.record_crash(
                    file_id=file_id,
                    crash_type="crash",
                    exception_type="TestCrash",
                    exception_message="Test crash message",
                )

        # Generate session report
        report_path = fuzzing_session.save_session_report()

        assert report_path.exists()

        # Load and verify report content
        with open(report_path, "r") as f:
            report = json.load(f)

        assert report["session_info"]["session_name"] == "test_session"
        assert report["statistics"]["files_fuzzed"] == 3
        assert report["statistics"]["mutations_applied"] == 3
        assert report["statistics"]["crashes"] == 1
        assert len(report["fuzzed_files"]) == 3
        assert len(report["crashes"]) == 1

    def test_error_recovery(self, fuzzing_session, temp_workspace):
        """Test error handling and recovery scenarios."""
        source_file = temp_workspace / "input" / "sample.dcm"
        output_file = temp_workspace / "output" / "error_test.dcm"

        # Test recording mutation without active session
        with pytest.raises(RuntimeError, match="No active file fuzzing session"):
            fuzzing_session.record_mutation(
                strategy_name="Test",
                mutation_type="test",
            )

        # Start a session
        file_id = fuzzing_session.start_file_fuzzing(
            source_file, output_file, "moderate"
        )

        # Test ending session without creating file
        fuzzing_session.end_file_fuzzing(output_file, success=False)

        # File hash should be empty
        assert fuzzing_session.fuzzed_files[file_id].file_hash == ""

        # Test with non-existent source file
        non_existent = temp_workspace / "input" / "missing.dcm"
        file_id = fuzzing_session.start_file_fuzzing(
            non_existent, output_file, "moderate"
        )

        # Should still create record even if metadata extraction fails
        assert file_id in fuzzing_session.fuzzed_files

    def test_metadata_extraction(self, fuzzing_session, temp_workspace):
        """Test DICOM metadata extraction and comparison."""
        source_file = temp_workspace / "input" / "sample.dcm"
        output_file = temp_workspace / "output" / "metadata_test.dcm"

        # Start fuzzing
        file_id = fuzzing_session.start_file_fuzzing(
            source_file, output_file, "moderate"
        )

        # Verify source metadata was extracted
        file_record = fuzzing_session.fuzzed_files[file_id]
        assert "PatientName" in file_record.source_metadata
        assert file_record.source_metadata["PatientName"] == "Test^Patient"
        assert "Modality" in file_record.source_metadata

        # Modify and save
        ds = pydicom.dcmread(str(source_file))
        ds.PatientName = "Modified^Patient"
        ds.InstitutionName = "New Hospital"  # Add new field
        ds.save_as(str(output_file))

        # End fuzzing
        fuzzing_session.end_file_fuzzing(output_file)

        # Verify fuzzed metadata
        assert file_record.fuzzed_metadata["PatientName"] == "Modified^Patient"
        assert "InstitutionName" in file_record.fuzzed_metadata

    def test_session_summary(self, fuzzing_session, temp_workspace):
        """Test session summary generation."""
        source_file = temp_workspace / "input" / "sample.dcm"

        # Create a session with various results
        test_results = ["success", "crash", "hang", "error", "success"]

        for i, result in enumerate(test_results):
            output_file = temp_workspace / "output" / f"test_{i}.dcm"
            file_id = fuzzing_session.start_file_fuzzing(
                source_file, output_file, "moderate"
            )

            shutil.copy(str(source_file), str(output_file))
            fuzzing_session.end_file_fuzzing(output_file)

            # Mark test result
            fuzzing_session.mark_test_result(file_id, result)

            if result == "crash":
                fuzzing_session.record_crash(
                    file_id=file_id,
                    crash_type="crash",
                    exception_type="TestCrash",
                )

        # Get summary
        summary = fuzzing_session.get_session_summary()

        assert summary["total_files"] == 5
        assert summary["total_mutations"] == 0  # No mutations recorded in this test
        assert summary["crashes"] == 1
        assert summary["hangs"] == 1
        assert summary["successes"] == 2
        assert "duration" in summary
        assert "files_per_minute" in summary

    def test_crash_deduplication_info(self, fuzzing_session, temp_workspace):
        """Test that crash records include info needed for deduplication."""
        source_file = temp_workspace / "input" / "sample.dcm"
        output_file = temp_workspace / "output" / "dedup_test.dcm"

        # Create file with specific mutations
        file_id = fuzzing_session.start_file_fuzzing(
            source_file, output_file, "aggressive"
        )

        mutations = [
            ("HeaderFuzzer", "corrupt_header", "(0008,0005)", "SpecificCharacterSet"),
            ("ValueFuzzer", "null_inject", "(0010,0010)", "PatientName"),
        ]

        for strategy, mut_type, tag, element in mutations:
            fuzzing_session.record_mutation(
                strategy_name=strategy,
                mutation_type=mut_type,
                target_tag=tag,
                target_element=element,
            )

        shutil.copy(str(source_file), str(output_file))
        fuzzing_session.end_file_fuzzing(output_file)

        # Record crash with full details
        crash_info = {
            "exception_type": "ValueError",
            "exception_message": "Invalid character encoding",
            "stack_trace": [
                "File parser.py, line 123, in parse_header",
                "File decoder.py, line 456, in decode_string",
            ],
        }

        crash_record = fuzzing_session.record_crash(
            file_id=file_id,
            crash_type="crash",
            exception_type=crash_info["exception_type"],
            exception_message=crash_info["exception_message"],
            stack_trace="\n".join(crash_info["stack_trace"]),
        )
        crash_id = crash_record.crash_id

        crash_record = fuzzing_session.crashes[0]

        # Verify crash has mutation context for deduplication
        assert len(crash_record.mutation_sequence) == 2
        assert crash_record.mutation_sequence[0] == ("HeaderFuzzer", "corrupt_header")
        assert crash_record.mutation_sequence[1] == ("ValueFuzzer", "null_inject")

    def test_concurrent_session_handling(self, temp_workspace):
        """Test handling multiple concurrent fuzzing sessions."""
        sessions = []

        # Create multiple sessions
        for i in range(3):
            session = FuzzingSession(
                session_name=f"concurrent_{i}",
                output_dir=str(temp_workspace / "output" / f"session_{i}"),
                reports_dir=str(temp_workspace / "reports"),
            )
            sessions.append(session)

        # Each session should have unique IDs and directories
        session_ids = [s.session_id for s in sessions]
        assert len(set(session_ids)) == 3  # All unique

        # Verify independent operation
        source_file = temp_workspace / "input" / "sample.dcm"

        for i, session in enumerate(sessions):
            output_file = temp_workspace / "output" / f"session_{i}" / "test.dcm"
            file_id = session.start_file_fuzzing(
                source_file, output_file, "moderate"
            )

            # Record different number of mutations
            for j in range(i + 1):
                session.record_mutation(
                    strategy_name=f"Strategy_{j}",
                    mutation_type="test",
                )

            shutil.copy(str(source_file), str(output_file))
            session.end_file_fuzzing(output_file)

        # Verify each session tracked independently
        assert sessions[0].stats["mutations_applied"] == 1
        assert sessions[1].stats["mutations_applied"] == 2
        assert sessions[2].stats["mutations_applied"] == 3

    def test_large_scale_session(self, fuzzing_session, temp_workspace):
        """Test session with large number of files and mutations."""
        source_file = temp_workspace / "input" / "sample.dcm"

        # Simulate fuzzing 100 files with various mutations
        for i in range(100):
            output_file = temp_workspace / "output" / f"large_{i:04d}.dcm"

            file_id = fuzzing_session.start_file_fuzzing(
                source_file, output_file, "moderate"
            )

            # Random number of mutations per file
            num_mutations = (i % 10) + 1
            for j in range(num_mutations):
                fuzzing_session.record_mutation(
                    strategy_name=f"Strategy{j % 5}",
                    mutation_type=f"type_{j % 3}",
                    original_value=f"orig_{i}_{j}",
                    mutated_value=f"mut_{i}_{j}",
                )

            # Don't actually create files to save time
            fuzzing_session.end_file_fuzzing(output_file, success=False)

            # Simulate some crashes
            if i % 20 == 0:
                fuzzing_session.record_crash(
                    file_id=file_id,
                    crash_type="crash",
                    exception_type=f"Crash{i}",
                )

        # Verify statistics
        assert fuzzing_session.stats["files_fuzzed"] == 100
        assert fuzzing_session.stats["mutations_applied"] == 550  # Sum of (i%10)+1 for i in 0..99
        assert fuzzing_session.stats["crashes"] == 5  # Every 20th file

        # Generate report should handle large session
        report_path = fuzzing_session.save_session_report()
        assert report_path.exists()

        # Verify report is valid JSON and contains all data
        with open(report_path, "r") as f:
            report = json.load(f)

        assert len(report["fuzzed_files"]) == 100
        assert len(report["crashes"]) == 5


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_invalid_paths(self, temp_workspace):
        """Test handling of invalid paths."""
        session = FuzzingSession(
            session_name="invalid_test",
            output_dir=str(temp_workspace / "nonexistent" / "deep" / "path"),
            reports_dir=str(temp_workspace / "another" / "deep" / "path"),
        )

        # Directories should be created
        assert session.output_dir.exists()
        assert session.reports_dir.exists()

    def test_special_characters_in_values(self, fuzzing_session, temp_workspace):
        """Test handling special characters in mutation values."""
        source_file = temp_workspace / "input" / "sample.dcm"
        output_file = temp_workspace / "output" / "special_chars.dcm"

        file_id = fuzzing_session.start_file_fuzzing(
            source_file, output_file, "moderate"
        )

        # Test various special characters
        special_values = [
            "Test\x00\x01\x02",  # Null bytes
            "Test\r\n\t",  # Whitespace
            '{"json": "value"}',  # JSON
            "<xml>test</xml>",  # XML
            "Test' OR '1'='1",  # SQL injection
            "Test\\Path\\To\\File",  # Backslashes
            "日本語テスト",  # Unicode
        ]

        for i, value in enumerate(special_values):
            fuzzing_session.record_mutation(
                strategy_name="SpecialCharTest",
                mutation_type="special",
                original_value=f"Original_{i}",
                mutated_value=value,
            )

        shutil.copy(str(source_file), str(output_file))
        fuzzing_session.end_file_fuzzing(output_file)

        # Verify all mutations were recorded correctly
        file_record = fuzzing_session.fuzzed_files[file_id]
        assert len(file_record.mutations) == len(special_values)

        # Generate report should handle special characters
        report_path = fuzzing_session.save_session_report()

        # Verify report is valid JSON despite special characters
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        assert len(report["fuzzed_files"]) == 1

    def test_empty_session_report(self, fuzzing_session):
        """Test generating report for empty session."""
        # Generate report without any fuzzing
        report_path = fuzzing_session.save_session_report()

        assert report_path.exists()

        with open(report_path, "r") as f:
            report = json.load(f)

        assert report["statistics"]["files_fuzzed"] == 0
        assert report["statistics"]["mutations_applied"] == 0
        assert len(report["fuzzed_files"]) == 0
        assert len(report["crashes"]) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])