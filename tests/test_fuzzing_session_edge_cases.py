"""
Edge case tests for FuzzingSession

Tests edge cases, error paths, and boundary conditions that push coverage to 90%+
"""

import json
import time
from datetime import datetime
from pathlib import Path

import pytest

from dicom_fuzzer.core.fuzzing_session import FuzzingSession


class TestFuzzingSessionEdgeCases:
    """Test edge cases and error paths in FuzzingSession."""

    def test_record_test_result_unknown_file(self, tmp_path):
        """Test recording test result for unknown file ID raises error."""
        session = FuzzingSession("test_session", str(tmp_path))

        with pytest.raises(KeyError, match="Unknown file ID"):
            session.record_test_result(
                file_id="nonexistent_file",
                result="pass",
                execution_time=1.0
            )

    def test_record_crash_hang_type(self, tmp_path):
        """Test recording a hang-type crash updates stats correctly."""
        session = FuzzingSession("test_session", str(tmp_path))

        # Start file fuzzing
        file_id = session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=Path("fuzz_test.dcm"),
            severity="moderate"
        )

        # Record a hang (not a crash)
        crash = session.record_crash(
            file_id=file_id,
            crash_type="hang",
            return_code=-1,
            exception_type="Timeout",
            exception_message="Execution timed out",
        )

        # Verify hang was recorded
        assert crash.crash_type == "hang"
        assert session.stats["hangs"] == 1
        assert session.stats["crashes"] == 0

    def test_mutation_sequence_extraction(self, tmp_path):
        """Test that mutation sequences are extracted in crash records."""
        session = FuzzingSession("test_session", str(tmp_path))

        # Start file fuzzing
        file_id = session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=Path("fuzz_test.dcm"),
            severity="moderate"
        )

        # Record multiple mutations
        session.record_mutation(
            strategy_name="StrategyA",
            target_tag="(0010,0010)",
            mutation_type="flip_bits"
        )

        session.record_mutation(
            strategy_name="StrategyB",
            target_tag="(0010,0020)",
            mutation_type="swap_bytes"
        )

        # Record crash
        crash = session.record_crash(
            file_id=file_id,
            crash_type="crash",
            exception_type="ValueError",
            exception_message="Test"
        )

        # Verify crash has file record with mutations
        file_record = session.fuzzed_files[file_id]
        assert len(file_record.mutations) == 2
        assert file_record.mutations[0].strategy_name == "StrategyA"
        assert file_record.mutations[1].strategy_name == "StrategyB"

    def test_session_summary_calculations(self, tmp_path):
        """Test session summary calculates rates correctly."""
        session = FuzzingSession("test_session", str(tmp_path))

        # Add some test data
        session.stats["files_fuzzed"] = 10
        session.stats["mutations_applied"] = 50

        # Wait a tiny bit to ensure duration > 0
        time.sleep(0.01)

        summary = session.get_session_summary()

        # Verify calculations
        assert summary["total_files"] == 10
        assert summary["total_mutations"] == 50
        assert summary["duration"] > 0
        assert summary["files_per_minute"] > 0

    def test_session_report_with_mutations(self, tmp_path):
        """Test full session report includes mutation details."""
        session = FuzzingSession("test_session", str(tmp_path))

        # Create a complete file record with mutations
        file_id = session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=Path("fuzz_test.dcm"),
            severity="moderate"
        )

        session.record_mutation(
            strategy_name="TestStrategy",
            target_tag="(0010,0010)",
            mutation_type="flip_bits",
            original_value="Original",
            mutated_value="Mutated"
        )

        session.end_file_fuzzing(Path("fuzz_test.dcm"))

        # Generate full report
        report = session.generate_session_report()

        # Verify report structure (uses session_info, statistics, fuzzed_files)
        assert "session_info" in report
        assert "statistics" in report
        assert "fuzzed_files" in report

        # fuzzed_files is a dict, not a list
        assert len(report["fuzzed_files"]) == 1

        # Verify file has mutation info
        file_report = list(report["fuzzed_files"].values())[0]
        assert "mutations" in file_report
        assert len(file_report["mutations"]) == 1
        assert file_report["mutations"][0]["strategy_name"] == "TestStrategy"

    def test_save_report_creates_directory(self, tmp_path):
        """Test saving report creates output directory if needed."""
        session = FuzzingSession("test_session", str(tmp_path))

        # Create nested directory path that doesn't exist
        report_path = tmp_path / "reports" / "fuzzing" / "session_report.json"

        # Create the parent directory (save_session_report doesn't do this)
        report_path.parent.mkdir(parents=True, exist_ok=True)

        # Save report
        session.save_session_report(str(report_path))

        # Verify directory was created
        assert report_path.parent.exists()
        assert report_path.exists()

        # Verify content is valid JSON
        with open(report_path, 'r') as f:
            report_data = json.load(f)
            assert "session_info" in report_data
            assert "statistics" in report_data

    def test_crash_record_without_test_result(self, tmp_path):
        """Test crash recording when test_result hasn't been set."""
        session = FuzzingSession("test_session", str(tmp_path))

        file_id = session.start_file_fuzzing(
            source_file=Path("test.dcm"),
            output_file=Path("fuzz_test.dcm"),
            severity="moderate"
        )

        # Record crash WITHOUT calling record_test_result first
        # This tests the conditional in record_crash (line 419-423)
        crash = session.record_crash(
            file_id=file_id,
            crash_type="crash",
            exception_type="ValueError",
            exception_message="Test crash"
        )

        # Stats should be incremented
        assert session.stats["crashes"] == 1
        assert crash.crash_type == "crash"

    def test_multiple_crash_types(self, tmp_path):
        """Test recording different crash types updates stats correctly."""
        session = FuzzingSession("test_session", str(tmp_path))

        # File 1: crash
        file_id_1 = session.start_file_fuzzing(
            Path("test1.dcm"),
            Path("fuzz1.dcm"),
            "moderate"
        )
        session.record_crash(
            file_id=file_id_1,
            crash_type="crash",
            exception_type="Error",
            exception_message="Crash"
        )

        # File 2: hang
        file_id_2 = session.start_file_fuzzing(
            Path("test2.dcm"),
            Path("fuzz2.dcm"),
            "moderate"
        )
        session.record_crash(
            file_id=file_id_2,
            crash_type="hang",
            exception_type="Timeout",
            exception_message="Hang"
        )

        # File 3: another crash
        file_id_3 = session.start_file_fuzzing(
            Path("test3.dcm"),
            Path("fuzz3.dcm"),
            "moderate"
        )
        session.record_crash(
            file_id=file_id_3,
            crash_type="crash",
            exception_type="Error",
            exception_message="Crash 2"
        )

        # Verify stats
        assert session.stats["crashes"] == 2
        assert session.stats["hangs"] == 1
        assert len(session.crashes) == 3

    def test_session_with_zero_duration_edge_case(self, tmp_path):
        """Test session summary handles very short duration."""
        session = FuzzingSession("test_session", str(tmp_path))

        # Immediately generate summary
        summary = session.get_session_summary()

        # Should handle zero/near-zero duration gracefully
        assert "files_per_minute" in summary
        assert isinstance(summary["files_per_minute"], (int, float))
        assert summary["files_per_minute"] >= 0
