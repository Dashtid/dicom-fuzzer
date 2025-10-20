"""
Tests for Enhanced HTML Reporter

Tests comprehensive HTML report generation with crash forensics.
Full coverage for HTML generation, template rendering, and data handling.
"""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from dicom_fuzzer.core.enhanced_reporter import EnhancedReportGenerator


class TestEnhancedReportGenerator:
    """Test enhanced report generation functionality."""

    @pytest.fixture
    def temp_report_dir(self):
        """Create temporary directory for reports."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def minimal_session_data(self):
        """Create minimal valid session data."""
        return {
            "session_info": {
                "session_id": "test_session_001",
                "session_name": "Test Fuzzing Session",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {
                "total_files_processed": 10,
                "total_mutations_applied": 50,
                "total_crashes": 2,
                "total_hangs": 1,
            },
            "crashes": [],
            "fuzzed_files": {},
        }

    @pytest.fixture
    def session_data_with_crashes(self):
        """Create session data with crashes."""
        return {
            "session_info": {
                "session_id": "crash_session_001",
                "session_name": "Crash Test Session",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {
                "total_files_processed": 5,
                "total_mutations_applied": 25,
                "total_crashes": 2,
                "total_hangs": 0,
            },
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "fuzzed_001.dcm",
                    "exception_type": "ValueError",
                    "exception_message": "Invalid header",
                    "stack_trace": "File test.py, line 10\nValueError: Invalid header",
                },
                {
                    "crash_id": "crash_002",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "hang",
                    "severity": "medium",
                    "fuzzed_file_id": "file_002",
                    "fuzzed_file_path": "fuzzed_002.dcm",
                    "exception_message": "Timeout after 30s",
                },
            ],
            "fuzzed_files": {
                "file_001": {
                    "file_id": "file_001",
                    "source_file": "original.dcm",
                    "output_file": "fuzzed_001.dcm",
                    "mutations": [
                        {
                            "mutation_id": "mut_001",
                            "strategy_name": "metadata_fuzzer",
                            "mutation_type": "corrupt_tag",
                        }
                    ],
                },
                "file_002": {
                    "file_id": "file_002",
                    "source_file": "original.dcm",
                    "output_file": "fuzzed_002.dcm",
                    "mutations": [],
                },
            },
        }

    def test_generator_initialization(self, temp_report_dir):
        """Test generator initialization."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        assert generator.output_dir == temp_report_dir
        assert temp_report_dir.exists()

    def test_generate_html_report_creates_file(
        self, temp_report_dir, minimal_session_data
    ):
        """Test that HTML report file is created."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert report_path.stat().st_size > 0

    def test_html_report_contains_session_info(
        self, temp_report_dir, minimal_session_data
    ):
        """Test that HTML report contains session information."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert "Test Fuzzing Session" in html
        assert "test_session_001" in html

    def test_html_report_contains_statistics(
        self, temp_report_dir, minimal_session_data
    ):
        """Test that HTML report contains statistics."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert "10" in html  # total_files_processed
        assert "50" in html  # total_mutations_applied

    def test_html_report_with_crashes(self, temp_report_dir, session_data_with_crashes):
        """Test HTML report generation with crash data."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_crashes)

        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check for crash information
        assert "crash_001" in html
        assert "ValueError" in html
        assert "Invalid header" in html

    def test_html_report_valid_structure(self, temp_report_dir, minimal_session_data):
        """Test that generated HTML has valid structure."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check for basic HTML structure
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "<head>" in html
        assert "<body>" in html
        assert "</html>" in html

    def test_html_report_has_styling(self, temp_report_dir, minimal_session_data):
        """Test that HTML report includes styling."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()

        assert "<style>" in html
        assert "</style>" in html

    def test_custom_output_path(self, temp_report_dir, minimal_session_data):
        """Test generating report with custom output path."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        custom_path = temp_report_dir / "custom_report.html"
        report_path = generator.generate_html_report(
            minimal_session_data, output_path=custom_path
        )

        assert report_path == custom_path
        assert custom_path.exists()

    def test_multiple_reports_same_generator(self, temp_report_dir):
        """Test generating multiple reports with same generator instance."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        # Generate first report
        data1 = {
            "session_info": {
                "session_id": "session_1",
                "session_name": "Session 1",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {"total_files_processed": 5},
            "crashes": [],
            "fuzzed_files": {},
        }

        # Generate second report
        data2 = {
            "session_info": {
                "session_id": "session_2",
                "session_name": "Session 2",
                "start_time": datetime.now().isoformat(),
                "end_time": datetime.now().isoformat(),
            },
            "statistics": {"total_files_processed": 10},
            "crashes": [],
            "fuzzed_files": {},
        }

        report1 = generator.generate_html_report(data1)
        report2 = generator.generate_html_report(data2)

        assert report1.exists()
        assert report2.exists()
        assert report1 != report2

    def test_crash_details_section(self, temp_report_dir, session_data_with_crashes):
        """Test that crash details section is generated."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_crashes)

        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check for crash details
        assert "crash_001" in html or "Crash Details" in html.lower()

    def test_mutation_analysis_section(
        self, temp_report_dir, session_data_with_crashes
    ):
        """Test that mutation analysis section is generated."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(session_data_with_crashes)

        with open(report_path, "r", encoding="utf-8") as f:
            html = f.read()

        # Check for mutation information
        assert "metadata_fuzzer" in html or "mutation" in html.lower()

    def test_empty_crashes_list(self, temp_report_dir, minimal_session_data):
        """Test report generation with no crashes."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        # Ensure crashes is empty
        minimal_session_data["crashes"] = []

        report_path = generator.generate_html_report(minimal_session_data)

        assert report_path.exists()

    def test_report_encoding_utf8(self, temp_report_dir, minimal_session_data):
        """Test that report is encoded in UTF-8."""
        generator = EnhancedReportGenerator(output_dir=str(temp_report_dir))

        report_path = generator.generate_html_report(minimal_session_data)

        # Should be able to read with UTF-8 encoding
        with open(report_path, "r", encoding="utf-8") as f:
            content = f.read()

        assert len(content) > 0
        assert 'charset="UTF-8"' in content or "utf-8" in content.lower()
