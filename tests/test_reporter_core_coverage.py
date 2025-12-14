"""Core Reporter Coverage Tests

Tests for dicom_fuzzer.core.reporter module to improve coverage from 21% to 80%+.
This module tests HTML/JSON report generation functionality.
"""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.core.crash_analyzer import CrashReport, CrashSeverity, CrashType
from dicom_fuzzer.core.reporter import ReportGenerator
from dicom_fuzzer.utils.identifiers import generate_crash_id


class TestReportGeneratorInit:
    """Tests for ReportGenerator initialization."""

    def test_init_creates_output_dir(self, tmp_path: Path) -> None:
        """Test that initialization creates output directory if not exists."""
        output_dir = tmp_path / "reports"
        assert not output_dir.exists()

        generator = ReportGenerator(output_dir=str(output_dir))

        assert output_dir.exists()
        assert generator.output_dir == output_dir

    def test_init_with_existing_dir(self, tmp_path: Path) -> None:
        """Test initialization with existing directory."""
        output_dir = tmp_path / "reports"
        output_dir.mkdir()

        generator = ReportGenerator(output_dir=str(output_dir))

        assert generator.output_dir == output_dir


class TestGenerateCrashHTMLReport:
    """Tests for generate_crash_html_report method."""

    @pytest.fixture
    def mock_analyzer(self) -> MagicMock:
        """Create mock crash analyzer with test data."""
        analyzer = MagicMock()

        # Create sample crash reports using valid CrashType values
        crash1 = CrashReport(
            crash_id=generate_crash_id(),
            timestamp=datetime.now(),
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.CRITICAL,
            test_case_path="/path/to/test1.dcm",
            stack_trace="File 'test.py', line 10\n  in function_a\nMemoryError",
            exception_message="Buffer overflow detected",
            crash_hash="abc123def456",
            additional_info={"exception_type": "MemoryError", "address": "0x7fff"},
        )

        crash2 = CrashReport(
            crash_id=generate_crash_id(),
            timestamp=datetime.now(),
            crash_type=CrashType.UNCAUGHT_EXCEPTION,
            severity=CrashSeverity.HIGH,
            test_case_path="/path/to/test2.dcm",
            stack_trace="File 'parser.py', line 50\n  in parse_header\nValueError",
            exception_message="Invalid DICOM header",
            crash_hash="def789ghi012",
            additional_info={"exception_type": "ValueError"},
        )

        crash3 = CrashReport(
            crash_id=generate_crash_id(),
            timestamp=datetime.now(),
            crash_type=CrashType.ASSERTION_FAILURE,
            severity=CrashSeverity.MEDIUM,
            test_case_path="/path/to/test3.dcm",
            stack_trace="",
            exception_message="VR mismatch",
            crash_hash="ghi345jkl678",
            additional_info={"exception_type": "AssertionError"},
        )

        crash4 = CrashReport(
            crash_id=generate_crash_id(),
            timestamp=datetime.now(),
            crash_type=CrashType.TIMEOUT,
            severity=CrashSeverity.LOW,
            test_case_path="/path/to/test4.dcm",
            stack_trace="",
            exception_message="Connection timeout",
            crash_hash="jkl901mno234",
            additional_info={},
        )

        analyzer.crashes = [crash1, crash2, crash3, crash4]
        analyzer.get_crash_summary.return_value = {
            "segmentation_fault": 1,
            "uncaught_exception": 1,
            "assertion_failure": 1,
            "timeout": 1,
        }

        return analyzer

    def test_generate_crash_html_report_creates_file(
        self, tmp_path: Path, mock_analyzer: MagicMock
    ) -> None:
        """Test that HTML report is created."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_html_report(
            mock_analyzer, campaign_name="Test Campaign"
        )

        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert "crash_report_" in report_path.name

    def test_generate_crash_html_report_contains_campaign_name(
        self, tmp_path: Path, mock_analyzer: MagicMock
    ) -> None:
        """Test that HTML report contains campaign name."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_html_report(
            mock_analyzer, campaign_name="My Security Test"
        )

        content = report_path.read_text(encoding="utf-8")
        assert "My Security Test" in content

    def test_generate_crash_html_report_contains_crash_details(
        self, tmp_path: Path, mock_analyzer: MagicMock
    ) -> None:
        """Test that HTML report contains crash details."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_html_report(mock_analyzer)

        content = report_path.read_text(encoding="utf-8")

        # Check for crash type badges
        assert "segmentation_fault" in content.lower()
        assert "uncaught_exception" in content.lower()

        # Check for severity badges (case-insensitive - HTML uses CSS classes)
        content_lower = content.lower()
        assert "critical" in content_lower
        assert "high" in content_lower
        assert "medium" in content_lower
        assert "low" in content_lower

    def test_generate_crash_html_report_with_empty_crashes(
        self, tmp_path: Path
    ) -> None:
        """Test HTML report with no crashes."""
        analyzer = MagicMock()
        analyzer.crashes = []
        analyzer.get_crash_summary.return_value = {}

        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_html_report(analyzer)

        content = report_path.read_text(encoding="utf-8")
        assert "No crashes found" in content

    def test_generate_crash_html_report_contains_stack_trace(
        self, tmp_path: Path, mock_analyzer: MagicMock
    ) -> None:
        """Test that HTML report contains stack traces."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_html_report(mock_analyzer)

        content = report_path.read_text(encoding="utf-8")
        assert "Stack Trace" in content
        assert "MemoryError" in content


class TestGenerateCrashJSONReport:
    """Tests for generate_crash_json_report method."""

    @pytest.fixture
    def mock_analyzer(self) -> MagicMock:
        """Create mock crash analyzer with test data."""
        analyzer = MagicMock()

        crash = CrashReport(
            crash_id=generate_crash_id(),
            timestamp=datetime(2025, 1, 15, 10, 30, 0),
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.CRITICAL,
            test_case_path="/path/to/test.dcm",
            stack_trace="Test stack trace",
            exception_message="Test error",
            crash_hash="abc123def456",
            additional_info={"exception_type": "TestError", "detail": "info"},
        )

        analyzer.crashes = [crash]
        analyzer.get_crash_summary.return_value = {"segmentation_fault": 1}

        return analyzer

    def test_generate_crash_json_report_creates_file(
        self, tmp_path: Path, mock_analyzer: MagicMock
    ) -> None:
        """Test that JSON report is created."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_json_report(
            mock_analyzer, campaign_name="Test Campaign"
        )

        assert report_path.exists()
        assert report_path.suffix == ".json"
        assert "crash_report_" in report_path.name

    def test_generate_crash_json_report_valid_json(
        self, tmp_path: Path, mock_analyzer: MagicMock
    ) -> None:
        """Test that JSON report is valid JSON."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_json_report(mock_analyzer)

        # Should not raise
        data = json.loads(report_path.read_text(encoding="utf-8"))

        assert "campaign_name" in data
        assert "generated_at" in data
        assert "summary" in data
        assert "crashes" in data

    def test_generate_crash_json_report_contains_summary(
        self, tmp_path: Path, mock_analyzer: MagicMock
    ) -> None:
        """Test that JSON report contains correct summary."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_json_report(mock_analyzer)

        data = json.loads(report_path.read_text(encoding="utf-8"))

        assert data["summary"]["total_crashes"] == 1
        assert data["summary"]["unique_crashes"] == 1
        assert "by_type" in data["summary"]
        assert "by_severity" in data["summary"]

    def test_generate_crash_json_report_crash_details(
        self, tmp_path: Path, mock_analyzer: MagicMock
    ) -> None:
        """Test that JSON report contains crash details."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_path = generator.generate_crash_json_report(mock_analyzer)

        data = json.loads(report_path.read_text(encoding="utf-8"))
        crash = data["crashes"][0]

        assert crash["crash_type"] == "segmentation_fault"
        assert crash["severity"] == "critical"
        assert crash["test_case_path"] == "/path/to/test.dcm"
        assert crash["crash_hash"] == "abc123def456"
        assert crash["exception_message"] == "Test error"
        assert crash["stack_trace"] == "Test stack trace"

    def test_generate_crash_json_report_severity_counts(self, tmp_path: Path) -> None:
        """Test that JSON report counts severities correctly."""
        analyzer = MagicMock()

        crashes = [
            CrashReport(
                crash_id=generate_crash_id(),
                timestamp=datetime.now(),
                crash_type=CrashType.SEGFAULT,
                severity=CrashSeverity.CRITICAL,
                test_case_path="/test1.dcm",
                stack_trace="",
                exception_message="Error 1",
                crash_hash="hash1",
                additional_info={},
            ),
            CrashReport(
                crash_id=generate_crash_id(),
                timestamp=datetime.now(),
                crash_type=CrashType.UNCAUGHT_EXCEPTION,
                severity=CrashSeverity.CRITICAL,
                test_case_path="/test2.dcm",
                stack_trace="",
                exception_message="Error 2",
                crash_hash="hash2",
                additional_info={},
            ),
            CrashReport(
                crash_id=generate_crash_id(),
                timestamp=datetime.now(),
                crash_type=CrashType.ASSERTION_FAILURE,
                severity=CrashSeverity.HIGH,
                test_case_path="/test3.dcm",
                stack_trace="",
                exception_message="Error 3",
                crash_hash="hash3",
                additional_info={},
            ),
        ]

        analyzer.crashes = crashes
        analyzer.get_crash_summary.return_value = {
            "segmentation_fault": 1,
            "uncaught_exception": 1,
            "assertion_failure": 1,
        }

        generator = ReportGenerator(output_dir=str(tmp_path))
        report_path = generator.generate_crash_json_report(analyzer)

        data = json.loads(report_path.read_text(encoding="utf-8"))

        assert data["summary"]["by_severity"]["critical"] == 2
        assert data["summary"]["by_severity"]["high"] == 1


class TestGeneratePerformanceHTMLReport:
    """Tests for generate_performance_html_report method."""

    def test_generate_performance_html_report_creates_file(
        self, tmp_path: Path
    ) -> None:
        """Test that performance HTML report is created."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 1000,
            "mutations_applied": 5000,
            "throughput_per_second": 25.5,
            "avg_time_per_file": 0.04,
            "peak_memory_mb": 512.0,
            "avg_cpu_percent": 75.3,
        }

        report_path = generator.generate_performance_html_report(
            metrics, campaign_name="Performance Test"
        )

        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert "performance_report_" in report_path.name

    def test_generate_performance_html_report_contains_metrics(
        self, tmp_path: Path
    ) -> None:
        """Test that performance report contains all metrics."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 1000,
            "mutations_applied": 5000,
            "throughput_per_second": 25.5,
            "avg_time_per_file": 0.04,
            "peak_memory_mb": 512.0,
            "avg_cpu_percent": 75.3,
        }

        report_path = generator.generate_performance_html_report(metrics)

        content = report_path.read_text(encoding="utf-8")

        assert "1000" in content  # files_generated
        assert "5000" in content  # mutations_applied
        assert "25.50" in content or "25.5" in content  # throughput
        assert "512" in content  # peak_memory_mb
        assert "75.3" in content or "75" in content  # avg_cpu_percent

    def test_generate_performance_html_report_with_strategy_usage(
        self, tmp_path: Path
    ) -> None:
        """Test performance report with strategy usage data."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 100,
            "mutations_applied": 500,
            "throughput_per_second": 10.0,
            "avg_time_per_file": 0.1,
            "peak_memory_mb": 256.0,
            "avg_cpu_percent": 50.0,
            "strategy_usage": {
                "bit_flip": 200,
                "byte_insert": 150,
                "truncate": 150,
            },
        }

        report_path = generator.generate_performance_html_report(metrics)

        content = report_path.read_text(encoding="utf-8")

        assert "bit_flip" in content
        assert "byte_insert" in content
        assert "truncate" in content
        assert "200" in content
        assert "150" in content


class TestGenerateReport:
    """Tests for generic generate_report method."""

    def test_generate_report_json_format(self, tmp_path: Path) -> None:
        """Test generate_report with JSON format."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_data = {
            "test_key": "test_value",
            "numbers": 123,
            "nested": {"a": 1, "b": 2},
        }

        report_path = generator.generate_report(report_data, format="json")

        assert report_path.exists()
        assert report_path.suffix == ".json"

        loaded = json.loads(report_path.read_text(encoding="utf-8"))
        assert loaded == report_data

    def test_generate_report_html_format(self, tmp_path: Path) -> None:
        """Test generate_report with HTML format."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_data = {
            "metric_a": "value_a",
            "metric_b": 456,
        }

        report_path = generator.generate_report(
            report_data, format="html", campaign_name="Generic Report"
        )

        assert report_path.exists()
        assert report_path.suffix == ".html"

        content = report_path.read_text(encoding="utf-8")
        assert "Generic Report" in content
        assert "metric_a" in content
        assert "value_a" in content
        assert "456" in content

    def test_generate_report_default_format(self, tmp_path: Path) -> None:
        """Test generate_report uses JSON by default."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        report_data = {"key": "value"}

        report_path = generator.generate_report(report_data)

        assert report_path.suffix == ".json"


class TestHTMLHelpers:
    """Tests for HTML generation helper methods."""

    def test_generate_html_header(self, tmp_path: Path) -> None:
        """Test HTML header generation."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        header = generator._generate_html_header("Test Title")

        assert "<!DOCTYPE html>" in header
        assert "<html" in header
        assert "Test Title" in header
        assert "<style>" in header

    def test_generate_html_footer(self, tmp_path: Path) -> None:
        """Test HTML footer generation."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        footer = generator._generate_html_footer()

        assert "</div>" in footer
        assert "</body>" in footer
        assert "</html>" in footer

    def test_generate_summary_section(self, tmp_path: Path) -> None:
        """Test summary section generation."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        summary = {
            "segmentation_fault": 5,
            "uncaught_exception": 3,
            "assertion_failure": 2,
        }

        section = generator._generate_summary_section(summary, total_crashes=10)

        assert "Summary" in section
        assert "10" in section  # total crashes
        assert "5" in section  # segmentation_fault count
        assert "3" in section  # uncaught_exception count

    def test_generate_crash_details_section_empty(self, tmp_path: Path) -> None:
        """Test crash details section with no crashes."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        section = generator._generate_crash_details_section([])

        assert "No crashes found" in section

    def test_generate_crash_details_section_with_crashes(self, tmp_path: Path) -> None:
        """Test crash details section with crashes."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        crash = CrashReport(
            crash_id=generate_crash_id(),
            timestamp=datetime.now(),
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.CRITICAL,
            test_case_path="/path/to/test.dcm",
            stack_trace="Traceback info here",
            exception_message="Buffer overflow",
            crash_hash="abc123def456",
            additional_info={"exception_type": "MemoryError"},
        )

        section = generator._generate_crash_details_section([crash])

        assert "Crash Details" in section
        # Check for severity (case-insensitive - HTML uses CSS classes)
        assert "critical" in section.lower()
        assert "Buffer overflow" in section
        assert "/path/to/test.dcm" in section
        assert "Stack Trace" in section


class TestCrashToDict:
    """Tests for _crash_to_dict helper method."""

    def test_crash_to_dict_basic(self, tmp_path: Path) -> None:
        """Test converting crash to dictionary."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        crash = CrashReport(
            crash_id=generate_crash_id(),
            timestamp=datetime(2025, 1, 15, 10, 30, 0),
            crash_type=CrashType.UNCAUGHT_EXCEPTION,
            severity=CrashSeverity.HIGH,
            test_case_path="/test.dcm",
            stack_trace="Stack here",
            exception_message="Parse failed",
            crash_hash="hash123",
            additional_info={"exception_type": "ParseError", "line": 42},
        )

        result = generator._crash_to_dict(crash)

        assert result["crash_type"] == "uncaught_exception"
        assert result["severity"] == "high"
        assert result["test_case_path"] == "/test.dcm"
        assert result["crash_hash"] == "hash123"
        assert result["exception_message"] == "Parse failed"
        assert result["stack_trace"] == "Stack here"
        assert result["exception_type"] == "ParseError"
        assert result["additional_info"]["line"] == 42

    def test_crash_to_dict_missing_exception_type(self, tmp_path: Path) -> None:
        """Test converting crash with missing exception type."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        crash = CrashReport(
            crash_id=generate_crash_id(),
            timestamp=datetime.now(),
            crash_type=CrashType.TIMEOUT,
            severity=CrashSeverity.LOW,
            test_case_path="/test.dcm",
            stack_trace="",
            exception_message="Network error",
            crash_hash="hash456",
            additional_info={},  # No exception_type
        )

        result = generator._crash_to_dict(crash)

        assert result["exception_type"] == "Unknown"


class TestPerformanceSection:
    """Tests for performance section generation."""

    def test_generate_performance_section(self, tmp_path: Path) -> None:
        """Test performance section generation."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 100,
            "mutations_applied": 500,
            "throughput_per_second": 10.0,
            "avg_time_per_file": 0.1,
            "peak_memory_mb": 256.0,
            "avg_cpu_percent": 50.0,
        }

        section = generator._generate_performance_section(metrics)

        assert "Performance Metrics" in section
        assert "100" in section
        assert "500" in section

    def test_generate_performance_section_with_zero_mutations(
        self, tmp_path: Path
    ) -> None:
        """Test performance section with zero mutations applied."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 0,
            "mutations_applied": 0,
            "throughput_per_second": 0.0,
            "avg_time_per_file": 0.0,
            "peak_memory_mb": 0.0,
            "avg_cpu_percent": 0.0,
            "strategy_usage": {"bit_flip": 0},
        }

        section = generator._generate_performance_section(metrics)

        # Should handle division by zero gracefully
        assert "Performance Metrics" in section
        assert "0" in section
