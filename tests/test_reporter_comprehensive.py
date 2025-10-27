"""Comprehensive tests for dicom_fuzzer.core.reporter module.

This test suite provides thorough coverage of report generation functionality,
including HTML and JSON report creation.
"""

import json
from datetime import datetime

from dicom_fuzzer.core.crash_analyzer import (
    CrashAnalyzer,
    CrashReport,
    CrashSeverity,
    CrashType,
)
from dicom_fuzzer.core.reporter import ReportGenerator


class TestReportGeneratorInitialization:
    """Test suite for ReportGenerator initialization."""

    def test_initialization_default_dir(self, tmp_path):
        """Test ReportGenerator with default directory."""
        output_dir = tmp_path / "reports"
        generator = ReportGenerator(output_dir=str(output_dir))

        assert generator.output_dir == output_dir
        assert generator.output_dir.exists()

    def test_initialization_creates_directory(self, tmp_path):
        """Test that output directory is created."""
        output_dir = tmp_path / "custom_reports"
        ReportGenerator(output_dir=str(output_dir))

        assert output_dir.exists()
        assert output_dir.is_dir()


class TestHTMLReportGeneration:
    """Test suite for HTML report generation."""

    def test_generate_crash_html_report(self, tmp_path):
        """Test generating HTML crash report."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Add a crash
        crash = CrashReport(
            crash_id="test_001",
            timestamp=datetime.now(),
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.CRITICAL,
            test_case_path="/test/file.dcm",
            stack_trace="Stack trace here",
            exception_message="Segfault occurred",
            crash_hash="abc123def456",
            additional_info={"exception_type": "SegmentationFault"},
        )
        analyzer.crashes.append(crash)

        report_path = generator.generate_crash_html_report(analyzer, "Test Campaign")

        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert "crash_report_" in report_path.name

    def test_html_report_contains_title(self, tmp_path):
        """Test HTML report contains campaign title."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        report_path = generator.generate_crash_html_report(analyzer, "My Test Campaign")

        content = report_path.read_text(encoding="utf-8")
        assert "My Test Campaign" in content

    def test_html_report_contains_crash_details(self, tmp_path):
        """Test HTML report contains crash details."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        crash = CrashReport(
            crash_id="test_002",
            timestamp=datetime.now(),
            crash_type=CrashType.ASSERTION_FAILURE,
            severity=CrashSeverity.HIGH,
            test_case_path="/test/crash_file.dcm",
            stack_trace="Assertion failed in module X",
            exception_message="Assert failed",
            crash_hash="hash123",
            additional_info={"exception_type": "AssertionError"},
        )
        analyzer.crashes.append(crash)

        report_path = generator.generate_crash_html_report(analyzer)
        content = report_path.read_text(encoding="utf-8")

        assert "crash_file.dcm" in content
        assert "Assert failed" in content

    def test_html_report_no_crashes(self, tmp_path):
        """Test HTML report with no crashes."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        report_path = generator.generate_crash_html_report(analyzer)
        content = report_path.read_text(encoding="utf-8")

        assert "No crashes found" in content or "0" in content


class TestJSONReportGeneration:
    """Test suite for JSON report generation."""

    def test_generate_crash_json_report(self, tmp_path):
        """Test generating JSON crash report."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        crash = CrashReport(
            crash_id="test_003",
            timestamp=datetime.now(),
            crash_type=CrashType.TIMEOUT,
            severity=CrashSeverity.MEDIUM,
            test_case_path="/test/timeout.dcm",
            stack_trace="",
            exception_message="Timeout after 5s",
            crash_hash="timeout_hash",
            additional_info={},
        )
        analyzer.crashes.append(crash)

        report_path = generator.generate_crash_json_report(analyzer, "Test Campaign")

        assert report_path.exists()
        assert report_path.suffix == ".json"
        assert "crash_report_" in report_path.name

    def test_json_report_structure(self, tmp_path):
        """Test JSON report has correct structure."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        crash = CrashReport(
            crash_id="test_004",
            timestamp=datetime.now(),
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.CRITICAL,
            test_case_path="/test/mem.dcm",
            stack_trace="Memory corruption",
            exception_message="Out of bounds",
            crash_hash="mem_hash",
            additional_info={"exception_type": "MemoryError"},
        )
        analyzer.crashes.append(crash)

        report_path = generator.generate_crash_json_report(analyzer)

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        assert "campaign_name" in data
        assert "generated_at" in data
        assert "summary" in data
        assert "crashes" in data

    def test_json_report_summary_counts(self, tmp_path):
        """Test JSON report summary has correct counts."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        for i in range(3):
            crash = CrashReport(
                crash_id=f"test_{i}",
                timestamp=datetime.now(),
                crash_type=CrashType.SEGFAULT,
                severity=CrashSeverity.HIGH,
                test_case_path=f"/test/crash{i}.dcm",
                stack_trace="",
                exception_message="Crash",
                crash_hash=f"hash{i}",
                additional_info={},
            )
            analyzer.crashes.append(crash)

        report_path = generator.generate_crash_json_report(analyzer)

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["summary"]["total_crashes"] == 3
        assert len(data["crashes"]) == 3

    def test_json_report_crash_details(self, tmp_path):
        """Test JSON report contains crash details."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        crash = CrashReport(
            crash_id="test_005",
            timestamp=datetime(2025, 1, 1, 12, 0, 0),
            crash_type=CrashType.UNCAUGHT_EXCEPTION,
            severity=CrashSeverity.LOW,
            test_case_path="/test/exception.dcm",
            stack_trace="Exception trace",
            exception_message="Test exception",
            crash_hash="exception_hash",
            additional_info={"exception_type": "ValueError", "extra": "data"},
        )
        analyzer.crashes.append(crash)

        report_path = generator.generate_crash_json_report(analyzer)

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        crash_data = data["crashes"][0]
        assert crash_data["test_case_path"] == "/test/exception.dcm"
        assert crash_data["exception_message"] == "Test exception"
        assert crash_data["crash_hash"] == "exception_hash"
        assert crash_data["exception_type"] == "ValueError"


class TestPerformanceReportGeneration:
    """Test suite for performance report generation."""

    def test_generate_performance_html_report(self, tmp_path):
        """Test generating performance HTML report."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 100,
            "mutations_applied": 500,
            "throughput_per_second": 10.5,
            "avg_time_per_file": 0.095,
            "peak_memory_mb": 256.7,
            "avg_cpu_percent": 45.2,
        }

        report_path = generator.generate_performance_html_report(
            metrics, "Performance Test"
        )

        assert report_path.exists()
        assert report_path.suffix == ".html"
        assert "performance_report_" in report_path.name

    def test_performance_report_contains_metrics(self, tmp_path):
        """Test performance report contains metrics."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 150,
            "mutations_applied": 750,
            "throughput_per_second": 15.3,
            "avg_time_per_file": 0.065,
            "peak_memory_mb": 312.5,
            "avg_cpu_percent": 67.8,
        }

        report_path = generator.generate_performance_html_report(metrics)
        content = report_path.read_text(encoding="utf-8")

        assert "150" in content  # files_generated
        assert "750" in content  # mutations_applied
        assert "15.3" in content or "15.30" in content  # throughput

    def test_performance_report_with_strategy_usage(self, tmp_path):
        """Test performance report with strategy usage."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 100,
            "mutations_applied": 500,
            "throughput_per_second": 10.0,
            "avg_time_per_file": 0.1,
            "peak_memory_mb": 200.0,
            "avg_cpu_percent": 50.0,
            "strategy_usage": {
                "bit_flip": 200,
                "byte_swap": 150,
                "random": 150,
            },
        }

        report_path = generator.generate_performance_html_report(metrics)
        content = report_path.read_text(encoding="utf-8")

        assert "bit_flip" in content
        assert "byte_swap" in content
        assert "200" in content


class TestHelperMethods:
    """Test suite for helper methods."""

    def test_crash_to_dict(self, tmp_path):
        """Test crash to dictionary conversion."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        crash = CrashReport(
            crash_id="test_006",
            timestamp=datetime(2025, 1, 1, 12, 0, 0),
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.CRITICAL,
            test_case_path="/test/crash.dcm",
            stack_trace="Stack trace",
            exception_message="Segfault",
            crash_hash="crash_hash_123",
            additional_info={"exception_type": "SegFault", "extra": "info"},
        )

        crash_dict = generator._crash_to_dict(crash)

        assert crash_dict["crash_type"] == "segmentation_fault"
        assert crash_dict["severity"] == "critical"
        assert crash_dict["test_case_path"] == "/test/crash.dcm"
        assert crash_dict["crash_hash"] == "crash_hash_123"
        assert crash_dict["exception_type"] == "SegFault"

    def test_generate_html_header(self, tmp_path):
        """Test HTML header generation."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        header = generator._generate_html_header("Test Title")

        assert "<!DOCTYPE html>" in header
        assert "Test Title" in header
        assert "<style>" in header
        assert "body" in header

    def test_generate_html_footer(self, tmp_path):
        """Test HTML footer generation."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        footer = generator._generate_html_footer()

        assert "</div>" in footer
        assert "</body>" in footer
        assert "</html>" in footer

    def test_generate_summary_section(self, tmp_path):
        """Test summary section generation."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        summary = {"segmentation_fault": 5, "timeout": 3, "exception": 2}
        html = generator._generate_summary_section(summary, 10)

        assert "Total Crashes" in html
        assert "10" in html
        assert "Segmentation Fault" in html or "segmentation fault" in html.lower()

    def test_generate_crash_details_section_empty(self, tmp_path):
        """Test crash details section with no crashes."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        html = generator._generate_crash_details_section([])

        assert "No crashes found" in html

    def test_generate_crash_details_section_with_crashes(self, tmp_path):
        """Test crash details section with crashes."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        crash = CrashReport(
            crash_id="test_007",
            timestamp=datetime.now(),
            crash_type=CrashType.SEGFAULT,
            severity=CrashSeverity.HIGH,
            test_case_path="/test/seg.dcm",
            stack_trace="Stack here",
            exception_message="Segfault message",
            crash_hash="seg_hash",
            additional_info={"exception_type": "SegFault"},
        )

        html = generator._generate_crash_details_section([crash])

        assert "seg.dcm" in html
        assert "Segfault message" in html
        assert "high" in html.lower()

    def test_generate_performance_section(self, tmp_path):
        """Test performance section generation."""
        generator = ReportGenerator(output_dir=str(tmp_path))

        metrics = {
            "files_generated": 50,
            "mutations_applied": 250,
            "throughput_per_second": 5.5,
            "avg_time_per_file": 0.18,
            "peak_memory_mb": 128.5,
            "avg_cpu_percent": 32.1,
        }

        html = generator._generate_performance_section(metrics)

        assert "Performance Metrics" in html
        assert "50" in html
        assert "250" in html


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    def test_complete_report_generation_workflow(self, tmp_path):
        """Test complete report generation workflow."""
        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Add multiple crashes
        for i in range(5):
            crash = CrashReport(
                crash_id=f"crash_{i}",
                timestamp=datetime.now(),
                crash_type=CrashType.SEGFAULT if i % 2 == 0 else CrashType.TIMEOUT,
                severity=CrashSeverity.HIGH if i < 3 else CrashSeverity.MEDIUM,
                test_case_path=f"/test/file{i}.dcm",
                stack_trace=f"Stack trace {i}",
                exception_message=f"Error {i}",
                crash_hash=f"hash{i}",
                additional_info={"exception_type": f"Type{i}"},
            )
            analyzer.crashes.append(crash)

        # Generate both reports
        html_path = generator.generate_crash_html_report(analyzer, "Integration Test")
        json_path = generator.generate_crash_json_report(analyzer, "Integration Test")

        assert html_path.exists()
        assert json_path.exists()

        # Verify both contain crash data
        html_content = html_path.read_text(encoding="utf-8")
        with open(json_path, encoding="utf-8") as f:
            json_data = json.load(f)

        assert "Integration Test" in html_content
        assert json_data["campaign_name"] == "Integration Test"
        assert json_data["summary"]["total_crashes"] == 5

    def test_multiple_report_generations(self, tmp_path):
        """Test generating multiple reports."""
        import time

        generator = ReportGenerator(output_dir=str(tmp_path))
        analyzer = CrashAnalyzer(crash_dir=str(tmp_path))

        # Generate three reports with small delay to avoid timestamp collision
        paths = []
        for i in range(3):
            path = generator.generate_crash_html_report(analyzer, f"Campaign {i}")
            paths.append(path)
            if i < 2:  # Don't sleep after last iteration
                time.sleep(1.1)  # Sleep > 1 second to ensure different timestamps

        # All should exist and be unique
        assert len(set(paths)) == 3
        for path in paths:
            assert path.exists()
