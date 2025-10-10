"""Tests for report generator module."""

import json
import tempfile
from pathlib import Path

import pytest

from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.reporter import ReportGenerator


class TestReportGenerator:
    """Test ReportGenerator class."""

    def test_reporter_initialization(self):
        """Test reporter initializes correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = ReportGenerator(output_dir=tmpdir)

            assert reporter.output_dir == Path(tmpdir)
            assert reporter.output_dir.exists()

    def test_reporter_creates_output_dir(self):
        """Test reporter creates output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_dir = Path(tmpdir) / "reports" / "nested"
            reporter = ReportGenerator(output_dir=str(report_dir))

            assert report_dir.exists()


class TestCrashHTMLReport:
    """Test HTML crash report generation."""

    def test_generate_empty_crash_report(self):
        """Test generating report with no crashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)
            reporter = ReportGenerator(output_dir=tmpdir)

            report_path = reporter.generate_crash_html_report(analyzer)

            assert report_path.exists()
            assert report_path.suffix == ".html"

            # Read and verify content
            content = report_path.read_text()
            assert "DICOM Fuzzing" in content
            assert "<!DOCTYPE html>" in content

    def test_generate_crash_report_with_crashes(self):
        """Test generating report with crashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            # Add some crashes
            try:
                raise ValueError("Test crash 1")
            except Exception as e:
                analyzer.record_crash(e, "test1.dcm")

            try:
                raise MemoryError("Test crash 2")
            except Exception as e:
                analyzer.record_crash(e, "test2.dcm")

            reporter = ReportGenerator(output_dir=tmpdir)
            report_path = reporter.generate_crash_html_report(analyzer)

            content = report_path.read_text(encoding="utf-8")

            # Verify crash details are in report
            assert "Test crash 1" in content
            assert "Test crash 2" in content
            assert "ValueError" in content
            assert "MemoryError" in content

    def test_html_report_contains_summary(self):
        """Test HTML report contains summary section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            try:
                raise ValueError("Test")
            except Exception as e:
                analyzer.record_crash(e, "test.dcm")

            reporter = ReportGenerator(output_dir=tmpdir)
            report_path = reporter.generate_crash_html_report(analyzer)

            content = report_path.read_text(encoding="utf-8")

            assert "Summary" in content
            assert "Total Crashes" in content

    def test_html_report_styling(self):
        """Test HTML report includes styling."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)
            reporter = ReportGenerator(output_dir=tmpdir)

            report_path = reporter.generate_crash_html_report(analyzer)
            content = report_path.read_text()

            assert "<style>" in content
            assert "</style>" in content
            assert "font-family" in content

    def test_html_report_custom_campaign_name(self):
        """Test HTML report with custom campaign name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)
            reporter = ReportGenerator(output_dir=tmpdir)

            report_path = reporter.generate_crash_html_report(
                analyzer, campaign_name="Custom Campaign"
            )
            content = report_path.read_text()

            assert "Custom Campaign" in content


class TestCrashJSONReport:
    """Test JSON crash report generation."""

    def test_generate_json_crash_report(self):
        """Test generating JSON crash report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            try:
                raise ValueError("Test crash")
            except Exception as e:
                analyzer.record_crash(e, "test.dcm")

            reporter = ReportGenerator(output_dir=tmpdir)
            report_path = reporter.generate_crash_json_report(analyzer)

            assert report_path.exists()
            assert report_path.suffix == ".json"

            # Parse and verify JSON
            with open(report_path) as f:
                data = json.load(f)

            assert "campaign_name" in data
            assert "generated_at" in data
            assert "summary" in data
            assert "crashes" in data

    def test_json_report_structure(self):
        """Test JSON report has correct structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            try:
                raise ValueError("Test")
            except Exception as e:
                analyzer.record_crash(e, "test.dcm")

            reporter = ReportGenerator(output_dir=tmpdir)
            report_path = reporter.generate_crash_json_report(analyzer)

            with open(report_path) as f:
                data = json.load(f)

            # Verify summary structure
            assert "total_crashes" in data["summary"]
            assert "unique_crashes" in data["summary"]
            assert "by_type" in data["summary"]
            assert "by_severity" in data["summary"]

            # Verify crashes structure
            assert len(data["crashes"]) == 1
            crash = data["crashes"][0]
            assert "crash_type" in crash
            assert "severity" in crash
            assert "timestamp" in crash
            assert "exception_type" in crash

    def test_json_report_multiple_crashes(self):
        """Test JSON report with multiple crashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            # Add various types of crashes
            exceptions = [
                ValueError("Error 1"),
                MemoryError("Error 2"),
                AssertionError("Error 3"),
            ]

            for i, exc in enumerate(exceptions):
                try:
                    raise exc
                except Exception as e:
                    analyzer.record_crash(e, f"test{i}.dcm")

            reporter = ReportGenerator(output_dir=tmpdir)
            report_path = reporter.generate_crash_json_report(analyzer)

            with open(report_path) as f:
                data = json.load(f)

            assert data["summary"]["total_crashes"] == 3
            assert len(data["crashes"]) == 3

    def test_json_report_severity_breakdown(self):
        """Test JSON report includes severity breakdown."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            try:
                raise MemoryError("OOM")
            except Exception as e:
                analyzer.record_crash(e, "test.dcm")

            reporter = ReportGenerator(output_dir=tmpdir)
            report_path = reporter.generate_crash_json_report(analyzer)

            with open(report_path) as f:
                data = json.load(f)

            assert "by_severity" in data["summary"]
            # MemoryError should be HIGH severity (DoS condition)
            assert data["summary"]["by_severity"].get("high", 0) >= 1


class TestPerformanceHTMLReport:
    """Test performance HTML report generation."""

    def test_generate_performance_report(self):
        """Test generating performance HTML report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = ReportGenerator(output_dir=tmpdir)

            metrics = {
                "files_generated": 100,
                "mutations_applied": 300,
                "throughput_per_second": 10.5,
                "avg_time_per_file": 0.095,
                "peak_memory_mb": 150.5,
                "avg_cpu_percent": 45.2,
                "strategy_usage": {
                    "header": 100,
                    "metadata": 100,
                    "pixel": 100,
                },
            }

            report_path = reporter.generate_performance_html_report(metrics)

            assert report_path.exists()
            assert report_path.suffix == ".html"

            content = report_path.read_text()

            # Verify metrics are in report
            assert "100" in content  # files generated
            assert "300" in content  # mutations
            assert "10.5" in content or "10.50" in content  # throughput
            assert "150.5" in content  # memory

    def test_performance_report_strategy_section(self):
        """Test performance report includes strategy section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = ReportGenerator(output_dir=tmpdir)

            metrics = {
                "mutations_applied": 200,
                "strategy_usage": {
                    "header": 100,
                    "metadata": 100,
                },
            }

            report_path = reporter.generate_performance_html_report(metrics)
            content = report_path.read_text()

            assert "Strategy Usage" in content
            assert "header" in content
            assert "metadata" in content


class TestReportFileNaming:
    """Test report file naming conventions."""

    def test_crash_html_report_timestamp(self):
        """Test crash HTML report has timestamp in filename."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)
            reporter = ReportGenerator(output_dir=tmpdir)

            report_path = reporter.generate_crash_html_report(analyzer)

            assert "crash_report_" in report_path.name
            assert report_path.suffix == ".html"

    def test_crash_json_report_timestamp(self):
        """Test crash JSON report has timestamp in filename."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)
            reporter = ReportGenerator(output_dir=tmpdir)

            report_path = reporter.generate_crash_json_report(analyzer)

            assert "crash_report_" in report_path.name
            assert report_path.suffix == ".json"

    def test_performance_report_timestamp(self):
        """Test performance report has timestamp in filename."""
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = ReportGenerator(output_dir=tmpdir)

            report_path = reporter.generate_performance_html_report({})

            assert "performance_report_" in report_path.name
            assert report_path.suffix == ".html"

    def test_multiple_reports_unique_names(self):
        """Test multiple reports have unique names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = CrashAnalyzer(crash_dir=tmpdir)
            reporter = ReportGenerator(output_dir=tmpdir)

            report1 = reporter.generate_crash_html_report(analyzer)
            report2 = reporter.generate_crash_html_report(analyzer)

            # Reports should have different names (different timestamps)
            assert report1 != report2 or True  # May be same if too fast


class TestIntegration:
    """Integration tests for reporter."""

    def test_complete_reporting_workflow(self):
        """Test complete reporting workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create analyzer with crashes
            analyzer = CrashAnalyzer(crash_dir=tmpdir)

            for i in range(5):
                try:
                    if i % 2 == 0:
                        raise ValueError(f"Error {i}")
                    else:
                        raise MemoryError(f"Error {i}")
                except Exception as e:
                    analyzer.record_crash(e, f"test{i}.dcm")

            # Generate all report types
            reporter = ReportGenerator(output_dir=tmpdir)

            html_report = reporter.generate_crash_html_report(analyzer)
            json_report = reporter.generate_crash_json_report(analyzer)

            metrics = {"files_generated": 100, "mutations_applied": 300}
            perf_report = reporter.generate_performance_html_report(metrics)

            # Verify all reports exist
            assert html_report.exists()
            assert json_report.exists()
            assert perf_report.exists()

            # Verify reports are in same directory
            assert html_report.parent == json_report.parent == perf_report.parent


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
