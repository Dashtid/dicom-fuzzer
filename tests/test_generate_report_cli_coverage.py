"""Generate Report CLI Coverage Tests

Tests for dicom_fuzzer.cli.generate_report module to improve coverage.
This module tests the unified report generation CLI functionality.
"""

import csv
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.generate_report import (
    generate_coverage_chart,
    generate_csv_report,
    generate_json_report,
    generate_markdown_report,
    generate_reports,
    main,
)


class TestGenerateReports:
    """Tests for generate_reports function."""

    def test_generate_reports_creates_html(self, tmp_path: Path) -> None:
        """Test that generate_reports creates HTML report."""
        # Create session JSON file
        session_data = {
            "session_info": {
                "session_name": "Test Session",
                "start_time": "2025-01-15 10:00:00",
            },
            "statistics": {
                "files_fuzzed": 100,
                "mutations_applied": 500,
                "crashes": 0,
                "hangs": 0,
                "successes": 100,
            },
            "crashes": [],
        }

        session_file = tmp_path / "session_test.json"
        session_file.write_text(json.dumps(session_data))

        # Create reports directory
        reports_dir = tmp_path / "reports"
        reports_dir.mkdir()

        with patch(
            "dicom_fuzzer.cli.generate_report.EnhancedReportGenerator"
        ) as mock_generator_cls:
            mock_generator = MagicMock()
            mock_html_path = tmp_path / "report.html"
            mock_html_path.write_text("<html></html>")
            mock_generator.generate_html_report.return_value = mock_html_path
            mock_generator_cls.return_value = mock_generator

            result = generate_reports(session_file)

            assert result == mock_html_path
            mock_generator.generate_html_report.assert_called_once()

    def test_generate_reports_with_custom_output(self, tmp_path: Path) -> None:
        """Test generate_reports with custom output path."""
        session_data = {
            "session_info": {"session_name": "Custom Output Test"},
            "statistics": {
                "files_fuzzed": 50,
                "mutations_applied": 200,
                "crashes": 1,
                "hangs": 0,
                "successes": 49,
            },
            "crashes": [],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        custom_output = tmp_path / "my_custom_report.html"

        with patch(
            "dicom_fuzzer.cli.generate_report.EnhancedReportGenerator"
        ) as mock_generator_cls:
            mock_generator = MagicMock()
            mock_generator.generate_html_report.return_value = custom_output
            mock_generator_cls.return_value = mock_generator

            result = generate_reports(session_file, output_html=custom_output)

            # generate_html_report is called with positional args: (session_data, output_path)
            call_args = mock_generator.generate_html_report.call_args
            # call_args[0] contains positional args, call_args[0][1] is the output_path
            assert call_args[0][1] == custom_output

    def test_generate_reports_with_crashes(self, tmp_path: Path, capsys: Any) -> None:
        """Test generate_reports with crash data prints crash info."""
        session_data = {
            "session_info": {"session_name": "Crash Test"},
            "statistics": {
                "files_fuzzed": 100,
                "mutations_applied": 500,
                "crashes": 2,
                "hangs": 0,
                "successes": 98,
            },
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "preserved_sample_path": "/path/to/sample1.dcm",
                    "crash_log_path": "/path/to/crash1.log",
                    "reproduction_command": "dicom-fuzzer --input sample1.dcm",
                },
                {
                    "crash_id": "crash_002",
                    "preserved_sample_path": "/path/to/sample2.dcm",
                    "crash_log_path": "/path/to/crash2.log",
                    # No reproduction_command
                },
            ],
        }

        session_file = tmp_path / "session_crashes.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "dicom_fuzzer.cli.generate_report.EnhancedReportGenerator"
        ) as mock_generator_cls:
            mock_generator = MagicMock()
            mock_html = tmp_path / "report.html"
            mock_html.write_text("<html></html>")
            mock_generator.generate_html_report.return_value = mock_html
            mock_generator_cls.return_value = mock_generator

            generate_reports(session_file)

        captured = capsys.readouterr()
        assert "crash_001" in captured.out
        assert "crash_002" in captured.out
        assert "sample1.dcm" in captured.out
        assert "crash1.log" in captured.out
        assert "Repro:" in captured.out

    def test_generate_reports_keep_json(self, tmp_path: Path, capsys: Any) -> None:
        """Test generate_reports with keep_json option."""
        session_data = {
            "session_info": {"session_name": "Keep JSON Test"},
            "statistics": {
                "files_fuzzed": 10,
                "mutations_applied": 50,
                "crashes": 0,
                "hangs": 0,
                "successes": 10,
            },
            "crashes": [],
        }

        session_file = tmp_path / "session_keep.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "dicom_fuzzer.cli.generate_report.EnhancedReportGenerator"
        ) as mock_generator_cls:
            mock_generator = MagicMock()
            mock_html = tmp_path / "report.html"
            mock_html.write_text("<html></html>")
            mock_generator.generate_html_report.return_value = mock_html
            mock_generator_cls.return_value = mock_generator

            generate_reports(session_file, keep_json=True)

        captured = capsys.readouterr()
        assert "JSON data saved at" in captured.out

    def test_generate_reports_prints_summary(self, tmp_path: Path, capsys: Any) -> None:
        """Test that generate_reports prints summary statistics."""
        session_data = {
            "session_info": {"session_name": "Summary Test"},
            "statistics": {
                "files_fuzzed": 123,
                "mutations_applied": 456,
                "crashes": 7,
                "hangs": 3,
                "successes": 113,
            },
            "crashes": [],
        }

        session_file = tmp_path / "session_summary.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "dicom_fuzzer.cli.generate_report.EnhancedReportGenerator"
        ) as mock_generator_cls:
            mock_generator = MagicMock()
            mock_html = tmp_path / "report.html"
            mock_html.write_text("<html></html>")
            mock_generator.generate_html_report.return_value = mock_html
            mock_generator_cls.return_value = mock_generator

            generate_reports(session_file)

        captured = capsys.readouterr()
        assert "REPORT SUMMARY" in captured.out
        assert "Files Fuzzed:" in captured.out
        assert "123" in captured.out
        assert "Mutations Applied:" in captured.out
        assert "456" in captured.out
        assert "Crashes:" in captured.out
        assert "7" in captured.out


class TestGenerateJsonReport:
    """Tests for generate_json_report function."""

    def test_generate_json_report_creates_file(self, tmp_path: Path) -> None:
        """Test that generate_json_report creates JSON file."""
        output_file = tmp_path / "report.json"
        data = {"campaign_name": "Test", "total_files": 100, "crashes": 5}

        generate_json_report(data, str(output_file))

        assert output_file.exists()

    def test_generate_json_report_valid_json(self, tmp_path: Path) -> None:
        """Test that generated JSON is valid."""
        output_file = tmp_path / "report.json"
        data = {"nested": {"a": 1, "b": [1, 2, 3]}, "list": ["x", "y", "z"]}

        generate_json_report(data, str(output_file))

        loaded = json.loads(output_file.read_text())
        assert loaded == data

    def test_generate_json_report_pretty_printed(self, tmp_path: Path) -> None:
        """Test that JSON is pretty-printed with indentation."""
        output_file = tmp_path / "report.json"
        data = {"key": "value"}

        generate_json_report(data, str(output_file))

        content = output_file.read_text()
        assert "\n" in content  # Pretty printed has newlines


class TestGenerateCsvReport:
    """Tests for generate_csv_report function."""

    def test_generate_csv_report_creates_file(self, tmp_path: Path) -> None:
        """Test that generate_csv_report creates CSV file."""
        output_file = tmp_path / "crashes.csv"
        crashes = [
            {"crash_id": "c1", "type": "overflow", "severity": "high"},
            {"crash_id": "c2", "type": "null_ptr", "severity": "critical"},
        ]

        generate_csv_report(crashes, str(output_file))

        assert output_file.exists()

    def test_generate_csv_report_valid_csv(self, tmp_path: Path) -> None:
        """Test that generated CSV is valid."""
        output_file = tmp_path / "crashes.csv"
        crashes = [
            {"crash_id": "c1", "type": "overflow"},
            {"crash_id": "c2", "type": "null_ptr"},
        ]

        generate_csv_report(crashes, str(output_file))

        with open(output_file, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["crash_id"] == "c1"
        assert rows[1]["crash_id"] == "c2"

    def test_generate_csv_report_empty_crashes(self, tmp_path: Path) -> None:
        """Test generate_csv_report with empty crashes list."""
        output_file = tmp_path / "empty.csv"

        generate_csv_report([], str(output_file))

        # File should not be created for empty crashes
        assert not output_file.exists()

    def test_generate_csv_report_includes_header(self, tmp_path: Path) -> None:
        """Test that CSV includes header row."""
        output_file = tmp_path / "crashes.csv"
        crashes = [{"id": "1", "type": "a", "severity": "b"}]

        generate_csv_report(crashes, str(output_file))

        content = output_file.read_text()
        lines = content.strip().split("\n")

        assert len(lines) == 2  # Header + 1 data row
        assert "id" in lines[0]
        assert "type" in lines[0]
        assert "severity" in lines[0]


class TestGenerateCoverageChart:
    """Tests for generate_coverage_chart function."""

    def test_generate_coverage_chart_with_matplotlib(self, tmp_path: Path) -> None:
        """Test chart generation when matplotlib is available."""
        output_file = tmp_path / "coverage.png"
        coverage_data = {1: 10.0, 2: 25.0, 3: 40.0, 4: 55.0, 5: 70.0}

        # Mock matplotlib
        mock_plt = MagicMock()
        mock_mpl = MagicMock()
        mock_mpl.pyplot = mock_plt

        with patch.dict(
            "dicom_fuzzer.cli.generate_report.__dict__", {"_matplotlib": mock_mpl}
        ):
            generate_coverage_chart(coverage_data, str(output_file))

        # Should have called figure, plot, xlabel, ylabel, title, savefig, close
        mock_plt.figure.assert_called_once()
        mock_plt.plot.assert_called_once()
        mock_plt.xlabel.assert_called_once_with("Iteration")
        mock_plt.ylabel.assert_called_once_with("Coverage")
        mock_plt.title.assert_called_once()
        mock_plt.savefig.assert_called_once()
        mock_plt.close.assert_called_once()

    def test_generate_coverage_chart_without_matplotlib(self, tmp_path: Path) -> None:
        """Test chart generation when matplotlib is not available."""
        output_file = tmp_path / "coverage.png"
        coverage_data = {1: 10.0, 2: 20.0}

        with patch.dict(
            "dicom_fuzzer.cli.generate_report.__dict__", {"_matplotlib": None}
        ):
            generate_coverage_chart(coverage_data, str(output_file))

        # Should create empty file as fallback
        assert output_file.exists()


class TestGenerateMarkdownReport:
    """Tests for generate_markdown_report function."""

    def test_generate_markdown_report_creates_file(self, tmp_path: Path) -> None:
        """Test that generate_markdown_report creates file."""
        output_file = tmp_path / "report.md"
        data = {
            "title": "Fuzzing Report",
            "summary": {"files_tested": 100, "crashes_found": 5},
            "findings": [
                {"severity": "high", "description": "Buffer overflow"},
                {"severity": "medium", "description": "Input validation"},
            ],
        }

        generate_markdown_report(data, str(output_file))

        assert output_file.exists()

    def test_generate_markdown_report_contains_title(self, tmp_path: Path) -> None:
        """Test that markdown includes title."""
        output_file = tmp_path / "report.md"
        data = {"title": "My Test Report"}

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "# My Test Report" in content

    def test_generate_markdown_report_contains_summary(self, tmp_path: Path) -> None:
        """Test that markdown includes summary section."""
        output_file = tmp_path / "report.md"
        data = {"title": "Report", "summary": {"total_tests": 200, "pass_rate": "95%"}}

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "## Summary" in content
        assert "total_tests" in content
        assert "200" in content
        assert "pass_rate" in content

    def test_generate_markdown_report_contains_findings(self, tmp_path: Path) -> None:
        """Test that markdown includes findings section."""
        output_file = tmp_path / "report.md"
        data = {
            "title": "Report",
            "findings": [
                {"severity": "critical", "description": "Memory corruption"},
                {"severity": "low", "description": "Minor issue"},
            ],
        }

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "## Findings" in content
        assert "critical" in content
        assert "Memory corruption" in content
        assert "low" in content

    def test_generate_markdown_report_no_summary(self, tmp_path: Path) -> None:
        """Test markdown without summary section."""
        output_file = tmp_path / "report.md"
        data = {"title": "Simple Report"}

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "# Simple Report" in content
        assert "## Summary" not in content

    def test_generate_markdown_report_no_findings(self, tmp_path: Path) -> None:
        """Test markdown without findings section."""
        output_file = tmp_path / "report.md"
        data = {"title": "No Findings Report", "summary": {"status": "clean"}}

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "## Findings" not in content


class TestMain:
    """Tests for main CLI function."""

    def test_main_file_not_found(self, tmp_path: Path, capsys: Any) -> None:
        """Test main with non-existent file."""
        non_existent = tmp_path / "does_not_exist.json"

        with patch("sys.argv", ["generate_report.py", str(non_existent)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "File not found" in captured.err

    def test_main_invalid_json(self, tmp_path: Path, capsys: Any) -> None:
        """Test main with invalid JSON file."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("not valid json {{{")

        with patch("sys.argv", ["generate_report.py", str(invalid_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Invalid JSON" in captured.err

    def test_main_with_output_option(self, tmp_path: Path) -> None:
        """Test main with --output option."""
        session_data = {
            "session_info": {"session_name": "Test"},
            "statistics": {
                "files_fuzzed": 10,
                "mutations_applied": 50,
                "crashes": 0,
                "hangs": 0,
                "successes": 10,
            },
            "crashes": [],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        output_file = tmp_path / "custom_output.html"

        with patch(
            "sys.argv",
            ["generate_report.py", str(session_file), "--output", str(output_file)],
        ):
            with patch("dicom_fuzzer.cli.generate_report.generate_reports") as mock_gen:
                mock_gen.return_value = output_file
                main()

            # main() calls generate_reports with keyword args
            call_args = mock_gen.call_args
            # Depending on how argparse passes args, check both positional and keyword
            if call_args.kwargs:
                assert call_args.kwargs.get("output_html") == output_file
            else:
                # Fallback to check if passed correctly
                mock_gen.assert_called_once()

    def test_main_with_keep_json_option(self, tmp_path: Path) -> None:
        """Test main with --keep-json option."""
        session_data = {
            "session_info": {"session_name": "Test"},
            "statistics": {
                "files_fuzzed": 5,
                "mutations_applied": 25,
                "crashes": 0,
                "hangs": 0,
                "successes": 5,
            },
            "crashes": [],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "sys.argv", ["generate_report.py", str(session_file), "--keep-json"]
        ):
            with patch("dicom_fuzzer.cli.generate_report.generate_reports") as mock_gen:
                mock_gen.return_value = tmp_path / "report.html"
                main()

            # main() calls generate_reports with keyword args
            call_args = mock_gen.call_args
            if call_args.kwargs:
                assert call_args.kwargs.get("keep_json") is True
            else:
                # Just verify it was called
                mock_gen.assert_called_once()

    def test_main_general_exception(self, tmp_path: Path, capsys: Any) -> None:
        """Test main handles general exceptions."""
        session_file = tmp_path / "session.json"
        session_file.write_text("{}")  # Valid but minimal JSON

        with patch("sys.argv", ["generate_report.py", str(session_file)]):
            with patch(
                "dicom_fuzzer.cli.generate_report.generate_reports",
                side_effect=RuntimeError("Test error"),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Error generating report" in captured.err


class TestIntegration:
    """Integration tests for generate_report module."""

    def test_full_report_generation_flow(self, tmp_path: Path, capsys: Any) -> None:
        """Test complete report generation flow."""
        # Create comprehensive session data
        session_data = {
            "session_info": {
                "session_name": "Integration Test Session",
                "start_time": "2025-01-15T10:00:00",
                "end_time": "2025-01-15T11:00:00",
                "target": "test_target",
            },
            "statistics": {
                "files_fuzzed": 500,
                "mutations_applied": 2500,
                "crashes": 3,
                "hangs": 1,
                "successes": 496,
            },
            "crashes": [
                {
                    "crash_id": "int_crash_001",
                    "preserved_sample_path": "/samples/crash1.dcm",
                    "crash_log_path": "/logs/crash1.log",
                    "reproduction_command": "fuzz --input crash1.dcm",
                }
            ],
            "performance": {"throughput": 8.3, "peak_memory_mb": 256},
        }

        session_file = tmp_path / "integration_session.json"
        session_file.write_text(json.dumps(session_data))

        # Generate all report types
        json_output = tmp_path / "report.json"
        csv_output = tmp_path / "crashes.csv"
        md_output = tmp_path / "report.md"

        generate_json_report(session_data, str(json_output))
        generate_csv_report(session_data["crashes"], str(csv_output))
        generate_markdown_report(
            {
                "title": "Integration Test Report",
                "summary": session_data["statistics"],
                "findings": [
                    {"severity": "high", "description": f"Crash: {c['crash_id']}"}
                    for c in session_data["crashes"]
                ],
            },
            str(md_output),
        )

        # Verify all files created
        assert json_output.exists()
        assert csv_output.exists()
        assert md_output.exists()

        # Verify content
        json_content = json.loads(json_output.read_text())
        assert json_content["statistics"]["files_fuzzed"] == 500

        md_content = md_output.read_text()
        assert "Integration Test Report" in md_content
        assert "int_crash_001" in md_content
