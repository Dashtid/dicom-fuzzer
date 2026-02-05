"""Test Generate Report Module

This test suite verifies the report generation functionality for
DICOM fuzzing campaigns including HTML, JSON, CSV, and Markdown reports.
"""

import csv
import json
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.commands.reports import (
    _matplotlib,
    generate_coverage_chart,
    generate_csv_report,
    generate_json_report,
    generate_markdown_report,
    generate_reports,
    main,
)


class TestGenerateReports:
    """Test the main generate_reports function."""

    def test_generate_reports_basic(self, tmp_path, capsys):
        """Test basic report generation from session data."""
        # Create session JSON file
        session_data = {
            "session_info": {"session_name": "test_session"},
            "statistics": {
                "files_fuzzed": 100,
                "mutations_applied": 500,
                "crashes": 0,
                "hangs": 0,
                "successes": 100,
            },
            "crashes": [],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "dicom_fuzzer.cli.commands.reports.EnhancedReportGenerator"
        ) as mock_reporter:
            mock_instance = MagicMock()
            mock_instance.generate_html_report.return_value = tmp_path / "report.html"
            mock_reporter.return_value = mock_instance

            result = generate_reports(session_file)

            assert result == tmp_path / "report.html"
            mock_instance.generate_html_report.assert_called_once()

        captured = capsys.readouterr()
        assert "Loading session data" in captured.out
        assert "Files Fuzzed" in captured.out
        assert "100" in captured.out

    def test_generate_reports_with_custom_output(self, tmp_path, capsys):
        """Test report generation with custom output path."""
        session_data = {
            "session_info": {},
            "statistics": {},
            "crashes": [],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        custom_output = tmp_path / "custom_report.html"

        with patch(
            "dicom_fuzzer.cli.commands.reports.EnhancedReportGenerator"
        ) as mock_reporter:
            mock_instance = MagicMock()
            mock_instance.generate_html_report.return_value = custom_output
            mock_reporter.return_value = mock_instance

            result = generate_reports(session_file, output_html=custom_output)

            assert result == custom_output
            mock_instance.generate_html_report.assert_called_once_with(
                session_data, custom_output
            )

    def test_generate_reports_with_keep_json(self, tmp_path, capsys):
        """Test report generation with keep_json flag."""
        session_data = {
            "session_info": {},
            "statistics": {},
            "crashes": [],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "dicom_fuzzer.cli.commands.reports.EnhancedReportGenerator"
        ) as mock_reporter:
            mock_instance = MagicMock()
            mock_instance.generate_html_report.return_value = tmp_path / "report.html"
            mock_reporter.return_value = mock_instance

            generate_reports(session_file, keep_json=True)

        captured = capsys.readouterr()
        assert "JSON data saved at" in captured.out

    def test_generate_reports_with_crashes(self, tmp_path, capsys):
        """Test report generation with crash data."""
        session_data = {
            "session_info": {},
            "statistics": {"crashes": 2},
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "preserved_sample_path": "/path/to/sample1.dcm",
                    "crash_log_path": "/path/to/log1.txt",
                    "reproduction_command": "python fuzz.py sample1.dcm",
                },
                {
                    "crash_id": "crash_002",
                    "preserved_sample_path": "/path/to/sample2.dcm",
                    "crash_log_path": "/path/to/log2.txt",
                },
            ],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "dicom_fuzzer.cli.commands.reports.EnhancedReportGenerator"
        ) as mock_reporter:
            mock_instance = MagicMock()
            mock_instance.generate_html_report.return_value = tmp_path / "report.html"
            mock_reporter.return_value = mock_instance

            generate_reports(session_file)

        captured = capsys.readouterr()
        assert "2 crash(es) detected" in captured.out
        assert "crash_001" in captured.out
        assert "crash_002" in captured.out
        assert "Repro:" in captured.out
        assert "python fuzz.py sample1.dcm" in captured.out


class TestMainFunction:
    """Test the main CLI entry point."""

    def test_main_with_valid_file(self, tmp_path):
        """Test main with valid session file."""
        session_data = {
            "session_info": {},
            "statistics": {},
            "crashes": [],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        with patch("sys.argv", ["generate_report.py", str(session_file)]):
            with patch(
                "dicom_fuzzer.cli.commands.reports.generate_reports"
            ) as mock_generate:
                mock_generate.return_value = tmp_path / "report.html"

                main()

                mock_generate.assert_called_once()
                call_args = mock_generate.call_args
                assert call_args.kwargs["session_json_path"] == session_file

    def test_main_with_custom_output(self, tmp_path):
        """Test main with custom output path."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps({"statistics": {}, "crashes": []}))

        custom_output = tmp_path / "custom.html"

        with patch(
            "sys.argv",
            ["generate_report.py", str(session_file), "--output", str(custom_output)],
        ):
            with patch(
                "dicom_fuzzer.cli.commands.reports.generate_reports"
            ) as mock_generate:
                mock_generate.return_value = custom_output

                main()

                call_args = mock_generate.call_args
                assert call_args.kwargs["output_html"] == custom_output

    def test_main_with_keep_json_flag(self, tmp_path):
        """Test main with --keep-json flag."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps({"statistics": {}, "crashes": []}))

        with patch(
            "sys.argv", ["generate_report.py", str(session_file), "--keep-json"]
        ):
            with patch(
                "dicom_fuzzer.cli.commands.reports.generate_reports"
            ) as mock_generate:
                mock_generate.return_value = tmp_path / "report.html"

                main()

                call_args = mock_generate.call_args
                assert call_args.kwargs["keep_json"] is True

    def test_main_with_short_flags(self, tmp_path):
        """Test main with short flag variants."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps({"statistics": {}, "crashes": []}))

        custom_output = tmp_path / "output.html"

        with patch(
            "sys.argv",
            [
                "generate_report.py",
                str(session_file),
                "-o",
                str(custom_output),
                "-k",
            ],
        ):
            with patch(
                "dicom_fuzzer.cli.commands.reports.generate_reports"
            ) as mock_generate:
                mock_generate.return_value = custom_output

                main()

                call_args = mock_generate.call_args
                assert call_args.kwargs["output_html"] == custom_output
                assert call_args.kwargs["keep_json"] is True

    def test_main_file_not_found(self, tmp_path, capsys):
        """Test main with non-existent file."""
        nonexistent = tmp_path / "nonexistent.json"

        with patch("sys.argv", ["generate_report.py", str(nonexistent)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error: File not found" in captured.err

    def test_main_invalid_json(self, tmp_path, capsys):
        """Test main with invalid JSON file."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("not valid json {{{")

        with patch("sys.argv", ["generate_report.py", str(invalid_file)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error: Invalid JSON file" in captured.err

    def test_main_general_exception(self, tmp_path, capsys):
        """Test main handles general exceptions."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps({"statistics": {}, "crashes": []}))

        with patch("sys.argv", ["generate_report.py", str(session_file)]):
            with patch(
                "dicom_fuzzer.cli.commands.reports.generate_reports",
                side_effect=Exception("Test error"),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error generating report" in captured.err


class TestGenerateJsonReport:
    """Test JSON report generation."""

    def test_generate_json_report_basic(self, tmp_path):
        """Test basic JSON report generation."""
        data = {
            "title": "Test Report",
            "summary": {"items": 10},
        }

        output_file = tmp_path / "report.json"

        generate_json_report(data, str(output_file))

        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            result = json.load(f)

        assert result == data

    def test_generate_json_report_complex_data(self, tmp_path):
        """Test JSON report with complex nested data."""
        data = {
            "title": "Complex Report",
            "nested": {"level1": {"level2": {"level3": "value"}}},
            "list": [1, 2, 3, {"key": "value"}],
            "unicode": "Test unicode: \u2713 \u2717",
        }

        output_file = tmp_path / "complex.json"

        generate_json_report(data, str(output_file))

        with open(output_file, encoding="utf-8") as f:
            result = json.load(f)

        assert result == data

    def test_generate_json_report_empty_data(self, tmp_path):
        """Test JSON report with empty data."""
        output_file = tmp_path / "empty.json"

        generate_json_report({}, str(output_file))

        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            result = json.load(f)

        assert result == {}


class TestGenerateCsvReport:
    """Test CSV report generation."""

    def test_generate_csv_report_basic(self, tmp_path):
        """Test basic CSV report generation."""
        crashes = [
            {"id": "1", "type": "segfault", "severity": "high"},
            {"id": "2", "type": "buffer_overflow", "severity": "critical"},
        ]

        output_file = tmp_path / "crashes.csv"

        generate_csv_report(crashes, str(output_file))

        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["id"] == "1"
        assert rows[1]["type"] == "buffer_overflow"

    def test_generate_csv_report_empty_list(self, tmp_path):
        """Test CSV report with empty crash list."""
        output_file = tmp_path / "empty.csv"

        generate_csv_report([], str(output_file))

        # Empty list should not create file
        assert not output_file.exists()

    def test_generate_csv_report_single_crash(self, tmp_path):
        """Test CSV report with single crash."""
        crashes = [{"id": "crash_001", "description": "Test crash"}]

        output_file = tmp_path / "single.csv"

        generate_csv_report(crashes, str(output_file))

        assert output_file.exists()

        with open(output_file, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 1
        assert rows[0]["id"] == "crash_001"


class TestGenerateCoverageChart:
    """Test coverage chart generation."""

    @pytest.mark.skipif(_matplotlib is None, reason="Matplotlib not installed")
    def test_generate_coverage_chart_with_matplotlib(self, tmp_path):
        """Test coverage chart generation with matplotlib."""
        coverage_data = {
            "1": 10.0,
            "2": 25.0,
            "3": 40.0,
            "4": 55.0,
            "5": 70.0,
        }

        output_file = tmp_path / "coverage.png"

        with patch.object(_matplotlib.pyplot, "figure"):
            with patch.object(_matplotlib.pyplot, "plot"):
                with patch.object(_matplotlib.pyplot, "xlabel"):
                    with patch.object(_matplotlib.pyplot, "ylabel"):
                        with patch.object(_matplotlib.pyplot, "title"):
                            with patch.object(
                                _matplotlib.pyplot, "savefig"
                            ) as mock_savefig:
                                with patch.object(
                                    _matplotlib.pyplot, "close"
                                ) as mock_close:
                                    generate_coverage_chart(
                                        coverage_data, str(output_file)
                                    )

                                    # Verify matplotlib functions were called
                                    mock_savefig.assert_called_once()
                                    mock_close.assert_called_once()

    def test_generate_coverage_chart_without_matplotlib(self, tmp_path):
        """Test coverage chart fallback when matplotlib not available."""
        coverage_data = {"1": 10.0, "2": 20.0}

        output_file = tmp_path / "coverage.png"

        with patch("dicom_fuzzer.cli.commands.reports._matplotlib", None):
            generate_coverage_chart(coverage_data, str(output_file))

        # Fallback creates empty file
        assert output_file.exists()

    def test_generate_coverage_chart_empty_data(self, tmp_path):
        """Test coverage chart with empty data."""
        output_file = tmp_path / "empty_coverage.png"

        with patch("dicom_fuzzer.cli.commands.reports._matplotlib", None):
            generate_coverage_chart({}, str(output_file))

        assert output_file.exists()


class TestGenerateMarkdownReport:
    """Test Markdown report generation."""

    def test_generate_markdown_report_basic(self, tmp_path):
        """Test basic Markdown report generation."""
        data = {
            "title": "Security Report",
            "summary": {"Total Crashes": 5, "Critical": 2},
            "findings": [
                {"severity": "critical", "description": "Buffer overflow"},
                {"severity": "high", "description": "Memory corruption"},
            ],
        }

        output_file = tmp_path / "report.md"

        generate_markdown_report(data, str(output_file))

        assert output_file.exists()

        content = output_file.read_text()
        assert "# Security Report" in content
        assert "## Summary" in content
        assert "Total Crashes" in content
        assert "## Findings" in content
        assert "critical" in content
        assert "Buffer overflow" in content

    def test_generate_markdown_report_no_summary(self, tmp_path):
        """Test Markdown report without summary section."""
        data = {
            "title": "Minimal Report",
            "findings": [{"severity": "low", "description": "Minor issue"}],
        }

        output_file = tmp_path / "minimal.md"

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "# Minimal Report" in content
        assert "## Summary" not in content
        assert "## Findings" in content

    def test_generate_markdown_report_no_findings(self, tmp_path):
        """Test Markdown report without findings section."""
        data = {
            "title": "Summary Only Report",
            "summary": {"Status": "Clean"},
        }

        output_file = tmp_path / "summary_only.md"

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "# Summary Only Report" in content
        assert "## Summary" in content
        assert "Status" in content
        assert "## Findings" not in content

    def test_generate_markdown_report_title_only(self, tmp_path):
        """Test Markdown report with title only."""
        data = {"title": "Empty Report"}

        output_file = tmp_path / "title_only.md"

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "# Empty Report" in content


class TestMatplotlibImport:
    """Test matplotlib import handling."""

    def test_matplotlib_import_variable_exists(self):
        """Test that _matplotlib variable exists."""
        from dicom_fuzzer.cli.commands.reports import _matplotlib

        # Should be either a module or None
        assert _matplotlib is None or hasattr(_matplotlib, "pyplot")


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_generate_reports_empty_statistics(self, tmp_path, capsys):
        """Test report generation with empty statistics."""
        session_data = {
            "session_info": {},
            "statistics": {},
            "crashes": [],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "dicom_fuzzer.cli.commands.reports.EnhancedReportGenerator"
        ) as mock_reporter:
            mock_instance = MagicMock()
            mock_instance.generate_html_report.return_value = tmp_path / "report.html"
            mock_reporter.return_value = mock_instance

            generate_reports(session_file)

        captured = capsys.readouterr()
        assert "Files Fuzzed:      0" in captured.out
        assert "Crashes:           0" in captured.out

    def test_generate_csv_with_unicode(self, tmp_path):
        """Test CSV report with unicode characters."""
        crashes = [
            {"id": "1", "description": "Test with unicode: \u2713 \u2717"},
        ]

        output_file = tmp_path / "unicode.csv"

        generate_csv_report(crashes, str(output_file))

        with open(output_file, encoding="utf-8") as f:
            content = f.read()

        assert "\u2713" in content

    def test_generate_markdown_with_special_characters(self, tmp_path):
        """Test Markdown report with special characters."""
        data = {
            "title": "Report with *special* _characters_",
            "summary": {"Key with: colon": "Value with **bold**"},
            "findings": [],
        }

        output_file = tmp_path / "special.md"

        generate_markdown_report(data, str(output_file))

        content = output_file.read_text()
        assert "*special*" in content
        assert "colon" in content

    def test_generate_reports_crash_without_repro_command(self, tmp_path, capsys):
        """Test report with crash that has no reproduction command."""
        session_data = {
            "session_info": {},
            "statistics": {"crashes": 1},
            "crashes": [
                {
                    "crash_id": "crash_no_repro",
                    "preserved_sample_path": "/path/sample.dcm",
                    "crash_log_path": "/path/log.txt",
                    # No reproduction_command
                },
            ],
        }

        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        with patch(
            "dicom_fuzzer.cli.commands.reports.EnhancedReportGenerator"
        ) as mock_reporter:
            mock_instance = MagicMock()
            mock_instance.generate_html_report.return_value = tmp_path / "report.html"
            mock_reporter.return_value = mock_instance

            generate_reports(session_file)

        captured = capsys.readouterr()
        assert "crash_no_repro" in captured.out
        # Should not have "Repro:" line since no command
        lines = [line for line in captured.out.split("\n") if "crash_no_repro" in line]
        assert len(lines) >= 1
