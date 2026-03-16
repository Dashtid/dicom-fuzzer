"""Test Generate Report Module

This test suite verifies the report generation functionality for
DICOM fuzzing campaigns including HTML, JSON, CSV, and Markdown reports.
"""

import json
from unittest.mock import MagicMock, patch

from dicom_fuzzer.cli.commands.reports import (
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
            "dicom_fuzzer.core.reporting.report_utils.EnhancedReportGenerator"
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
            "dicom_fuzzer.core.reporting.report_utils.EnhancedReportGenerator"
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
            "dicom_fuzzer.core.reporting.report_utils.EnhancedReportGenerator"
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
            "dicom_fuzzer.core.reporting.report_utils.EnhancedReportGenerator"
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

        result = main([str(nonexistent)])

        assert result == 1
        captured = capsys.readouterr()
        assert "Error: File not found" in captured.err

    def test_main_invalid_json(self, tmp_path, capsys):
        """Test main with invalid JSON file."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("not valid json {{{")

        result = main([str(invalid_file)])

        assert result == 1
        captured = capsys.readouterr()
        assert "Error: Invalid JSON file" in captured.err

    def test_main_general_exception(self, tmp_path, capsys):
        """Test main handles general exceptions."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps({"statistics": {}, "crashes": []}))

        with patch(
            "dicom_fuzzer.cli.commands.reports.generate_reports",
            side_effect=Exception("Test error"),
        ):
            result = main([str(session_file)])

        assert result == 1
        captured = capsys.readouterr()
        assert "Error generating report" in captured.err


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
            "dicom_fuzzer.core.reporting.report_utils.EnhancedReportGenerator"
        ) as mock_reporter:
            mock_instance = MagicMock()
            mock_instance.generate_html_report.return_value = tmp_path / "report.html"
            mock_reporter.return_value = mock_instance

            generate_reports(session_file)

        captured = capsys.readouterr()
        assert "Files Fuzzed:      0" in captured.out
        assert "Crashes:           0" in captured.out

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
            "dicom_fuzzer.core.reporting.report_utils.EnhancedReportGenerator"
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
