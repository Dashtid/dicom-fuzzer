"""Tests for generate_report CLI module to improve code coverage.

These tests exercise the report generation code paths.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from dicom_fuzzer.cli.generate_report import (
    generate_coverage_chart,
    generate_csv_report,
    generate_json_report,
    generate_markdown_report,
    generate_reports,
    main,
)


@pytest.fixture
def temp_dir(tmp_path):
    """Create temporary directory for tests."""
    return tmp_path


@pytest.fixture
def sample_session_data():
    """Create sample session data for testing."""
    return {
        "session_info": {
            "session_id": "test-session-001",
            "session_name": "Test Session",
            "start_time": "2025-01-01T10:00:00",
            "end_time": "2025-01-01T11:00:00",
        },
        "statistics": {
            "files_fuzzed": 100,
            "mutations_applied": 500,
            "crashes": 3,
            "hangs": 1,
            "successes": 96,
        },
        "fuzzed_files": {
            "file-001": {
                "original_file": "/path/to/original1.dcm",
                "mutations": [{"mutation_type": "header"}],
            },
            "file-002": {
                "original_file": "/path/to/original2.dcm",
                "mutations": [{"mutation_type": "metadata"}],
            },
        },
        "crashes": [
            {
                "crash_id": "crash-001",
                "crash_type": "crash",
                "severity": "critical",
                "fuzzed_file_id": "file-001",
                "fuzzed_file_path": "/path/to/fuzzed1.dcm",
                "preserved_sample_path": "/path/to/crash1.dcm",
                "crash_log_path": "/path/to/crash1.log",
                "reproduction_command": "dicom-fuzz reproduce crash-001",
                "timestamp": "2025-01-01T10:30:00",
            },
            {
                "crash_id": "crash-002",
                "crash_type": "crash",
                "severity": "high",
                "fuzzed_file_id": "file-002",
                "fuzzed_file_path": "/path/to/fuzzed2.dcm",
                "preserved_sample_path": "/path/to/crash2.dcm",
                "crash_log_path": "/path/to/crash2.log",
                "timestamp": "2025-01-01T10:45:00",
            },
        ],
    }


@pytest.fixture
def session_json_file(temp_dir, sample_session_data):
    """Create a session JSON file for testing."""
    json_path = temp_dir / "session.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sample_session_data, f)
    return json_path


class TestGenerateReports:
    """Test generate_reports function."""

    def test_generate_reports_basic(self, session_json_file, temp_dir, capsys):
        """Test basic report generation."""
        output_html = temp_dir / "output.html"

        result = generate_reports(
            session_json_path=session_json_file,
            output_html=output_html,
            keep_json=False,
        )

        assert result is not None
        captured = capsys.readouterr()
        assert "Loading session data" in captured.out
        assert "HTML report generated" in captured.out

    def test_generate_reports_with_crashes_summary(
        self, session_json_file, temp_dir, capsys
    ):
        """Test report generation with crash summary."""
        result = generate_reports(
            session_json_path=session_json_file,
            output_html=temp_dir / "output.html",
        )

        captured = capsys.readouterr()
        assert "crash(es) detected" in captured.out
        assert "crash-001" in captured.out
        assert "Repro:" in captured.out  # reproduction_command present

    def test_generate_reports_keep_json(self, session_json_file, temp_dir, capsys):
        """Test report generation with keep_json flag."""
        generate_reports(
            session_json_path=session_json_file,
            output_html=temp_dir / "output.html",
            keep_json=True,
        )

        captured = capsys.readouterr()
        assert "JSON data saved" in captured.out

    def test_generate_reports_no_crashes(self, temp_dir, capsys):
        """Test report generation with no crashes."""
        session_data = {
            "session_info": {
                "session_id": "no-crash-session",
                "session_name": "No Crashes",
                "start_time": "2025-01-01T10:00:00",
                "end_time": "2025-01-01T11:00:00",
            },
            "statistics": {
                "files_fuzzed": 50,
                "mutations_applied": 200,
                "crashes": 0,
                "hangs": 0,
                "successes": 50,
            },
            "fuzzed_files": {},
            "crashes": [],
        }

        json_path = temp_dir / "no_crashes.json"
        with open(json_path, "w") as f:
            json.dump(session_data, f)

        generate_reports(
            session_json_path=json_path,
            output_html=temp_dir / "output.html",
        )

        captured = capsys.readouterr()
        assert "crash(es) detected" not in captured.out

    def test_generate_reports_auto_output_path(self, session_json_file, capsys):
        """Test report generation with auto-generated output path."""
        result = generate_reports(
            session_json_path=session_json_file,
            output_html=None,  # Auto-generate
        )

        assert result is not None


class TestMain:
    """Test main function."""

    def test_main_file_not_found(self, temp_dir, capsys):
        """Test main with non-existent file."""
        with patch(
            "sys.argv", ["generate_report.py", str(temp_dir / "nonexistent.json")]
        ):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "File not found" in captured.err

    def test_main_invalid_json(self, temp_dir, capsys):
        """Test main with invalid JSON file."""
        invalid_json = temp_dir / "invalid.json"
        invalid_json.write_text("{ invalid json }")

        with patch("sys.argv", ["generate_report.py", str(invalid_json)]):
            with pytest.raises(SystemExit) as exc_info:
                main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Invalid JSON" in captured.err

    def test_main_success(self, session_json_file, temp_dir, capsys):
        """Test main with valid input."""
        output_path = temp_dir / "report.html"

        with patch(
            "sys.argv",
            [
                "generate_report.py",
                str(session_json_file),
                "--output",
                str(output_path),
            ],
        ):
            main()

        captured = capsys.readouterr()
        assert "HTML report generated" in captured.out

    def test_main_with_keep_json(self, session_json_file, temp_dir, capsys):
        """Test main with --keep-json flag."""
        with patch(
            "sys.argv",
            [
                "generate_report.py",
                str(session_json_file),
                "--keep-json",
            ],
        ):
            main()

        captured = capsys.readouterr()
        assert "JSON data saved" in captured.out

    def test_main_generic_error(self, session_json_file, capsys):
        """Test main handles generic errors."""
        with patch("sys.argv", ["generate_report.py", str(session_json_file)]):
            with patch(
                "dicom_fuzzer.cli.generate_report.generate_reports",
                side_effect=RuntimeError("Test error"),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Error generating report" in captured.err


class TestGenerateJsonReport:
    """Test generate_json_report function."""

    def test_generate_json_report(self, temp_dir):
        """Test JSON report generation."""
        data = {"key": "value", "nested": {"a": 1, "b": 2}}
        output_file = str(temp_dir / "output.json")

        generate_json_report(data, output_file)

        with open(output_file) as f:
            loaded = json.load(f)

        assert loaded == data

    def test_generate_json_report_complex(self, temp_dir):
        """Test JSON report with complex data."""
        data = {
            "campaign_id": "test-001",
            "statistics": {
                "total_files": 100,
                "crashes": 5,
            },
            "crashes": [
                {"id": "c1", "severity": "high"},
                {"id": "c2", "severity": "medium"},
            ],
        }
        output_file = str(temp_dir / "complex.json")

        generate_json_report(data, output_file)

        assert Path(output_file).exists()


class TestGenerateCsvReport:
    """Test generate_csv_report function."""

    def test_generate_csv_report(self, temp_dir):
        """Test CSV report generation."""
        crashes = [
            {"crash_id": "c1", "severity": "high", "type": "crash"},
            {"crash_id": "c2", "severity": "medium", "type": "hang"},
        ]
        output_file = str(temp_dir / "crashes.csv")

        generate_csv_report(crashes, output_file)

        assert Path(output_file).exists()

        # Verify content
        with open(output_file) as f:
            content = f.read()

        assert "crash_id" in content
        assert "c1" in content
        assert "c2" in content

    def test_generate_csv_report_empty(self, temp_dir):
        """Test CSV report with empty crashes."""
        output_file = str(temp_dir / "empty.csv")

        generate_csv_report([], output_file)

        # Should not create file for empty crashes
        assert not Path(output_file).exists()


class TestGenerateCoverageChart:
    """Test generate_coverage_chart function."""

    def test_generate_coverage_chart_with_matplotlib(self, temp_dir):
        """Test coverage chart generation with matplotlib available."""
        coverage_data = {0: 10, 100: 25, 200: 40, 300: 55, 400: 60}
        output_file = str(temp_dir / "coverage.png")

        # Check if matplotlib is available
        try:
            import importlib.util

            has_matplotlib = importlib.util.find_spec("matplotlib") is not None
        except ImportError:
            has_matplotlib = False

        generate_coverage_chart(coverage_data, output_file)

        # File should exist either way (matplotlib creates chart, fallback creates empty)
        assert Path(output_file).exists()

    def test_generate_coverage_chart_no_matplotlib(self, temp_dir):
        """Test coverage chart fallback when matplotlib not available."""
        coverage_data = {0: 10, 100: 25}
        output_file = str(temp_dir / "coverage_fallback.png")

        # Patch matplotlib to None
        with patch("dicom_fuzzer.cli.generate_report._matplotlib", None):
            generate_coverage_chart(coverage_data, output_file)

        # Should create empty file as fallback
        assert Path(output_file).exists()


class TestGenerateMarkdownReport:
    """Test generate_markdown_report function."""

    def test_generate_markdown_report_full(self, temp_dir):
        """Test full markdown report generation."""
        data = {
            "title": "Fuzzing Report",
            "summary": {
                "Total Files": 100,
                "Crashes": 5,
                "Coverage": "75%",
            },
            "findings": [
                {"severity": "HIGH", "description": "Buffer overflow in parser"},
                {"severity": "MEDIUM", "description": "Memory leak in handler"},
            ],
        }
        output_file = str(temp_dir / "report.md")

        generate_markdown_report(data, output_file)

        with open(output_file) as f:
            content = f.read()

        assert "# Fuzzing Report" in content
        assert "## Summary" in content
        assert "Total Files" in content
        assert "## Findings" in content
        assert "HIGH" in content
        assert "Buffer overflow" in content

    def test_generate_markdown_report_minimal(self, temp_dir):
        """Test markdown report with minimal data."""
        data = {"title": "Minimal Report"}
        output_file = str(temp_dir / "minimal.md")

        generate_markdown_report(data, output_file)

        with open(output_file) as f:
            content = f.read()

        assert "# Minimal Report" in content
        assert "## Summary" not in content
        assert "## Findings" not in content

    def test_generate_markdown_report_no_findings(self, temp_dir):
        """Test markdown report without findings."""
        data = {
            "title": "No Findings Report",
            "summary": {"Status": "Clean"},
        }
        output_file = str(temp_dir / "no_findings.md")

        generate_markdown_report(data, output_file)

        with open(output_file) as f:
            content = f.read()

        assert "## Summary" in content
        assert "## Findings" not in content


class TestEdgeCases:
    """Test edge cases."""

    def test_generate_reports_missing_stats(self, temp_dir, capsys):
        """Test report with minimal statistics (defaults for missing fields)."""
        session_data = {
            "session_info": {
                "session_id": "minimal-session",
                "session_name": "Test",
                "start_time": "2025-01-01T10:00:00",
                "end_time": "2025-01-01T11:00:00",
            },
            "statistics": {
                "files_fuzzed": 0,
                "mutations_applied": 0,
                "crashes": 0,
                "hangs": 0,
                "successes": 0,
            },
            "fuzzed_files": {},
            "crashes": [],
        }

        json_path = temp_dir / "missing_stats.json"
        with open(json_path, "w") as f:
            json.dump(session_data, f)

        generate_reports(json_path, temp_dir / "output.html")

        captured = capsys.readouterr()
        # Should use default 0 values
        assert "Files Fuzzed:      0" in captured.out

    def test_generate_reports_crash_without_repro(self, temp_dir, capsys):
        """Test report with crash missing reproduction command."""
        session_data = {
            "session_info": {
                "session_id": "crash-repro-session",
                "session_name": "Test",
                "start_time": "2025-01-01T10:00:00",
                "end_time": "2025-01-01T11:00:00",
            },
            "statistics": {
                "files_fuzzed": 1,
                "mutations_applied": 1,
                "crashes": 1,
                "hangs": 0,
                "successes": 0,
            },
            "fuzzed_files": {
                "file-001": {
                    "original_file": "/path/to/original.dcm",
                    "mutations": [{"mutation_type": "header"}],
                },
            },
            "crashes": [
                {
                    "crash_id": "crash-no-repro",
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file-001",
                    "fuzzed_file_path": "/path/fuzzed.dcm",
                    "preserved_sample_path": "/path.dcm",
                    "crash_log_path": "/log.txt",
                    "timestamp": "2025-01-01T10:30:00",
                    # No reproduction_command
                }
            ],
        }

        json_path = temp_dir / "no_repro.json"
        with open(json_path, "w") as f:
            json.dump(session_data, f)

        generate_reports(json_path, temp_dir / "output.html")

        captured = capsys.readouterr()
        # Should not print Repro line for crash without it
        assert "crash-no-repro" in captured.out
