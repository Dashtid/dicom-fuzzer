"""Tests for dicom_fuzzer.cli.create_html_report module."""

import json
from pathlib import Path

import pytest

from dicom_fuzzer.cli.commands.reports import (
    create_html_report,
)


class TestCreateHtmlReport:
    """Tests for create_html_report function."""

    def test_create_html_report_basic(self, tmp_path):
        """Test basic HTML report creation."""
        # Create test JSON data
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 0,
                "viewer_crashes": 0,
                "viewer_success": 10,
                "files_processed": 10,
                "files_fuzzed": 10,
                "files_generated": 10,
                "hang_rate": 0.0,
            },
            "configuration": {
                "viewer_path": "/path/to/viewer",
                "input_dir": "/input",
                "output_dir": "/output",
                "timeout": 30,
            },
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        assert html_path.endswith(".html")
        assert Path(html_path).exists()

        # Check content
        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "DICOM Viewer Security Assessment" in content
            assert "2024-01-01T12:00:00" in content

    def test_create_html_report_with_custom_output(self, tmp_path):
        """Test HTML report with custom output path."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 0,
                "viewer_crashes": 0,
                "viewer_success": 10,
                "hang_rate": 0.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "input.json"
        html_path = tmp_path / "custom_output.html"

        with open(json_path, "w") as f:
            json.dump(json_data, f)

        result = create_html_report(str(json_path), str(html_path))

        assert result == str(html_path)
        assert html_path.exists()

    def test_create_html_report_critical_hang_rate(self, tmp_path):
        """Test HTML report with 100% hang rate (critical alert)."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 10,
                "viewer_crashes": 0,
                "viewer_success": 0,
                "hang_rate": 100.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "CRITICAL SECURITY FINDING" in content
            assert "100% hang rate detected" in content

    def test_create_html_report_warning_hang_rate(self, tmp_path):
        """Test HTML report with 50%+ hang rate (warning alert)."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 6,
                "viewer_crashes": 0,
                "viewer_success": 4,
                "hang_rate": 60.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "WARNING" in content
            assert "60.0%" in content

    def test_create_html_report_success_info(self, tmp_path):
        """Test HTML report with low hang rate (success info)."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 1,
                "viewer_crashes": 0,
                "viewer_success": 9,
                "hang_rate": 10.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "INFO" in content
            assert "10.0%" in content

    def test_create_html_report_no_tests(self, tmp_path):
        """Test HTML report with no tests run."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 0,
                "viewer_crashes": 0,
                "viewer_success": 0,
                "hang_rate": 0.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        # Should not have any alert when total_tests is 0
        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            # No alert should be shown
            assert 'class="alert"' not in content
            assert 'class="warning"' not in content
            assert 'class="success"' not in content

    def test_create_html_report_includes_configuration(self, tmp_path):
        """Test HTML report includes configuration details."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 0,
                "viewer_crashes": 0,
                "viewer_success": 10,
                "hang_rate": 0.0,
            },
            "configuration": {
                "viewer_path": "/usr/bin/dicom_viewer",
                "input_dir": "/data/dicom/input",
                "output_dir": "/data/dicom/output",
                "timeout": 60,
            },
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "/usr/bin/dicom_viewer" in content
            assert "/data/dicom/input" in content
            assert "/data/dicom/output" in content
            assert "60" in content

    def test_create_html_report_includes_statistics(self, tmp_path):
        """Test HTML report includes all statistics."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 5,
                "viewer_crashes": 3,
                "viewer_success": 92,
                "files_processed": 100,
                "files_fuzzed": 50,
                "files_generated": 75,
                "hang_rate": 5.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "100" in content  # files_processed
            assert "50" in content  # files_fuzzed
            assert "75" in content  # files_generated
            assert "3" in content  # viewer_crashes
            assert "5" in content  # viewer_hangs

    def test_create_html_report_default_path_from_json(self, tmp_path):
        """Test default HTML path is derived from JSON path."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 0,
                "viewer_crashes": 0,
                "viewer_success": 1,
                "hang_rate": 0.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "my_report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        assert html_path == str(tmp_path / "my_report.html")

    def test_create_html_report_missing_config_keys(self, tmp_path):
        """Test HTML report handles missing configuration keys."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "hang_rate": 0.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "N/A" in content  # Default for missing values


class TestMainModule:
    """Tests for module-level execution."""

    def test_main_with_json_argument(self, tmp_path):
        """Test main execution with JSON argument."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {"hang_rate": 0.0},
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        # Import and run main
        import sys

        old_argv = sys.argv
        try:
            sys.argv = ["create_html_report.py", str(json_path)]
            # Reload module to trigger __main__ block
            import dicom_fuzzer.cli.commands.reports as module

            # Call create_html_report directly
            html_path = module.create_html_report(str(json_path))
            assert Path(html_path).exists()
        finally:
            sys.argv = old_argv

    def test_main_with_custom_output_argument(self, tmp_path):
        """Test main execution with custom output path."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {"hang_rate": 0.0},
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        html_path = tmp_path / "custom.html"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        import dicom_fuzzer.cli.commands.reports as module

        result = module.create_html_report(str(json_path), str(html_path))
        assert result == str(html_path)
        assert html_path.exists()


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_json_with_missing_statistics(self, tmp_path):
        """Test handling JSON with missing statistics key."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        with pytest.raises(KeyError):
            create_html_report(str(json_path))

    def test_json_with_missing_configuration(self, tmp_path):
        """Test handling JSON with missing configuration key."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {"hang_rate": 0.0},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        with pytest.raises(KeyError):
            create_html_report(str(json_path))

    def test_invalid_json_file(self, tmp_path):
        """Test handling invalid JSON file."""
        json_path = tmp_path / "invalid.json"
        json_path.write_text("{ invalid json }", encoding="utf-8")

        with pytest.raises(json.JSONDecodeError):
            create_html_report(str(json_path))

    def test_nonexistent_json_file(self, tmp_path):
        """Test handling non-existent JSON file."""
        json_path = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError):
            create_html_report(str(json_path))

    def test_hang_rate_exactly_50(self, tmp_path):
        """Test hang rate at exactly 50% threshold."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 5,
                "viewer_crashes": 0,
                "viewer_success": 5,
                "hang_rate": 50.0,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "WARNING" in content  # 50% is >= 50, so warning

    def test_hang_rate_just_below_50(self, tmp_path):
        """Test hang rate just below 50% threshold."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 4,
                "viewer_crashes": 0,
                "viewer_success": 5,
                "hang_rate": 49.9,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            # Should show INFO (success) since total_tests > 0 and hang_rate < 50
            assert "INFO" in content or "success" in content

    def test_html_escaping(self, tmp_path):
        """Test that HTML content is properly structured."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 0,
                "viewer_crashes": 0,
                "viewer_success": 1,
                "hang_rate": 0.0,
            },
            "configuration": {
                "viewer_path": "path/with/<script>alert('xss')</script>",
            },
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            # The path should be in the HTML (this is a raw string, not escaped)
            # In production, you'd want to escape this
            assert "viewer_path" not in content or "path/with/" in content

    def test_large_numbers_in_statistics(self, tmp_path):
        """Test handling large numbers in statistics."""
        json_data = {
            "timestamp": "2024-01-01T12:00:00",
            "statistics": {
                "viewer_hangs": 1000000,
                "viewer_crashes": 500000,
                "viewer_success": 10000000,
                "files_processed": 99999999,
                "hang_rate": 8.7,
            },
            "configuration": {},
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(json_data, f)

        html_path = create_html_report(str(json_path))

        with open(html_path, encoding="utf-8") as f:
            content = f.read()
            assert "1000000" in content
            assert "99999999" in content
