"""Tests for generate_all.py - Bulk Sample Generator CLI.

Tests cover argument parsing, category selection, and generator dispatch.
"""

import sys
from unittest.mock import patch

from dicom_fuzzer.generators.generate_all import main


class TestMain:
    """Test main function."""

    def test_main_list_categories(self, capsys):
        """Test --list shows available categories."""
        with patch.object(sys, "argv", ["generate_all", "--list"]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "Available categories" in captured.out
        assert "cve" in captured.out
        assert "stress" in captured.out
        assert "preamble" in captured.out
        assert "compliance" in captured.out

    def test_main_invalid_category(self, capsys, tmp_path):
        """Test invalid category returns error."""
        with patch.object(
            sys,
            "argv",
            ["generate_all", "--output", str(tmp_path), "--categories", "invalid"],
        ):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown categories" in captured.out

    def test_main_default_output(self, capsys):
        """Test default output directory."""
        with patch.object(sys, "argv", ["generate_all", "--list"]):
            result = main()

        assert result == 0

    def test_main_multiple_invalid_categories(self, capsys, tmp_path):
        """Test multiple invalid categories returns error."""
        with patch.object(
            sys,
            "argv",
            ["generate_all", "--output", str(tmp_path), "--categories", "foo,bar"],
        ):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown categories" in captured.out
        assert "foo" in captured.out

    def test_main_mixed_valid_invalid_categories(self, capsys, tmp_path):
        """Test mix of valid and invalid categories returns error."""
        with patch.object(
            sys,
            "argv",
            ["generate_all", "--output", str(tmp_path), "--categories", "cve,invalid"],
        ):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown categories" in captured.out
        assert "invalid" in captured.out
