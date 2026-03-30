"""Tests for cli/commands/sanitize.py -- Sanitize Subcommand."""

from __future__ import annotations

import argparse
from unittest.mock import patch

import pytest

from dicom_fuzzer.cli.commands.sanitize import create_parser, main


class TestCreateParser:
    """Test argument parser configuration."""

    def test_parser_creation(self):
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_seed_dir_required(self):
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_seed_dir_positional(self):
        parser = create_parser()
        args = parser.parse_args(["./seeds"])
        assert args.seed_dir == "./seeds"

    def test_output_default_is_none(self):
        parser = create_parser()
        args = parser.parse_args(["./seeds"])
        assert args.output is None

    def test_output_custom(self):
        parser = create_parser()
        args = parser.parse_args(["./seeds", "-o", "/tmp/out"])
        assert args.output == "/tmp/out"

    def test_recursive_default_false(self):
        parser = create_parser()
        args = parser.parse_args(["./seeds"])
        assert args.recursive is False

    def test_keep_private_default_false(self):
        parser = create_parser()
        args = parser.parse_args(["./seeds"])
        assert args.keep_private is False

    def test_keep_uids_default_false(self):
        parser = create_parser()
        args = parser.parse_args(["./seeds"])
        assert args.keep_uids is False

    def test_dry_run_default_false(self):
        parser = create_parser()
        args = parser.parse_args(["./seeds"])
        assert args.dry_run is False


class TestMain:
    """Test main entry point."""

    def test_missing_directory_returns_1(self, capsys):
        result = main(["nonexistent_dir"])
        assert result == 1
        captured = capsys.readouterr()
        assert "Directory not found" in captured.out

    def test_empty_directory_returns_1(self, tmp_path, capsys):
        empty = tmp_path / "empty"
        empty.mkdir()
        result = main([str(empty)])
        assert result == 1
        captured = capsys.readouterr()
        assert "No DICOM files found" in captured.out

    def test_dry_run_no_writes(self, tmp_path, capsys):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "test.dcm").write_bytes(b"\x00" * 132 + b"DICM")
        result = main([str(seed_dir), "--dry-run"])
        assert result == 0
        captured = capsys.readouterr()
        assert "Dry run" in captured.out
        # No output directory should be created
        assert not (tmp_path / "seeds_sanitized").exists()

    @patch("dicom_fuzzer.cli.commands.sanitize.sanitize_directory")
    def test_sanitize_success(self, mock_sanitize, tmp_path, capsys):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "test.dcm").write_bytes(b"\x00" * 132 + b"DICM")

        mock_sanitize.return_value = {"processed": 1, "succeeded": 1, "failed": 0}

        result = main([str(seed_dir), "-o", str(tmp_path / "out")])
        assert result == 0
        mock_sanitize.assert_called_once()

        captured = capsys.readouterr()
        assert "Sanitized 1/1" in captured.out

    @patch("dicom_fuzzer.cli.commands.sanitize.sanitize_directory")
    def test_partial_failure_shows_warning(self, mock_sanitize, tmp_path, capsys):
        seed_dir = tmp_path / "seeds"
        seed_dir.mkdir()
        (seed_dir / "test.dcm").write_bytes(b"\x00" * 132 + b"DICM")

        mock_sanitize.return_value = {"processed": 3, "succeeded": 2, "failed": 1}

        result = main([str(seed_dir)])
        assert result == 0
        captured = capsys.readouterr()
        assert "1 file(s) failed" in captured.out
