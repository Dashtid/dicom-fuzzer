"""Tests for cli/samples.py - Samples Subcommand.

Tests cover argument parsing, listing sources, and strip pixel data.
"""

from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.cli.commands.samples import (
    SAMPLE_SOURCES,
    create_parser,
    main,
    run_list_sources,
    run_strip_pixel_data,
)


class TestSampleSources:
    """Test SAMPLE_SOURCES constant."""

    def test_sources_defined(self):
        """Test that sample sources are defined."""
        assert len(SAMPLE_SOURCES) > 0
        assert "rubo" in SAMPLE_SOURCES
        assert "osirix" in SAMPLE_SOURCES

    def test_source_structure(self):
        """Test each source has required fields."""
        for key, source in SAMPLE_SOURCES.items():
            assert "name" in source
            assert "url" in source
            assert "description" in source


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created."""
        parser = create_parser()
        assert parser is not None

    def test_list_sources_action(self):
        """Test --list-sources action."""
        parser = create_parser()
        args = parser.parse_args(["--list-sources"])
        assert args.list_sources is True

    def test_strip_pixel_data_action(self):
        """Test --strip-pixel-data action."""
        parser = create_parser()
        args = parser.parse_args(["--strip-pixel-data", "./input", "-o", "./output"])
        assert args.strip_pixel_data == "./input"

    def test_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--list-sources", "--strip-pixel-data", "./input"])

    def test_default_output(self):
        """Test default output path."""
        parser = create_parser()
        args = parser.parse_args(["--list-sources"])
        assert args.output == "./artifacts/samples"

    def test_verbose_flag(self):
        """Test verbose flag."""
        parser = create_parser()
        args = parser.parse_args(["--list-sources", "-v"])
        assert args.verbose is True


class TestRunListSources:
    """Test run_list_sources function."""

    def test_list_sources(self, capsys):
        """Test listing sources."""
        args = MagicMock()

        result = run_list_sources(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Public DICOM Sample Sources" in captured.out
        assert "rubo" in captured.out.lower()
        assert "osirix" in captured.out.lower()

    def test_list_sources_contains_urls(self, capsys):
        """Test listing includes URLs."""
        args = MagicMock()

        run_list_sources(args)

        captured = capsys.readouterr()
        assert "URL:" in captured.out
        assert "http" in captured.out


class TestRunStripPixelData:
    """Test run_strip_pixel_data function."""

    def test_strip_path_not_found(self, tmp_path, capsys):
        """Test stripping nonexistent path."""
        args = MagicMock()
        args.strip_pixel_data = str(tmp_path / "nonexistent")
        args.output = str(tmp_path / "output")

        result = run_strip_pixel_data(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestMain:
    """Test main function."""

    def test_main_list_sources(self, capsys):
        """Test main with --list-sources."""
        result = main(["--list-sources"])

        assert result == 0
        captured = capsys.readouterr()
        assert "Public DICOM Sample Sources" in captured.out

    def test_main_no_action(self, capsys):
        """Test main without any action."""
        with pytest.raises(SystemExit):
            main([])

    def test_main_help(self, capsys):
        """Test main with --help."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0
