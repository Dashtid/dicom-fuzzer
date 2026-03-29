"""Tests for cli/commands/seeds.py - Generate Seeds Subcommand."""

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

from dicom_fuzzer.cli.commands.seeds import create_parser, main


class TestCreateParser:
    """Test argument parser configuration."""

    def test_parser_creation(self):
        """Test parser is created."""
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_input_optional(self):
        """Test input argument is optional (--synthetic makes it unnecessary)."""
        parser = create_parser()
        args = parser.parse_args([])
        assert args.input is None

    def test_input_positional(self):
        """Test input is a positional argument."""
        parser = create_parser()
        args = parser.parse_args(["myfile.dcm"])
        assert args.input == "myfile.dcm"

    def test_output_default(self):
        """Test output defaults to ./artifacts/seeds."""
        parser = create_parser()
        args = parser.parse_args(["myfile.dcm"])
        assert args.output == "./artifacts/seeds"

    def test_output_custom(self):
        """Test custom output directory."""
        parser = create_parser()
        args = parser.parse_args(["myfile.dcm", "-o", "/tmp/seeds"])
        assert args.output == "/tmp/seeds"

    def test_count_default(self):
        """Test count defaults to 100."""
        parser = create_parser()
        args = parser.parse_args(["myfile.dcm"])
        assert args.count == 100

    def test_count_custom(self):
        """Test custom count."""
        parser = create_parser()
        args = parser.parse_args(["myfile.dcm", "-n", "50"])
        assert args.count == 50

    def test_count_is_int(self):
        """Test count is parsed as integer."""
        parser = create_parser()
        args = parser.parse_args(["myfile.dcm", "-n", "25"])
        assert isinstance(args.count, int)


class TestMain:
    """Test main entry point."""

    def test_missing_file_returns_1(self, capsys):
        """Test that a nonexistent input file returns error code 1."""
        result = main(["nonexistent_file.dcm"])
        assert result == 1
        captured = capsys.readouterr()
        assert "File not found" in captured.out

    @patch("dicom_fuzzer.cli.commands.seeds.DICOMGenerator")
    def test_generates_seeds(self, mock_gen_cls, tmp_path, capsys):
        """Test successful seed generation."""
        # Create a fake input file
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"fake dicom")

        output_dir = tmp_path / "output"

        # Mock the generator
        mock_gen = MagicMock()
        mock_gen.generate_batch.return_value = [Path("a.dcm"), Path("b.dcm")]
        mock_gen_cls.return_value = mock_gen

        result = main([str(input_file), "-o", str(output_dir), "-n", "10"])

        assert result == 0
        mock_gen_cls.assert_called_once_with(output_dir=str(output_dir), seed=None)
        mock_gen.generate_batch.assert_called_once_with(str(input_file), count=10)

        captured = capsys.readouterr()
        assert "Generated 2 seed files" in captured.out

    @patch("dicom_fuzzer.cli.commands.seeds.DICOMGenerator")
    def test_zero_results(self, mock_gen_cls, tmp_path, capsys):
        """Test when generator produces no files."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"fake dicom")

        mock_gen = MagicMock()
        mock_gen.generate_batch.return_value = []
        mock_gen_cls.return_value = mock_gen

        result = main([str(input_file)])
        assert result == 0

        captured = capsys.readouterr()
        assert "Generated 0 seed files" in captured.out
