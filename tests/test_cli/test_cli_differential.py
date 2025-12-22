"""Tests for differential fuzzing CLI subcommand.

Tests for dicom_fuzzer.cli.differential module.
"""

import argparse
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli import differential


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created with required arguments."""
        parser = differential.create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_test_action(self):
        """Test --test argument."""
        parser = differential.create_parser()
        args = parser.parse_args(["--test", "input.dcm"])
        assert args.test == "input.dcm"

    def test_parser_test_dir_action(self):
        """Test --test-dir argument."""
        parser = differential.create_parser()
        args = parser.parse_args(["--test-dir", "./corpus"])
        assert args.test_dir == "./corpus"

    def test_parser_list_parsers_action(self):
        """Test --list-parsers argument."""
        parser = differential.create_parser()
        args = parser.parse_args(["--list-parsers"])
        assert args.list_parsers is True

    def test_parser_mutually_exclusive(self):
        """Test that actions are mutually exclusive."""
        parser = differential.create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--test", "file.dcm", "--list-parsers"])

    def test_parser_output_options(self):
        """Test output options."""
        parser = differential.create_parser()
        args = parser.parse_args(
            ["--test", "input.dcm", "-o", "./output", "--format", "json", "-v"]
        )
        assert args.output == "./output"
        assert args.format == "json"
        assert args.verbose is True

    def test_parser_defaults(self):
        """Test default values."""
        parser = differential.create_parser()
        args = parser.parse_args(["--test", "input.dcm"])
        assert args.output is None
        assert args.format == "text"
        assert args.verbose is False


class TestRunTest:
    """Test run_test function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_test_file_not_found(self, capsys):
        """Test error when input file not found."""
        args = argparse.Namespace(
            test="/nonexistent/file.dcm",
            output=None,
            format="text",
            verbose=False,
        )

        result = differential.run_test(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_test_no_differences(self, temp_dir, capsys):
        """Test when all parsers agree."""
        input_file = temp_dir / "test.dcm"
        input_file.write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            test=str(input_file),
            output=None,
            format="text",
            verbose=False,
        )

        mock_result = MagicMock()
        mock_result.differences = []

        mock_fuzzer = MagicMock()
        mock_fuzzer.test_file.return_value = mock_result
        mock_fuzzer.get_statistics.return_value = {"files_tested": 1}

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"
            ):
                result = differential.run_test(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No differences found" in captured.out

    def test_run_test_with_differences(self, temp_dir, capsys):
        """Test when parsers disagree."""
        input_file = temp_dir / "test.dcm"
        input_file.write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            test=str(input_file),
            output=None,
            format="text",
            verbose=False,
        )

        mock_result = MagicMock()
        mock_result.differences = [
            "pydicom: (0010,0010) = 'John Doe'",
            "gdcm: (0010,0010) = 'JOHN DOE'",
        ]

        mock_fuzzer = MagicMock()
        mock_fuzzer.test_file.return_value = mock_result
        mock_fuzzer.get_statistics.return_value = {}

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"
            ):
                result = differential.run_test(args)

        # Should return 1 when differences found
        assert result == 1
        captured = capsys.readouterr()
        assert "Found 2 differences" in captured.out

    def test_run_test_with_output_json(self, temp_dir, capsys):
        """Test with JSON output."""
        input_file = temp_dir / "test.dcm"
        input_file.write_bytes(b"\x00" * 100)
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            test=str(input_file),
            output=str(output_dir),
            format="json",
            verbose=False,
        )

        mock_result = MagicMock()
        mock_result.differences = []

        mock_fuzzer = MagicMock()
        mock_fuzzer.test_file.return_value = mock_result
        mock_fuzzer.get_statistics.return_value = {}

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"
            ):
                result = differential.run_test(args)

        assert result == 0
        assert output_dir.exists()

        report_files = list(output_dir.glob("diff_*.json"))
        assert len(report_files) == 1

    def test_run_test_with_output_text(self, temp_dir, capsys):
        """Test with text output."""
        input_file = temp_dir / "test.dcm"
        input_file.write_bytes(b"\x00" * 100)
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            test=str(input_file),
            output=str(output_dir),
            format="text",
            verbose=False,
        )

        mock_result = MagicMock()
        mock_result.differences = ["diff1", "diff2"]

        mock_fuzzer = MagicMock()
        mock_fuzzer.test_file.return_value = mock_result
        mock_fuzzer.get_statistics.return_value = {}

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"
            ):
                result = differential.run_test(args)

        report_files = list(output_dir.glob("diff_*.text"))
        assert len(report_files) == 1

        content = report_files[0].read_text()
        assert "diff1" in content

    def test_run_test_import_error(self, temp_dir, capsys):
        """Test handling of import error."""
        input_file = temp_dir / "test.dcm"
        input_file.write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            test=str(input_file),
            output=None,
            format="text",
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            side_effect=ImportError("Module not found"),
        ):
            result = differential.run_test(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not available" in captured.out

    def test_run_test_exception_verbose(self, temp_dir, capsys):
        """Test exception handling with verbose flag."""
        input_file = temp_dir / "test.dcm"
        input_file.write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            test=str(input_file),
            output=None,
            format="text",
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            side_effect=RuntimeError("Test error"),
        ):
            result = differential.run_test(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Testing failed" in captured.out


class TestRunTestDir:
    """Test run_test_dir function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_test_dir_not_found(self, capsys):
        """Test error when directory not found."""
        args = argparse.Namespace(
            test_dir="/nonexistent/dir",
            output=None,
            format="text",
            verbose=False,
        )

        result = differential.run_test_dir(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_test_dir_no_differences(self, temp_dir, capsys):
        """Test batch testing with no differences."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()
        for i in range(3):
            (input_dir / f"test_{i}.dcm").write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            test_dir=str(input_dir),
            output=None,
            format="text",
            verbose=False,
        )

        mock_result = MagicMock()
        mock_result.differences = []

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_directory.return_value = [
            mock_result,
            mock_result,
            mock_result,
        ]

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"
            ):
                result = differential.run_test_dir(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Tested 3 files" in captured.out
        assert "Files with differences: 0" in captured.out

    def test_run_test_dir_with_differences(self, temp_dir, capsys):
        """Test batch testing with differences."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()
        (input_dir / "test.dcm").write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            test_dir=str(input_dir),
            output=None,
            format="text",
            verbose=False,
        )

        mock_result_ok = MagicMock()
        mock_result_ok.differences = []

        mock_result_diff = MagicMock()
        mock_result_diff.differences = ["diff1", "diff2"]

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_directory.return_value = [mock_result_ok, mock_result_diff]

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"
            ):
                result = differential.run_test_dir(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Files with differences: 1" in captured.out
        assert "Total differences: 2" in captured.out

    def test_run_test_dir_with_output_json(self, temp_dir, capsys):
        """Test batch testing with JSON output."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()
        (input_dir / "test.dcm").write_bytes(b"\x00" * 100)
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            test_dir=str(input_dir),
            output=str(output_dir),
            format="json",
            verbose=False,
        )

        mock_result = MagicMock()
        mock_result.differences = []

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_directory.return_value = [mock_result]

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"
            ):
                result = differential.run_test_dir(args)

        assert result == 0
        report_files = list(output_dir.glob("diff_batch.json"))
        assert len(report_files) == 1

    def test_run_test_dir_import_error(self, temp_dir, capsys):
        """Test handling of import error."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()

        args = argparse.Namespace(
            test_dir=str(input_dir),
            output=None,
            format="text",
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
            side_effect=ImportError("Module not found"),
        ):
            result = differential.run_test_dir(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not available" in captured.out


class TestRunListParsers:
    """Test run_list_parsers function."""

    def test_list_parsers_output(self, capsys):
        """Test list parsers displays all parsers."""
        args = argparse.Namespace()

        with patch("importlib.util.find_spec") as mock_find:
            mock_find.return_value = MagicMock()  # Module found
            with patch("shutil.which", return_value="/usr/bin/dcmdump"):
                result = differential.run_list_parsers(args)

        assert result == 0
        captured = capsys.readouterr()

        # Verify parsers are listed
        assert "pydicom" in captured.out
        assert "gdcm" in captured.out
        assert "dcmtk" in captured.out

        # Verify languages
        assert "Python" in captured.out
        assert "C++" in captured.out

    def test_list_parsers_not_installed(self, capsys):
        """Test list parsers shows not installed status."""
        args = argparse.Namespace()

        with patch("importlib.util.find_spec", return_value=None):
            with patch("shutil.which", return_value=None):
                result = differential.run_list_parsers(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Not installed" in captured.out

    def test_list_parsers_exception(self, capsys):
        """Test list parsers handles exceptions."""
        args = argparse.Namespace()

        with patch("importlib.util.find_spec", side_effect=Exception("Error")):
            result = differential.run_list_parsers(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Not installed" in captured.out


class TestMain:
    """Test main function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_main_test(self, temp_dir):
        """Test main with --test."""
        input_file = temp_dir / "test.dcm"
        input_file.write_bytes(b"\x00" * 100)

        with patch.object(differential, "run_test", return_value=0) as mock_run:
            result = differential.main(["--test", str(input_file)])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_test_dir(self, temp_dir):
        """Test main with --test-dir."""
        with patch.object(differential, "run_test_dir", return_value=0) as mock_run:
            result = differential.main(["--test-dir", str(temp_dir)])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_list_parsers(self):
        """Test main with --list-parsers."""
        with patch.object(differential, "run_list_parsers", return_value=0) as mock_run:
            result = differential.main(["--list-parsers"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_no_args(self):
        """Test main with no arguments shows help."""
        with pytest.raises(SystemExit) as exc_info:
            differential.main([])

        assert exc_info.value.code != 0

    def test_main_none_argv(self):
        """Test main with None argv uses sys.argv."""
        with patch("sys.argv", ["differential", "--list-parsers"]):
            with patch.object(
                differential, "run_list_parsers", return_value=0
            ) as mock_run:
                result = differential.main(None)

        assert result == 0
        mock_run.assert_called_once()
