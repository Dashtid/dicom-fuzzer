"""Tests for differential.py - Cross-parser differential testing CLI.

Tests cover argument parsing, test execution, parser listing, and main dispatch.
"""

import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.differential import (
    create_parser,
    main,
    run_list_parsers,
    run_test,
    run_test_dir,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_defaults(self):
        """Test parser with --list-parsers (minimal required arg)."""
        parser = create_parser()
        args = parser.parse_args(["--list-parsers"])

        assert args.list_parsers is True
        assert args.test is None
        assert args.test_dir is None
        assert args.output is None
        assert args.format == "text"
        assert args.verbose is False

    def test_parser_test_file(self):
        """Test --test option."""
        parser = create_parser()
        args = parser.parse_args(["--test", "input.dcm"])

        assert args.test == "input.dcm"
        assert args.list_parsers is False
        assert args.test_dir is None

    def test_parser_test_dir(self):
        """Test --test-dir option."""
        parser = create_parser()
        args = parser.parse_args(["--test-dir", "./corpus"])

        assert args.test_dir == "./corpus"
        assert args.test is None
        assert args.list_parsers is False

    def test_parser_list_parsers(self):
        """Test --list-parsers flag."""
        parser = create_parser()
        args = parser.parse_args(["--list-parsers"])

        assert args.list_parsers is True

    def test_parser_mutually_exclusive(self):
        """Test that --test, --test-dir, --list-parsers are mutually exclusive."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["--test", "file.dcm", "--list-parsers"])

        with pytest.raises(SystemExit):
            parser.parse_args(["--test", "file.dcm", "--test-dir", "./dir"])

    def test_parser_output_options(self):
        """Test output options."""
        parser = create_parser()
        args = parser.parse_args(
            ["--test", "file.dcm", "-o", "/output", "--format", "json", "-v"]
        )

        assert args.output == "/output"
        assert args.format == "json"
        assert args.verbose is True

    def test_parser_format_choices(self):
        """Test valid format choices."""
        parser = create_parser()

        for fmt in ["json", "text"]:
            args = parser.parse_args(["--test", "file.dcm", "--format", fmt])
            assert args.format == fmt

    def test_parser_requires_action(self):
        """Test that one of the action args is required."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args([])


class TestRunTest:
    """Test run_test function."""

    def test_run_test_file_not_found(self, tmp_path, capsys):
        """Test with non-existent file."""
        args = argparse.Namespace(
            test=str(tmp_path / "nonexistent.dcm"),
            output=None,
            format="text",
            verbose=False,
        )

        result = run_test(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()

    def test_run_test_success_no_diffs(self, tmp_path, capsys):
        """Test successful run with no differences found."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        mock_result = MagicMock()
        mock_result.differences = []

        mock_fuzzer = MagicMock()
        mock_fuzzer.test_file.return_value = mock_result
        mock_fuzzer.get_statistics.return_value = {"files_tested": 1}

        with (
            patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
                return_value=mock_fuzzer,
            ),
            patch("dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"),
        ):
            args = argparse.Namespace(
                test=str(test_file),
                output=None,
                format="text",
                verbose=False,
            )

            result = run_test(args)

            assert result == 0
            captured = capsys.readouterr()
            assert "no differences" in captured.out.lower()

    def test_run_test_success_with_diffs(self, tmp_path, capsys):
        """Test successful run with differences found."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        mock_result = MagicMock()
        mock_result.differences = ["diff1", "diff2"]

        mock_fuzzer = MagicMock()
        mock_fuzzer.test_file.return_value = mock_result
        mock_fuzzer.get_statistics.return_value = {"files_tested": 1}

        with (
            patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
                return_value=mock_fuzzer,
            ),
            patch("dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"),
        ):
            args = argparse.Namespace(
                test=str(test_file),
                output=None,
                format="text",
                verbose=False,
            )

            result = run_test(args)

            assert result == 1  # Returns 1 when differences found
            captured = capsys.readouterr()
            assert "2 differences" in captured.out

    def test_run_test_saves_json_report(self, tmp_path, capsys):
        """Test that JSON report is saved when output specified."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")
        output_dir = tmp_path / "output"

        mock_result = MagicMock()
        mock_result.differences = ["diff1"]

        mock_fuzzer = MagicMock()
        mock_fuzzer.test_file.return_value = mock_result
        mock_fuzzer.get_statistics.return_value = {}

        with (
            patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
                return_value=mock_fuzzer,
            ),
            patch("dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"),
        ):
            args = argparse.Namespace(
                test=str(test_file),
                output=str(output_dir),
                format="json",
                verbose=False,
            )

            run_test(args)

            report_file = output_dir / "diff_test.json"
            assert report_file.exists()

            with open(report_file) as f:
                report = json.load(f)
            assert "differences" in report

    def test_run_test_saves_text_report(self, tmp_path, capsys):
        """Test that text report is saved when output specified."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")
        output_dir = tmp_path / "output"

        mock_result = MagicMock()
        mock_result.differences = ["diff1"]

        mock_fuzzer = MagicMock()
        mock_fuzzer.test_file.return_value = mock_result
        mock_fuzzer.get_statistics.return_value = {}

        with (
            patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
                return_value=mock_fuzzer,
            ),
            patch("dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"),
        ):
            args = argparse.Namespace(
                test=str(test_file),
                output=str(output_dir),
                format="text",
                verbose=False,
            )

            run_test(args)

            report_file = output_dir / "diff_test.text"
            assert report_file.exists()
            content = report_file.read_text()
            assert "Differences:" in content

    def test_run_test_import_error(self, tmp_path, capsys):
        """Test handling when differential fuzzer import fails."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        with (
            patch.dict(
                "sys.modules",
                {"dicom_fuzzer.core.differential_fuzzer": None},
            ),
            patch(
                "builtins.__import__",
                side_effect=ImportError("Module not available"),
            ),
        ):
            args = argparse.Namespace(
                test=str(test_file),
                output=None,
                format="text",
                verbose=False,
            )

            result = run_test(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "not available" in captured.out.lower()

    def test_run_test_exception(self, tmp_path, capsys):
        """Test handling of general exceptions."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        with (
            patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
                side_effect=Exception("Test error"),
            ),
            patch("dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"),
        ):
            args = argparse.Namespace(
                test=str(test_file),
                output=None,
                format="text",
                verbose=False,
            )

            result = run_test(args)

            assert result == 1
            captured = capsys.readouterr()
            assert "failed" in captured.out.lower()


class TestRunTestDir:
    """Test run_test_dir function."""

    def test_run_test_dir_not_found(self, tmp_path, capsys):
        """Test with non-existent directory."""
        args = argparse.Namespace(
            test_dir=str(tmp_path / "nonexistent"),
            output=None,
            format="text",
            verbose=False,
        )

        result = run_test_dir(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()

    def test_run_test_dir_success(self, tmp_path, capsys):
        """Test successful directory testing."""
        test_dir = tmp_path / "corpus"
        test_dir.mkdir()
        (test_dir / "test1.dcm").write_bytes(b"test1")
        (test_dir / "test2.dcm").write_bytes(b"test2")

        mock_result1 = MagicMock()
        mock_result1.differences = []
        mock_result2 = MagicMock()
        mock_result2.differences = ["diff1"]

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_directory.return_value = [mock_result1, mock_result2]

        with (
            patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
                return_value=mock_fuzzer,
            ),
            patch("dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"),
        ):
            args = argparse.Namespace(
                test_dir=str(test_dir),
                output=None,
                format="text",
                verbose=False,
            )

            result = run_test_dir(args)

            assert result == 1  # Has files with diffs
            captured = capsys.readouterr()
            assert "Tested 2 files" in captured.out

    def test_run_test_dir_saves_results(self, tmp_path, capsys):
        """Test that results are saved when output specified."""
        test_dir = tmp_path / "corpus"
        test_dir.mkdir()
        output_dir = tmp_path / "output"

        mock_result = MagicMock()
        mock_result.differences = []

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_directory.return_value = [mock_result]

        with (
            patch(
                "dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzer",
                return_value=mock_fuzzer,
            ),
            patch("dicom_fuzzer.core.differential_fuzzer.DifferentialFuzzerConfig"),
        ):
            args = argparse.Namespace(
                test_dir=str(test_dir),
                output=str(output_dir),
                format="json",
                verbose=False,
            )

            run_test_dir(args)

            report_file = output_dir / "diff_batch.json"
            assert report_file.exists()

    def test_run_test_dir_import_error(self, tmp_path, capsys):
        """Test handling when differential fuzzer import fails."""
        test_dir = tmp_path / "corpus"
        test_dir.mkdir()

        with (
            patch.dict(
                "sys.modules",
                {"dicom_fuzzer.core.differential_fuzzer": None},
            ),
            patch(
                "builtins.__import__",
                side_effect=ImportError("Module not available"),
            ),
        ):
            args = argparse.Namespace(
                test_dir=str(test_dir),
                output=None,
                format="text",
                verbose=False,
            )

            result = run_test_dir(args)

            assert result == 1


class TestRunListParsers:
    """Test run_list_parsers function."""

    def test_list_parsers_output(self, capsys):
        """Test that parser list is printed."""
        args = argparse.Namespace()

        result = run_list_parsers(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "pydicom" in captured.out.lower()
        assert "gdcm" in captured.out.lower()
        assert "dcmtk" in captured.out.lower()

    def test_list_parsers_pydicom_available(self, capsys):
        """Test that pydicom shows as available (since it's installed)."""
        args = argparse.Namespace()

        run_list_parsers(args)

        captured = capsys.readouterr()
        # pydicom should be available since it's a dependency
        assert "[+] pydicom" in captured.out

    def test_list_parsers_returns_zero(self):
        """Test that function always returns 0."""
        args = argparse.Namespace()

        result = run_list_parsers(args)

        assert result == 0

    def test_list_parsers_shows_installation_info(self, capsys):
        """Test that installation instructions are shown."""
        args = argparse.Namespace()

        run_list_parsers(args)

        captured = capsys.readouterr()
        assert "pip install" in captured.out


class TestMain:
    """Test main entry point."""

    def test_main_test_dispatch(self, tmp_path):
        """Test main dispatches to run_test."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        with patch(
            "dicom_fuzzer.cli.differential.run_test", return_value=0
        ) as mock_run:
            result = main(["--test", str(test_file)])

            mock_run.assert_called_once()
            assert result == 0

    def test_main_test_dir_dispatch(self, tmp_path):
        """Test main dispatches to run_test_dir."""
        test_dir = tmp_path / "corpus"
        test_dir.mkdir()

        with patch(
            "dicom_fuzzer.cli.differential.run_test_dir", return_value=0
        ) as mock_run:
            result = main(["--test-dir", str(test_dir)])

            mock_run.assert_called_once()
            assert result == 0

    def test_main_list_parsers_dispatch(self):
        """Test main dispatches to run_list_parsers."""
        with patch(
            "dicom_fuzzer.cli.differential.run_list_parsers", return_value=0
        ) as mock_run:
            result = main(["--list-parsers"])

            mock_run.assert_called_once()
            assert result == 0

    def test_main_no_args_shows_help(self, capsys):
        """Test that no args shows help and returns 1."""
        with pytest.raises(SystemExit) as exc_info:
            main([])

        # argparse exits with 2 for missing required args
        assert exc_info.value.code == 2
