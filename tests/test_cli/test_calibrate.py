"""
Tests for calibrate.py - Calibration Mutation CLI Subcommand.

Tests cover argument parsing, category listing, and mutation execution.
"""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.calibrate import (
    create_parser,
    main,
    run_calibration_mutation,
    run_list_categories,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_defaults(self):
        """Test default argument values."""
        parser = create_parser()
        args = parser.parse_args(["--list-categories"])

        assert args.list_categories is True
        assert args.category == "all"
        assert args.count == 10
        assert args.severity == "moderate"
        assert args.output == "./artifacts/calibrate"
        assert args.verbose is False

    def test_parser_with_input_file(self):
        """Test parser with input file argument."""
        parser = create_parser()
        args = parser.parse_args(["--input", "test.dcm"])

        assert args.input == "test.dcm"
        assert args.list_categories is False

    def test_parser_all_category_choices(self):
        """Test all valid category choices."""
        parser = create_parser()

        valid_categories = [
            "pixel-spacing",
            "hounsfield",
            "window-level",
            "slice-thickness",
            "all",
        ]

        for category in valid_categories:
            args = parser.parse_args(["--input", "test.dcm", "--category", category])
            assert args.category == category

    def test_parser_all_severity_choices(self):
        """Test all valid severity choices."""
        parser = create_parser()

        valid_severities = ["minimal", "moderate", "aggressive", "extreme"]

        for severity in valid_severities:
            args = parser.parse_args(["--input", "test.dcm", "--severity", severity])
            assert args.severity == severity

    def test_parser_mutually_exclusive(self):
        """Test that --input and --list-categories are mutually exclusive."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args(["--input", "test.dcm", "--list-categories"])

    def test_parser_requires_action(self):
        """Test that either --input or --list-categories is required."""
        parser = create_parser()

        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_custom_count(self):
        """Test custom count argument."""
        parser = create_parser()
        args = parser.parse_args(["--input", "test.dcm", "-c", "50"])

        assert args.count == 50

    def test_parser_custom_output(self):
        """Test custom output directory."""
        parser = create_parser()
        args = parser.parse_args(["--input", "test.dcm", "-o", "/custom/path"])

        assert args.output == "/custom/path"

    def test_parser_verbose_flag(self):
        """Test verbose flag."""
        parser = create_parser()
        args = parser.parse_args(["--input", "test.dcm", "-v"])

        assert args.verbose is True


class TestRunListCategories:
    """Test run_list_categories function."""

    def test_returns_zero(self, capsys):
        """Test that function returns 0 on success."""
        result = run_list_categories()

        assert result == 0

    def test_prints_categories(self, capsys):
        """Test that function prints category information."""
        run_list_categories()

        captured = capsys.readouterr()
        output = captured.out

        # Check for category names
        assert "pixel-spacing" in output
        assert "hounsfield" in output
        assert "window-level" in output
        assert "slice-thickness" in output

    def test_prints_attack_types(self, capsys):
        """Test that function prints attack type details."""
        run_list_categories()

        captured = capsys.readouterr()
        output = captured.out

        # Check for some attack types
        assert "overflow" in output.lower() or "zero" in output.lower()

    def test_prints_header(self, capsys):
        """Test that function prints header."""
        run_list_categories()

        captured = capsys.readouterr()
        output = captured.out

        assert "DICOM Fuzzer" in output
        assert "Calibration" in output


class TestRunCalibrationMutation:
    """Test run_calibration_mutation function."""

    def test_file_not_found(self, tmp_path, capsys):
        """Test error handling when input file doesn't exist."""
        args = argparse.Namespace(
            input=str(tmp_path / "nonexistent.dcm"),
            category="all",
            severity="moderate",
            count=5,
            output=str(tmp_path / "output"),
            verbose=False,
        )

        result = run_calibration_mutation(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()

    def test_successful_mutation_with_mocks(self, tmp_path):
        """Test successful mutation execution with mocked dependencies."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"fake dicom")

        # Create mock objects
        mock_ds = MagicMock()
        mock_ds.PatientName = "Test^Patient"
        mock_ds.copy.return_value = mock_ds

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_pixel_spacing.return_value = (mock_ds, [])
        mock_fuzzer.fuzz_hounsfield_rescale.return_value = (mock_ds, [])
        mock_fuzzer.fuzz_window_level.return_value = (mock_ds, [])
        mock_fuzzer.fuzz_slice_thickness.return_value = (mock_ds, [])

        # Patch at the point of import
        with (
            patch.dict(
                "sys.modules",
                {
                    "pydicom": MagicMock(
                        dcmread=MagicMock(return_value=mock_ds),
                        dcmwrite=MagicMock(),
                    ),
                },
            ),
            patch(
                "dicom_fuzzer.attacks.format.calibration_fuzzer.CalibrationFuzzer",
                return_value=mock_fuzzer,
            ),
        ):
            args = argparse.Namespace(
                input=str(input_file),
                category="all",
                severity="moderate",
                count=2,
                output=str(tmp_path / "output"),
                verbose=False,
            )

            result = run_calibration_mutation(args)

            assert result == 0

    def test_single_category_mutation(self, tmp_path):
        """Test mutation with single category."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"fake dicom")

        mock_ds = MagicMock()
        mock_ds.PatientName = "Test"
        mock_ds.copy.return_value = mock_ds

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_pixel_spacing.return_value = (mock_ds, [])

        with (
            patch.dict(
                "sys.modules",
                {
                    "pydicom": MagicMock(
                        dcmread=MagicMock(return_value=mock_ds),
                        dcmwrite=MagicMock(),
                    ),
                },
            ),
            patch(
                "dicom_fuzzer.attacks.format.calibration_fuzzer.CalibrationFuzzer",
                return_value=mock_fuzzer,
            ),
        ):
            args = argparse.Namespace(
                input=str(input_file),
                category="pixel-spacing",
                severity="extreme",
                count=1,
                output=str(tmp_path / "output"),
                verbose=False,
            )

            result = run_calibration_mutation(args)

            assert result == 0
            mock_fuzzer.fuzz_pixel_spacing.assert_called()
            mock_fuzzer.fuzz_hounsfield_rescale.assert_not_called()

    def test_verbose_output(self, tmp_path, capsys):
        """Test verbose mode prints mutation details."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"fake dicom")

        mock_ds = MagicMock()
        mock_ds.PatientName = "Test"
        mock_ds.copy.return_value = mock_ds

        mock_record = MagicMock()
        mock_record.attack_type = "zero"
        mock_record.original_value = "1.0"
        mock_record.mutated_value = "0.0"

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_pixel_spacing.return_value = (mock_ds, [mock_record])

        with (
            patch.dict(
                "sys.modules",
                {
                    "pydicom": MagicMock(
                        dcmread=MagicMock(return_value=mock_ds),
                        dcmwrite=MagicMock(),
                    ),
                },
            ),
            patch(
                "dicom_fuzzer.attacks.format.calibration_fuzzer.CalibrationFuzzer",
                return_value=mock_fuzzer,
            ),
        ):
            args = argparse.Namespace(
                input=str(input_file),
                category="pixel-spacing",
                severity="moderate",
                count=1,
                output=str(tmp_path / "output"),
                verbose=True,
            )

            run_calibration_mutation(args)

            captured = capsys.readouterr()
            assert "zero" in captured.out or "0.0" in captured.out

    def test_creates_output_directory(self, tmp_path):
        """Test that output directory is created."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"fake dicom")
        output_dir = tmp_path / "nested" / "output"

        mock_ds = MagicMock()
        mock_ds.PatientName = "Test"
        mock_ds.copy.return_value = mock_ds

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_pixel_spacing.return_value = (mock_ds, [])

        with (
            patch.dict(
                "sys.modules",
                {
                    "pydicom": MagicMock(
                        dcmread=MagicMock(return_value=mock_ds),
                        dcmwrite=MagicMock(),
                    ),
                },
            ),
            patch(
                "dicom_fuzzer.attacks.format.calibration_fuzzer.CalibrationFuzzer",
                return_value=mock_fuzzer,
            ),
        ):
            args = argparse.Namespace(
                input=str(input_file),
                category="pixel-spacing",
                severity="moderate",
                count=1,
                output=str(output_dir),
                verbose=False,
            )

            run_calibration_mutation(args)

            assert output_dir.exists()


class TestMain:
    """Test main entry point."""

    def test_main_list_categories(self, capsys):
        """Test main dispatches to list categories."""
        result = main(["--list-categories"])

        assert result == 0
        captured = capsys.readouterr()
        assert "pixel-spacing" in captured.out

    def test_main_returns_error_on_missing_file(self, tmp_path, capsys):
        """Test main returns error for missing file."""
        result = main(
            [
                "--input",
                str(tmp_path / "missing.dcm"),
                "-o",
                str(tmp_path / "out"),
            ]
        )

        assert result == 1

    def test_main_with_input(self, tmp_path):
        """Test main dispatches to calibration mutation."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"fake")

        mock_ds = MagicMock()
        mock_ds.PatientName = "Test"
        mock_ds.copy.return_value = mock_ds

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_pixel_spacing.return_value = (mock_ds, [])
        mock_fuzzer.fuzz_hounsfield_rescale.return_value = (mock_ds, [])
        mock_fuzzer.fuzz_window_level.return_value = (mock_ds, [])
        mock_fuzzer.fuzz_slice_thickness.return_value = (mock_ds, [])

        with (
            patch.dict(
                "sys.modules",
                {
                    "pydicom": MagicMock(
                        dcmread=MagicMock(return_value=mock_ds),
                        dcmwrite=MagicMock(),
                    ),
                },
            ),
            patch(
                "dicom_fuzzer.attacks.format.calibration_fuzzer.CalibrationFuzzer",
                return_value=mock_fuzzer,
            ),
        ):
            result = main(
                [
                    "--input",
                    str(input_file),
                    "-o",
                    str(tmp_path / "out"),
                    "-c",
                    "1",
                ]
            )

            assert result == 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_exception_during_mutation_is_skipped(self, tmp_path, capsys):
        """Test handling of exception during mutation - category is skipped."""
        input_file = tmp_path / "test.dcm"
        input_file.write_bytes(b"fake dicom")

        mock_ds = MagicMock()
        mock_ds.PatientName = "Test"
        mock_ds.copy.return_value = mock_ds

        mock_fuzzer = MagicMock()
        mock_fuzzer.fuzz_pixel_spacing.side_effect = Exception("Mutation failed")

        with (
            patch.dict(
                "sys.modules",
                {
                    "pydicom": MagicMock(
                        dcmread=MagicMock(return_value=mock_ds),
                        dcmwrite=MagicMock(),
                    ),
                },
            ),
            patch(
                "dicom_fuzzer.attacks.format.calibration_fuzzer.CalibrationFuzzer",
                return_value=mock_fuzzer,
            ),
        ):
            args = argparse.Namespace(
                input=str(input_file),
                category="pixel-spacing",
                severity="moderate",
                count=1,
                output=str(tmp_path / "output"),
                verbose=True,
            )

            # Should not raise, but skip the failed mutation
            result = run_calibration_mutation(args)

            # Returns 0 because exception is caught
            assert result == 0
