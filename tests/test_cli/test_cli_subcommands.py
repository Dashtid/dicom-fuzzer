"""Tests for CLI Subcommands - study, calibrate, stress.

Tests argument parsing, help output, strategy listing, and basic execution paths.
"""

import argparse

import pytest


class TestStudySubcommand:
    """Test study CLI subcommand."""

    def test_create_parser(self):
        """Test study parser creation."""
        from dicom_fuzzer.cli.commands.study import create_parser

        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.prog == "dicom-fuzzer study"

    def test_list_strategies(self, capsys):
        """Test --list-strategies output."""
        from dicom_fuzzer.cli.commands.study import run_list_strategies

        result = run_list_strategies()
        assert result == 0

        captured = capsys.readouterr()
        assert "cross-series" in captured.out
        assert "frame-of-reference" in captured.out
        assert "patient-consistency" in captured.out
        assert "study-metadata" in captured.out
        assert "mixed-modality" in captured.out

    def test_main_list_strategies(self, capsys):
        """Test main() with --list-strategies."""
        from dicom_fuzzer.cli.commands.study import main

        result = main(["--list-strategies"])
        assert result == 0

    def test_main_no_args_shows_help(self, capsys):
        """Test main() with no args shows help."""
        from dicom_fuzzer.cli.commands.study import main

        with pytest.raises(SystemExit):
            main([])

    def test_parser_strategy_choices(self):
        """Test parser accepts valid strategies."""
        from dicom_fuzzer.cli.commands.study import create_parser

        parser = create_parser()
        args = parser.parse_args(["--study", "./test", "--strategy", "cross-series"])
        assert args.strategy == "cross-series"

    def test_parser_severity_choices(self):
        """Test parser accepts valid severity levels."""
        from dicom_fuzzer.cli.commands.study import create_parser

        parser = create_parser()

        for severity in ["minimal", "moderate", "aggressive", "extreme"]:
            args = parser.parse_args(["--study", "./test", "--severity", severity])
            assert args.severity == severity

    def test_parser_defaults(self):
        """Test parser default values."""
        from dicom_fuzzer.cli.commands.study import create_parser

        parser = create_parser()
        args = parser.parse_args(["--study", "./test"])

        assert args.strategy == "all"
        assert args.severity == "moderate"
        assert args.count == 5
        assert args.output == "./artifacts/study"
        assert args.verbose is False

    def test_run_study_mutation_missing_dir(self, capsys, tmp_path):
        """Test run_study_mutation with non-existent directory."""
        from dicom_fuzzer.cli.commands.study import create_parser, run_study_mutation

        parser = create_parser()
        args = parser.parse_args(
            ["--study", str(tmp_path / "nonexistent"), "-o", str(tmp_path / "out")]
        )

        result = run_study_mutation(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestCalibrateSubcommand:
    """Test calibrate CLI subcommand."""

    def test_create_parser(self):
        """Test calibrate parser creation."""
        from dicom_fuzzer.cli.commands.calibrate import create_parser

        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.prog == "dicom-fuzzer calibrate"

    def test_list_categories(self, capsys):
        """Test --list-categories output."""
        from dicom_fuzzer.cli.commands.calibrate import run_list_categories

        result = run_list_categories()
        assert result == 0

        captured = capsys.readouterr()
        assert "pixel-spacing" in captured.out
        assert "hounsfield" in captured.out
        assert "window-level" in captured.out
        assert "slice-thickness" in captured.out

    def test_main_list_categories(self, capsys):
        """Test main() with --list-categories."""
        from dicom_fuzzer.cli.commands.calibrate import main

        result = main(["--list-categories"])
        assert result == 0

    def test_main_no_args_shows_help(self, capsys):
        """Test main() with no args shows help."""
        from dicom_fuzzer.cli.commands.calibrate import main

        with pytest.raises(SystemExit):
            main([])

    def test_parser_category_choices(self):
        """Test parser accepts valid categories."""
        from dicom_fuzzer.cli.commands.calibrate import create_parser

        parser = create_parser()

        for category in [
            "pixel-spacing",
            "hounsfield",
            "window-level",
            "slice-thickness",
            "all",
        ]:
            args = parser.parse_args(["--input", "./test.dcm", "--category", category])
            assert args.category == category

    def test_parser_defaults(self):
        """Test parser default values."""
        from dicom_fuzzer.cli.commands.calibrate import create_parser

        parser = create_parser()
        args = parser.parse_args(["--input", "./test.dcm"])

        assert args.category == "all"
        assert args.count == 10
        assert args.output == "./artifacts/calibrate"
        assert args.verbose is False

    def test_run_calibration_missing_file(self, capsys, tmp_path):
        """Test run_calibration_mutation with non-existent file."""
        from dicom_fuzzer.cli.commands.calibrate import (
            create_parser,
            run_calibration_mutation,
        )

        parser = create_parser()
        args = parser.parse_args(
            ["--input", str(tmp_path / "nonexistent.dcm"), "-o", str(tmp_path / "out")]
        )

        result = run_calibration_mutation(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestStressSubcommand:
    """Test stress CLI subcommand."""

    def test_create_parser(self):
        """Test stress parser creation."""
        from dicom_fuzzer.cli.commands.stress import create_parser

        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.prog == "dicom-fuzzer stress"

    def test_list_scenarios(self, capsys):
        """Test --list-scenarios output."""
        from dicom_fuzzer.cli.commands.stress import run_list_scenarios

        result = run_list_scenarios()
        assert result == 0

        captured = capsys.readouterr()
        assert "Large Series" in captured.out
        assert "High Resolution" in captured.out
        assert "Memory Escalation" in captured.out

    def test_main_list_scenarios(self, capsys):
        """Test main() with --list-scenarios."""
        from dicom_fuzzer.cli.commands.stress import main

        result = main(["--list-scenarios"])
        assert result == 0

    def test_main_no_args_shows_help(self, capsys):
        """Test main() with no args shows help."""
        from dicom_fuzzer.cli.commands.stress import main

        with pytest.raises(SystemExit):
            main([])

    def test_parser_pattern_choices(self):
        """Test parser accepts valid patterns."""
        from dicom_fuzzer.cli.commands.stress import create_parser

        parser = create_parser()

        for pattern in ["gradient", "random", "anatomical"]:
            args = parser.parse_args(["--generate-series", "--pattern", pattern])
            assert args.pattern == pattern

    def test_parser_modality_choices(self):
        """Test parser accepts valid modalities."""
        from dicom_fuzzer.cli.commands.stress import create_parser

        parser = create_parser()

        for modality in ["CT", "MR", "PT"]:
            args = parser.parse_args(["--generate-series", "--modality", modality])
            assert args.modality == modality

    def test_parser_defaults(self):
        """Test parser default values."""
        from dicom_fuzzer.cli.commands.stress import create_parser

        parser = create_parser()
        args = parser.parse_args(["--generate-series"])

        assert args.slices == 100
        assert args.dimensions == "512x512"
        assert args.pattern == "gradient"
        assert args.modality == "CT"
        assert args.memory_limit == 4096
        assert args.output == "./artifacts/stress"
        assert args.verbose is False

    def test_parse_dimensions_valid(self):
        """Test dimension string parsing."""
        from dicom_fuzzer.cli.commands.stress import parse_dimensions

        assert parse_dimensions("512x512") == (512, 512)
        assert parse_dimensions("1024x768") == (1024, 768)
        assert parse_dimensions("256X256") == (256, 256)  # Case insensitive

    def test_parse_dimensions_invalid(self):
        """Test dimension string parsing with invalid input."""
        from dicom_fuzzer.cli.commands.stress import parse_dimensions

        with pytest.raises(ValueError, match="Invalid dimensions"):
            parse_dimensions("invalid")

        with pytest.raises(ValueError, match="Invalid dimensions"):
            parse_dimensions("512")

        with pytest.raises(ValueError, match="Invalid dimensions"):
            parse_dimensions("axb")


class TestOutputModule:
    """Test CLI output utilities."""

    def test_success_output(self, capsys):
        """Test success message output."""
        from dicom_fuzzer.cli.utils.output import success

        success("Test message")
        captured = capsys.readouterr()
        assert "[+]" in captured.out
        assert "Test message" in captured.out

    def test_error_output(self, capsys):
        """Test error message output."""
        from dicom_fuzzer.cli.utils.output import error

        error("Error message")
        captured = capsys.readouterr()
        assert "[-]" in captured.out
        assert "Error message" in captured.out

    def test_warning_output(self, capsys):
        """Test warning message output."""
        from dicom_fuzzer.cli.utils.output import warning

        warning("Warning message")
        captured = capsys.readouterr()
        assert "[!]" in captured.out
        assert "Warning message" in captured.out

    def test_info_output(self, capsys):
        """Test info message output."""
        from dicom_fuzzer.cli.utils.output import info

        info("Info message")
        captured = capsys.readouterr()
        assert "[i]" in captured.out
        assert "Info message" in captured.out

    def test_header_output(self, capsys):
        """Test header output."""
        from dicom_fuzzer.cli.utils.output import header

        header("Test Header", "Subtitle")
        captured = capsys.readouterr()
        assert "Test Header" in captured.out
        assert "Subtitle" in captured.out

    def test_section_output(self, capsys):
        """Test section output."""
        from dicom_fuzzer.cli.utils.output import section

        section("Section Title")
        captured = capsys.readouterr()
        assert "Section Title" in captured.out

    def test_detail_output(self, capsys):
        """Test detail output."""
        from dicom_fuzzer.cli.utils.output import detail

        detail("Label", "Value")
        captured = capsys.readouterr()
        assert "Label" in captured.out
        assert "Value" in captured.out

    def test_divider_output(self, capsys):
        """Test divider output."""
        from dicom_fuzzer.cli.utils.output import divider

        divider()
        captured = capsys.readouterr()
        assert "-" * 10 in captured.out  # At least 10 dashes

    def test_supports_color(self):
        """Test color support detection."""
        from dicom_fuzzer.cli.utils.output import supports_color

        # Should return a boolean
        result = supports_color()
        assert isinstance(result, bool)

    def test_table_row_simple(self, capsys):
        """Test simple table row."""
        from dicom_fuzzer.cli.utils.output import table_row

        table_row(["Col1", "Col2", "Col3"])
        captured = capsys.readouterr()
        assert "Col1" in captured.out
        assert "Col2" in captured.out
        assert "Col3" in captured.out

    def test_table_row_with_widths(self, capsys):
        """Test table row with widths."""
        from dicom_fuzzer.cli.utils.output import table_row

        table_row(["A", "B", "C"], [10, 10, 10])
        captured = capsys.readouterr()
        assert "A" in captured.out

    def test_print_summary(self, capsys):
        """Test summary panel output."""
        from dicom_fuzzer.cli.utils.output import print_summary

        stats = {
            "Total": 100,
            "Passed": 90,
            "Failed": 10,
        }
        print_summary("Test Summary", stats, success_count=90, error_count=10)
        captured = capsys.readouterr()
        assert "Test Summary" in captured.out
        assert "100" in captured.out


class TestStressTesterIntegration:
    """Integration tests for stress tester CLI."""

    def test_generate_series_creates_output(self, tmp_path, capsys):
        """Test generate-series creates files."""
        from dicom_fuzzer.cli.commands.stress import create_parser, run_generate_series

        output_dir = tmp_path / "stress_out"
        parser = create_parser()
        args = parser.parse_args(
            [
                "--generate-series",
                "--slices",
                "2",  # Minimal for speed
                "--dimensions",
                "64x64",
                "-o",
                str(output_dir),
            ]
        )

        result = run_generate_series(args)
        assert result == 0

        # Check files created
        assert output_dir.exists()
        dcm_files = list(output_dir.rglob("*.dcm"))
        assert len(dcm_files) == 2

    def test_generate_series_verbose(self, tmp_path, capsys):
        """Test generate-series with verbose output."""
        from dicom_fuzzer.cli.commands.stress import create_parser, run_generate_series

        output_dir = tmp_path / "stress_out"
        parser = create_parser()
        args = parser.parse_args(
            [
                "--generate-series",
                "--slices",
                "2",
                "--dimensions",
                "64x64",
                "-o",
                str(output_dir),
                "-v",
            ]
        )

        result = run_generate_series(args)
        assert result == 0


class TestCalibrationIntegration:
    """Integration tests for calibration CLI."""

    @pytest.fixture
    def sample_ct_file(self, tmp_path):
        """Create a sample CT DICOM file with calibration tags."""
        from pydicom.dataset import FileDataset, FileMetaDataset
        from pydicom.uid import UID

        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = UID("1.2.840.10008.5.1.4.1.1.2")
        file_meta.MediaStorageSOPInstanceUID = UID("1.2.3.4.5.6.7.8.9")
        file_meta.TransferSyntaxUID = UID("1.2.840.10008.1.2.1")

        filepath = tmp_path / "ct_sample.dcm"
        ds = FileDataset(
            str(filepath),
            {},
            file_meta=file_meta,
            preamble=b"\x00" * 128,
        )

        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.Modality = "CT"
        ds.PixelSpacing = [0.5, 0.5]
        ds.RescaleSlope = 1.0
        ds.RescaleIntercept = -1024.0
        ds.WindowCenter = 40
        ds.WindowWidth = 400
        ds.SliceThickness = 5.0

        ds.save_as(str(filepath))
        return filepath

    def test_run_calibration_with_file(self, sample_ct_file, tmp_path, capsys):
        """Test calibration with actual DICOM file."""
        from dicom_fuzzer.cli.commands.calibrate import (
            create_parser,
            run_calibration_mutation,
        )

        output_dir = tmp_path / "calibrate_out"
        parser = create_parser()
        args = parser.parse_args(
            [
                "--input",
                str(sample_ct_file),
                "--category",
                "pixel-spacing",
                "-c",
                "1",
                "-o",
                str(output_dir),
            ]
        )

        result = run_calibration_mutation(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "generated" in captured.out.lower() or "mutated" in captured.out.lower()
