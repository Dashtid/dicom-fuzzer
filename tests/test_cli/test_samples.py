"""Tests for cli/samples.py - Samples Subcommand.

Tests cover argument parsing, sample generation, listing sources,
scanning, sanitizing, and all action handlers.
"""

from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.cli.samples import (
    SAMPLE_SOURCES,
    SUPPORTED_MODALITIES,
    create_parser,
    main,
    run_list_sources,
    run_sanitize,
    run_scan,
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


class TestSupportedModalities:
    """Test SUPPORTED_MODALITIES constant."""

    def test_modalities_defined(self):
        """Test that modalities are defined."""
        assert len(SUPPORTED_MODALITIES) > 0
        assert "CT" in SUPPORTED_MODALITIES
        assert "MR" in SUPPORTED_MODALITIES
        assert "US" in SUPPORTED_MODALITIES


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created."""
        parser = create_parser()
        assert parser is not None

    def test_generate_action(self):
        """Test --generate action."""
        parser = create_parser()
        args = parser.parse_args(["--generate", "-o", "./output"])
        assert args.generate is True
        assert args.output == "./output"

    def test_list_sources_action(self):
        """Test --list-sources action."""
        parser = create_parser()
        args = parser.parse_args(["--list-sources"])
        assert args.list_sources is True

    def test_malicious_action(self):
        """Test --malicious action."""
        parser = create_parser()
        args = parser.parse_args(["--malicious", "-o", "./output"])
        assert args.malicious is True

    def test_preamble_attacks_action(self):
        """Test --preamble-attacks action."""
        parser = create_parser()
        args = parser.parse_args(["--preamble-attacks", "-o", "./output"])
        assert args.preamble_attacks is True

    def test_cve_samples_action(self):
        """Test --cve-samples action."""
        parser = create_parser()
        args = parser.parse_args(["--cve-samples", "-o", "./output"])
        assert args.cve_samples is True

    def test_parser_stress_action(self):
        """Test --parser-stress action."""
        parser = create_parser()
        args = parser.parse_args(["--parser-stress", "-o", "./output"])
        assert args.parser_stress is True

    def test_compliance_action(self):
        """Test --compliance action."""
        parser = create_parser()
        args = parser.parse_args(["--compliance", "-o", "./output"])
        assert args.compliance is True

    def test_scan_action(self):
        """Test --scan action."""
        parser = create_parser()
        args = parser.parse_args(["--scan", "./path"])
        assert args.scan == "./path"

    def test_sanitize_action(self):
        """Test --sanitize action."""
        parser = create_parser()
        args = parser.parse_args(["--sanitize", "./file.dcm"])
        assert args.sanitize == "./file.dcm"

    def test_strip_pixel_data_action(self):
        """Test --strip-pixel-data action."""
        parser = create_parser()
        args = parser.parse_args(["--strip-pixel-data", "./input", "-o", "./output"])
        assert args.strip_pixel_data == "./input"

    def test_generation_options(self):
        """Test generation options."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--generate",
                "-c",
                "20",
                "-o",
                "./output",
                "-m",
                "CT",
                "--series",
                "--rows",
                "512",
                "--columns",
                "512",
                "--seed",
                "42",
                "-v",
            ]
        )
        assert args.count == 20
        assert args.modality == "CT"
        assert args.series is True
        assert args.rows == 512
        assert args.columns == 512
        assert args.seed == 42
        assert args.verbose is True

    def test_malicious_options(self):
        """Test malicious sample options."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--malicious",
                "-o",
                "./output",
                "--depth",
                "200",
                "--base-dicom",
                "./base.dcm",
            ]
        )
        assert args.depth == 200
        assert args.base_dicom == "./base.dcm"

    def test_scanning_options(self):
        """Test scanning options."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--scan",
                "./path",
                "--json",
                "--recursive",
            ]
        )
        assert args.json is True
        assert args.recursive is True

    def test_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--generate", "--malicious"])

    def test_default_count(self):
        """Test default count value."""
        parser = create_parser()
        args = parser.parse_args(["--generate", "-o", "./output"])
        assert args.count == 10

    def test_default_output(self):
        """Test default output path."""
        parser = create_parser()
        args = parser.parse_args(["--generate"])
        assert args.output == "./artifacts/samples"

    def test_default_rows_columns(self):
        """Test default image dimensions."""
        parser = create_parser()
        args = parser.parse_args(["--generate"])
        assert args.rows == 256
        assert args.columns == 256

    def test_default_depth(self):
        """Test default nesting depth."""
        parser = create_parser()
        args = parser.parse_args(["--malicious", "-o", "./output"])
        assert args.depth == 100


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


class TestRunScan:
    """Test run_scan function."""

    def test_scan_path_not_found(self, tmp_path, capsys):
        """Test scanning nonexistent path."""
        args = MagicMock()
        args.scan = str(tmp_path / "nonexistent")

        result = run_scan(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestRunSanitize:
    """Test run_sanitize function."""

    def test_sanitize_file_not_found(self, tmp_path, capsys):
        """Test sanitizing nonexistent file."""
        args = MagicMock()
        args.sanitize = str(tmp_path / "nonexistent.dcm")

        result = run_sanitize(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_sanitize_directory_error(self, tmp_path, capsys):
        """Test error when trying to sanitize directory."""
        args = MagicMock()
        args.sanitize = str(tmp_path)

        result = run_sanitize(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "single file" in captured.out


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


class TestMainGenerate:
    """Test main with --generate using real generator."""

    def test_main_generate_synthetic(self, tmp_path, capsys):
        """Test synthetic generation creates files."""
        result = main(
            [
                "--generate",
                "-o",
                str(tmp_path),
                "-c",
                "3",
                "-m",
                "CT",
                "--rows",
                "32",
                "--columns",
                "32",
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "Generated" in captured.out

        # Verify files were created
        dcm_files = list(tmp_path.glob("*.dcm"))
        assert len(dcm_files) == 3

    def test_main_generate_series(self, tmp_path, capsys):
        """Test series generation."""
        result = main(
            [
                "--generate",
                "-o",
                str(tmp_path),
                "-c",
                "5",
                "-m",
                "MR",
                "--series",
                "--rows",
                "32",
                "--columns",
                "32",
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "Generated" in captured.out


class TestMainMalicious:
    """Test main with malicious sample generation."""

    def test_main_preamble_attacks(self, tmp_path, capsys):
        """Test preamble attack generation."""
        result = main(
            [
                "--preamble-attacks",
                "-o",
                str(tmp_path),
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "polyglot" in captured.out.lower()

    def test_main_cve_samples(self, tmp_path, capsys):
        """Test CVE sample generation."""
        result = main(
            [
                "--cve-samples",
                "-o",
                str(tmp_path),
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "CVE" in captured.out

    def test_main_parser_stress(self, tmp_path, capsys):
        """Test parser stress generation."""
        result = main(
            [
                "--parser-stress",
                "-o",
                str(tmp_path),
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "stress" in captured.out.lower()

    def test_main_compliance(self, tmp_path, capsys):
        """Test compliance violation generation."""
        result = main(
            [
                "--compliance",
                "-o",
                str(tmp_path),
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "compliance" in captured.out.lower() or "Generated" in captured.out

    def test_main_malicious_all(self, tmp_path, capsys):
        """Test all malicious samples generation."""
        result = main(
            [
                "--malicious",
                "-o",
                str(tmp_path),
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "Malicious Sample Generation" in captured.out
