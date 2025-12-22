"""Tests for samples CLI subcommand.

Tests for dicom_fuzzer.cli.samples module.
Note: Some functionality depends on optional external 'samples.*' packages.
Tests for those are skipped if the modules are not available.
"""

import argparse
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli import samples


class TestConstants:
    """Test module constants."""

    def test_sample_sources(self):
        """Test SAMPLE_SOURCES contains expected sources."""
        assert "rubo" in samples.SAMPLE_SOURCES
        assert "osirix" in samples.SAMPLE_SOURCES
        assert "dicom_library" in samples.SAMPLE_SOURCES
        assert "tcia" in samples.SAMPLE_SOURCES

        # Verify structure
        for source in samples.SAMPLE_SOURCES.values():
            assert "name" in source
            assert "url" in source
            assert "description" in source

    def test_supported_modalities(self):
        """Test SUPPORTED_MODALITIES contains expected modalities."""
        assert "CT" in samples.SUPPORTED_MODALITIES
        assert "MR" in samples.SUPPORTED_MODALITIES
        assert "US" in samples.SUPPORTED_MODALITIES
        assert "CR" in samples.SUPPORTED_MODALITIES


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created with required arguments."""
        parser = samples.create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_generate_action(self):
        """Test --generate argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--generate"])
        assert args.generate is True

    def test_parser_list_sources_action(self):
        """Test --list-sources argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--list-sources"])
        assert args.list_sources is True

    def test_parser_malicious_action(self):
        """Test --malicious argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--malicious"])
        assert args.malicious is True

    def test_parser_preamble_attacks_action(self):
        """Test --preamble-attacks argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--preamble-attacks"])
        assert args.preamble_attacks is True

    def test_parser_cve_samples_action(self):
        """Test --cve-samples argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--cve-samples"])
        assert args.cve_samples is True

    def test_parser_parser_stress_action(self):
        """Test --parser-stress argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--parser-stress"])
        assert args.parser_stress is True

    def test_parser_compliance_action(self):
        """Test --compliance argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--compliance"])
        assert args.compliance is True

    def test_parser_scan_action(self):
        """Test --scan argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--scan", "./files"])
        assert args.scan == "./files"

    def test_parser_sanitize_action(self):
        """Test --sanitize argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--sanitize", "file.dcm"])
        assert args.sanitize == "file.dcm"

    def test_parser_strip_pixel_data_action(self):
        """Test --strip-pixel-data argument."""
        parser = samples.create_parser()
        args = parser.parse_args(["--strip-pixel-data", "./corpus"])
        assert args.strip_pixel_data == "./corpus"

    def test_parser_mutually_exclusive(self):
        """Test that actions are mutually exclusive."""
        parser = samples.create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--generate", "--malicious"])

    def test_parser_generation_options(self):
        """Test generation options."""
        parser = samples.create_parser()
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
        assert args.output == "./output"
        assert args.modality == "CT"
        assert args.series is True
        assert args.rows == 512
        assert args.columns == 512
        assert args.seed == 42
        assert args.verbose is True

    def test_parser_malicious_options(self):
        """Test malicious sample options."""
        parser = samples.create_parser()
        args = parser.parse_args(["--parser-stress", "--depth", "200"])
        assert args.depth == 200

    def test_parser_scan_options(self):
        """Test scanning options."""
        parser = samples.create_parser()
        args = parser.parse_args(["--scan", "./files", "--json", "--recursive"])
        assert args.json is True
        assert args.recursive is True

    def test_parser_defaults(self):
        """Test default values."""
        parser = samples.create_parser()
        args = parser.parse_args(["--generate"])
        assert args.count == 10
        assert args.output == "./samples"
        assert args.modality is None
        assert args.series is False
        assert args.rows == 256
        assert args.columns == 256
        assert args.seed is None
        assert args.verbose is False
        assert args.depth == 100


class TestRunGenerate:
    """Test run_generate function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_generate_basic(self, temp_dir, capsys):
        """Test basic generation."""
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            count=3,
            output=str(output_dir),
            modality=None,
            series=False,
            rows=256,
            columns=256,
            seed=None,
            verbose=False,
        )

        mock_generator = MagicMock()
        mock_files = [output_dir / f"test_{i}.dcm" for i in range(3)]
        mock_generator.generate_batch.return_value = mock_files

        with patch.object(
            samples, "SyntheticDicomGenerator", return_value=mock_generator
        ):
            result = samples.run_generate(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Synthetic Sample Generation" in captured.out
        assert "Generated 3 synthetic DICOM files" in captured.out

    def test_run_generate_series(self, temp_dir, capsys):
        """Test series generation."""
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            count=5,
            output=str(output_dir),
            modality="MR",
            series=True,
            rows=128,
            columns=128,
            seed=42,
            verbose=False,
        )

        mock_generator = MagicMock()
        mock_files = [output_dir / f"slice_{i}.dcm" for i in range(5)]
        mock_generator.generate_series.return_value = mock_files

        with patch.object(
            samples, "SyntheticDicomGenerator", return_value=mock_generator
        ):
            result = samples.run_generate(args)

        assert result == 0
        mock_generator.generate_series.assert_called_once()
        captured = capsys.readouterr()
        assert "Series (consistent UIDs)" in captured.out

    def test_run_generate_verbose(self, temp_dir, capsys):
        """Test generation with verbose output."""
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            count=3,
            output=str(output_dir),
            modality="CT",
            series=False,
            rows=256,
            columns=256,
            seed=None,
            verbose=True,
        )

        mock_generator = MagicMock()
        mock_files = [Path(output_dir / f"file_{i}.dcm") for i in range(3)]
        mock_generator.generate_batch.return_value = mock_files

        with patch.object(
            samples, "SyntheticDicomGenerator", return_value=mock_generator
        ):
            result = samples.run_generate(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Generated files:" in captured.out

    def test_run_generate_exception(self, temp_dir, capsys):
        """Test generation handles exceptions."""
        args = argparse.Namespace(
            count=1,
            output=str(temp_dir / "output"),
            modality=None,
            series=False,
            rows=256,
            columns=256,
            seed=None,
            verbose=False,
        )

        mock_generator = MagicMock()
        mock_generator.generate_batch.side_effect = RuntimeError("Generation error")

        with patch.object(
            samples,
            "SyntheticDicomGenerator",
            return_value=mock_generator,
        ):
            result = samples.run_generate(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Generation failed" in captured.out


class TestRunListSources:
    """Test run_list_sources function."""

    def test_list_sources_output(self, capsys):
        """Test list sources displays all sources."""
        args = argparse.Namespace()

        result = samples.run_list_sources(args)

        assert result == 0
        captured = capsys.readouterr()

        # Verify sources are listed
        for key in samples.SAMPLE_SOURCES.keys():
            assert key in captured.out

        # Verify includes URL and description
        assert "http" in captured.out
        assert "Note:" in captured.out


# Tests for optional modules - these test the error handling paths
# when the external 'samples.*' packages are not installed


class TestRunMalicious:
    """Test run_malicious function (tests error handling)."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_malicious_module_not_found(self, temp_dir, capsys):
        """Test malicious generation when samples modules not available."""
        args = argparse.Namespace(
            output=str(temp_dir / "malicious"),
            verbose=False,
        )

        # Without mocking, the imports will fail naturally if modules aren't installed
        result = samples.run_malicious(args)

        # Should handle the error gracefully
        captured = capsys.readouterr()
        assert "Malicious Sample Generation" in captured.out


class TestRunPreambleAttacks:
    """Test run_preamble_attacks function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_preamble_attacks_module_not_found(self, temp_dir, capsys):
        """Test preamble attack generation when modules not available."""
        args = argparse.Namespace(output=str(temp_dir / "attacks"))

        result = samples.run_preamble_attacks(args)

        # Should return 1 when module not found
        captured = capsys.readouterr()
        assert "Preamble Attack Sample Generation" in captured.out


class TestRunCveSamples:
    """Test run_cve_samples function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_cve_samples_module_not_found(self, temp_dir, capsys):
        """Test CVE sample generation when modules not available."""
        args = argparse.Namespace(output=str(temp_dir / "cves"))

        result = samples.run_cve_samples(args)

        # Should handle missing module gracefully
        captured = capsys.readouterr()
        assert "CVE Reproduction Sample Generation" in captured.out


class TestRunParserStress:
    """Test run_parser_stress function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_parser_stress_module_not_found(self, temp_dir, capsys):
        """Test parser stress generation when modules not available."""
        args = argparse.Namespace(output=str(temp_dir / "stress"))

        result = samples.run_parser_stress(args)

        captured = capsys.readouterr()
        assert "Parser Stress Sample Generation" in captured.out


class TestRunCompliance:
    """Test run_compliance function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_compliance_module_not_found(self, temp_dir, capsys):
        """Test compliance violation generation when modules not available."""
        args = argparse.Namespace(output=str(temp_dir / "compliance"))

        result = samples.run_compliance(args)

        captured = capsys.readouterr()
        assert "Compliance Violation Sample Generation" in captured.out


class TestRunScan:
    """Test run_scan function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_scan_path_not_found(self, capsys):
        """Test scan with nonexistent path."""
        args = argparse.Namespace(
            scan="/nonexistent/path",
            json=False,
            recursive=False,
        )

        result = samples.run_scan(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_scan_module_not_found(self, temp_dir, capsys):
        """Test scan when scanner module not available."""
        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"\x00" * 132 + b"DICM")

        args = argparse.Namespace(
            scan=str(test_file),
            json=False,
            recursive=False,
        )

        result = samples.run_scan(args)

        captured = capsys.readouterr()
        assert "DICOM Security Scanner" in captured.out


class TestRunSanitize:
    """Test run_sanitize function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_sanitize_file_not_found(self, capsys):
        """Test sanitize with nonexistent file."""
        args = argparse.Namespace(sanitize="/nonexistent/file.dcm")

        result = samples.run_sanitize(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_sanitize_not_file(self, temp_dir, capsys):
        """Test sanitize with directory."""
        args = argparse.Namespace(sanitize=str(temp_dir))

        result = samples.run_sanitize(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "requires a single file" in captured.out

    def test_run_sanitize_module_not_found(self, temp_dir, capsys):
        """Test sanitize when sanitizer module not available."""
        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"MZ" + b"\x00" * 130 + b"DICM")

        args = argparse.Namespace(sanitize=str(test_file))

        result = samples.run_sanitize(args)

        captured = capsys.readouterr()
        assert "DICOM Preamble Sanitizer" in captured.out


class TestRunStripPixelData:
    """Test run_strip_pixel_data function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_strip_pixel_data_not_found(self, capsys):
        """Test strip with nonexistent path."""
        args = argparse.Namespace(
            strip_pixel_data="/nonexistent/path",
            output="./output",
            verbose=False,
        )

        result = samples.run_strip_pixel_data(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_strip_pixel_data_file(self, temp_dir, capsys):
        """Test stripping single file."""
        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"\x00" * 1000)
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            strip_pixel_data=str(test_file),
            output=str(output_dir),
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.utils.corpus_minimization.strip_pixel_data"
        ) as mock_strip:
            mock_strip.return_value = (True, 500)

            # Mock the output file to exist after strip
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / test_file.name).write_bytes(b"\x00" * 500)

            result = samples.run_strip_pixel_data(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Stripped" in captured.out

    def test_run_strip_pixel_data_exception(self, temp_dir, capsys):
        """Test strip handles exceptions."""
        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            strip_pixel_data=str(test_file),
            output=str(temp_dir / "output"),
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.utils.corpus_minimization.strip_pixel_data",
            side_effect=RuntimeError("Error"),
        ):
            result = samples.run_strip_pixel_data(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Optimization failed" in captured.out


class TestMain:
    """Test main function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_main_generate(self):
        """Test main with --generate."""
        with patch.object(samples, "run_generate", return_value=0) as mock_run:
            result = samples.main(["--generate"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_list_sources(self):
        """Test main with --list-sources."""
        with patch.object(samples, "run_list_sources", return_value=0) as mock_run:
            result = samples.main(["--list-sources"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_malicious(self):
        """Test main with --malicious."""
        with patch.object(samples, "run_malicious", return_value=0) as mock_run:
            result = samples.main(["--malicious"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_preamble_attacks(self):
        """Test main with --preamble-attacks."""
        with patch.object(samples, "run_preamble_attacks", return_value=0) as mock_run:
            result = samples.main(["--preamble-attacks"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_cve_samples(self):
        """Test main with --cve-samples."""
        with patch.object(samples, "run_cve_samples", return_value=0) as mock_run:
            result = samples.main(["--cve-samples"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_parser_stress(self):
        """Test main with --parser-stress."""
        with patch.object(samples, "run_parser_stress", return_value=0) as mock_run:
            result = samples.main(["--parser-stress"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_compliance(self):
        """Test main with --compliance."""
        with patch.object(samples, "run_compliance", return_value=0) as mock_run:
            result = samples.main(["--compliance"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_scan(self):
        """Test main with --scan."""
        with patch.object(samples, "run_scan", return_value=0) as mock_run:
            result = samples.main(["--scan", "./files"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_sanitize(self):
        """Test main with --sanitize."""
        with patch.object(samples, "run_sanitize", return_value=0) as mock_run:
            result = samples.main(["--sanitize", "file.dcm"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_strip_pixel_data(self):
        """Test main with --strip-pixel-data."""
        with patch.object(samples, "run_strip_pixel_data", return_value=0) as mock_run:
            result = samples.main(["--strip-pixel-data", "./corpus"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_no_args(self):
        """Test main with no arguments shows help."""
        with pytest.raises(SystemExit) as exc_info:
            samples.main([])

        assert exc_info.value.code != 0

    def test_main_none_argv(self):
        """Test main with None argv uses sys.argv."""
        with patch("sys.argv", ["samples", "--list-sources"]):
            with patch.object(samples, "run_list_sources", return_value=0) as mock_run:
                result = samples.main(None)

        assert result == 0
        mock_run.assert_called_once()
