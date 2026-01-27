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

    def test_parser_defaults(self):
        """Test default values."""
        parser = samples.create_parser()
        args = parser.parse_args(["--generate"])
        assert args.count == 10
        assert args.output == "./artifacts/samples"
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


class TestGeneratePreambleAttacks:
    """Test _generate_preamble_attacks helper function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_generate_preamble_attacks_success(self, temp_dir, capsys):
        """Test successful preamble attack generation."""
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        mock_gen = MagicMock()
        mock_gen.create_pe_dicom.return_value = output_dir / "pe.dcm"
        mock_gen.create_elf_dicom.return_value = output_dir / "elf.dcm"

        with patch(
            "dicom_fuzzer.generators.preamble_attacks.generator.PreambleAttackGenerator",
            return_value=mock_gen,
        ):
            count, error = samples._generate_preamble_attacks(output_dir, verbose=True)

        assert count == 2
        assert error is None
        captured = capsys.readouterr()
        assert "Preamble attacks: 2 samples" in captured.out

    def test_generate_preamble_attacks_partial_success(self, temp_dir, capsys):
        """Test partial success (only one polyglot generated)."""
        output_dir = temp_dir / "output"
        output_dir.mkdir()

        mock_gen = MagicMock()
        mock_gen.create_pe_dicom.return_value = output_dir / "pe.dcm"
        mock_gen.create_elf_dicom.return_value = None  # Failed

        with patch(
            "dicom_fuzzer.generators.preamble_attacks.generator.PreambleAttackGenerator",
            return_value=mock_gen,
        ):
            count, error = samples._generate_preamble_attacks(output_dir, verbose=False)

        assert count == 1
        assert error is None

    def test_generate_preamble_attacks_exception(self, temp_dir, capsys):
        """Test exception handling."""
        with patch(
            "dicom_fuzzer.generators.preamble_attacks.generator.PreambleAttackGenerator",
            side_effect=RuntimeError("Import failed"),
        ):
            count, error = samples._generate_preamble_attacks(temp_dir, verbose=False)

        assert count == 0
        assert "Import failed" in error


class TestGenerateCveSamples:
    """Test _generate_cve_samples helper function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_generate_cve_samples_success(self, temp_dir, capsys):
        """Test successful CVE sample generation."""
        mock_gen = MagicMock()
        mock_gen.generate_all.return_value = {
            "CVE-2024-0001": temp_dir / "cve1.dcm",
            "CVE-2024-0002": temp_dir / "cve2.dcm",
            "CVE-2024-0003": None,  # Failed
        }

        with patch(
            "dicom_fuzzer.generators.cve_reproductions.generator.CVESampleGenerator",
            return_value=mock_gen,
        ):
            count, error = samples._generate_cve_samples(temp_dir, verbose=True)

        assert count == 2
        assert error is None
        captured = capsys.readouterr()
        assert "CVE reproductions: 2 samples" in captured.out

    def test_generate_cve_samples_exception(self, temp_dir, capsys):
        """Test exception handling."""
        with patch(
            "dicom_fuzzer.generators.cve_reproductions.generator.CVESampleGenerator",
            side_effect=RuntimeError("CVE gen failed"),
        ):
            count, error = samples._generate_cve_samples(temp_dir, verbose=False)

        assert count == 0
        assert "CVE gen failed" in error


class TestGenerateParserStress:
    """Test _generate_parser_stress helper function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_generate_parser_stress_success(self, temp_dir, capsys):
        """Test successful parser stress generation."""
        mock_gen = MagicMock()
        mock_gen.generate_all.return_value = {
            "deep_nesting": temp_dir / "deep.dcm",
            "truncated": temp_dir / "trunc.dcm",
        }

        with patch(
            "dicom_fuzzer.generators.parser_stress.generator.ParserStressGenerator",
            return_value=mock_gen,
        ):
            count, error = samples._generate_parser_stress(temp_dir, verbose=True)

        assert count == 2
        assert error is None

    def test_generate_parser_stress_exception(self, temp_dir, capsys):
        """Test exception handling."""
        with patch(
            "dicom_fuzzer.generators.parser_stress.generator.ParserStressGenerator",
            side_effect=RuntimeError("Stress gen failed"),
        ):
            count, error = samples._generate_parser_stress(temp_dir, verbose=False)

        assert count == 0
        assert "Stress gen failed" in error


class TestGenerateComplianceViolations:
    """Test _generate_compliance_violations helper function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_generate_compliance_violations_success(self, temp_dir, capsys):
        """Test successful compliance violation generation."""
        mock_gen = MagicMock()
        mock_gen.generate_all.return_value = {
            "type1": {"sample1": temp_dir / "s1.dcm", "sample2": temp_dir / "s2.dcm"},
            "type2": {"sample3": temp_dir / "s3.dcm"},
        }

        with patch(
            "dicom_fuzzer.generators.compliance_violations.generator.ComplianceViolationGenerator",
            return_value=mock_gen,
        ):
            count, error = samples._generate_compliance_violations(
                temp_dir, verbose=True
            )

        assert count == 3
        assert error is None

    def test_generate_compliance_violations_exception(self, temp_dir, capsys):
        """Test exception handling."""
        with patch(
            "dicom_fuzzer.generators.compliance_violations.generator.ComplianceViolationGenerator",
            side_effect=RuntimeError("Compliance gen failed"),
        ):
            count, error = samples._generate_compliance_violations(
                temp_dir, verbose=False
            )

        assert count == 0
        assert "Compliance gen failed" in error


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

    def test_run_malicious_success(self, temp_dir, capsys):
        """Test successful malicious sample generation."""
        args = argparse.Namespace(
            output=str(temp_dir / "malicious"),
            verbose=True,
        )

        # Mock all generator helpers
        with (
            patch.object(samples, "_generate_preamble_attacks", return_value=(2, None)),
            patch.object(samples, "_generate_cve_samples", return_value=(5, None)),
            patch.object(samples, "_generate_parser_stress", return_value=(3, None)),
            patch.object(
                samples, "_generate_compliance_violations", return_value=(4, None)
            ),
        ):
            result = samples.run_malicious(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total samples generated: 14" in captured.out

    def test_run_malicious_with_errors(self, temp_dir, capsys):
        """Test malicious generation with some errors."""
        args = argparse.Namespace(
            output=str(temp_dir / "malicious"),
            verbose=False,
        )

        with (
            patch.object(samples, "_generate_preamble_attacks", return_value=(2, None)),
            patch.object(
                samples, "_generate_cve_samples", return_value=(0, "CVE gen failed")
            ),
            patch.object(samples, "_generate_parser_stress", return_value=(3, None)),
            patch.object(
                samples,
                "_generate_compliance_violations",
                return_value=(0, "Compliance failed"),
            ),
        ):
            result = samples.run_malicious(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Errors: 2" in captured.out


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

    def test_run_preamble_attacks_success(self, temp_dir, capsys):
        """Test successful preamble attack generation."""
        args = argparse.Namespace(output=str(temp_dir / "attacks"))

        mock_gen = MagicMock()
        mock_gen.create_pe_dicom.return_value = temp_dir / "pe.dcm"
        mock_gen.create_elf_dicom.return_value = temp_dir / "elf.dcm"

        with patch(
            "dicom_fuzzer.generators.preamble_attacks.generator.PreambleAttackGenerator",
            return_value=mock_gen,
        ):
            result = samples.run_preamble_attacks(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "PE/DICOM polyglot" in captured.out
        assert "ELF/DICOM polyglot" in captured.out
        assert "Generated 2 polyglot samples" in captured.out

    def test_run_preamble_attacks_exception(self, temp_dir, capsys):
        """Test exception handling."""
        args = argparse.Namespace(output=str(temp_dir / "attacks"))

        with patch(
            "dicom_fuzzer.generators.preamble_attacks.generator.PreambleAttackGenerator",
            side_effect=RuntimeError("Failed to create"),
        ):
            result = samples.run_preamble_attacks(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Failed" in captured.out


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

    def test_run_cve_samples_success(self, temp_dir, capsys):
        """Test successful CVE sample generation."""
        args = argparse.Namespace(output=str(temp_dir / "cves"))

        mock_gen = MagicMock()
        mock_gen.generate_all.return_value = {
            "CVE-2024-0001": temp_dir / "cve1.dcm",
            "CVE-2024-0002": temp_dir / "cve2.dcm",
            "CVE-2024-0003": None,  # One failed
        }

        with patch(
            "dicom_fuzzer.generators.cve_reproductions.generator.CVESampleGenerator",
            return_value=mock_gen,
        ):
            result = samples.run_cve_samples(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "CVE-2024-0001" in captured.out
        assert "CVE-2024-0002" in captured.out
        assert "Failed to generate" in captured.out  # For the None one
        assert "Generated 2/3 CVE samples" in captured.out

    def test_run_cve_samples_exception(self, temp_dir, capsys):
        """Test exception handling."""
        args = argparse.Namespace(output=str(temp_dir / "cves"))

        with patch(
            "dicom_fuzzer.generators.cve_reproductions.generator.CVESampleGenerator",
            side_effect=RuntimeError("CVE failed"),
        ):
            result = samples.run_cve_samples(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Failed" in captured.out


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

    def test_run_parser_stress_success(self, temp_dir, capsys):
        """Test successful parser stress generation."""
        args = argparse.Namespace(output=str(temp_dir / "stress"))

        mock_gen = MagicMock()
        mock_gen.generate_all.return_value = {
            "deep_nesting": temp_dir / "deep.dcm",
            "truncated": temp_dir / "trunc.dcm",
            "malformed": None,  # One failed
        }

        with patch(
            "dicom_fuzzer.generators.parser_stress.generator.ParserStressGenerator",
            return_value=mock_gen,
        ):
            result = samples.run_parser_stress(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "deep_nesting" in captured.out
        assert "truncated" in captured.out
        assert "Failed to generate" in captured.out
        assert "Generated 2/3 stress samples" in captured.out

    def test_run_parser_stress_exception(self, temp_dir, capsys):
        """Test exception handling."""
        args = argparse.Namespace(output=str(temp_dir / "stress"))

        with patch(
            "dicom_fuzzer.generators.parser_stress.generator.ParserStressGenerator",
            side_effect=RuntimeError("Stress failed"),
        ):
            result = samples.run_parser_stress(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Failed" in captured.out


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

    def test_run_compliance_success(self, temp_dir, capsys):
        """Test successful compliance violation generation."""
        args = argparse.Namespace(output=str(temp_dir / "compliance"))

        mock_gen = MagicMock()
        mock_gen.generate_all.return_value = {
            "vr_violations": {
                "wrong_vr": temp_dir / "wrong_vr.dcm",
                "invalid_length": temp_dir / "invalid_len.dcm",
            },
            "sequence_errors": {"unclosed": temp_dir / "unclosed.dcm"},
        }

        with patch(
            "dicom_fuzzer.generators.compliance_violations.generator.ComplianceViolationGenerator",
            return_value=mock_gen,
        ):
            result = samples.run_compliance(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "vr_violations" in captured.out
        assert "wrong_vr" in captured.out
        assert "sequence_errors" in captured.out
        assert "Generated 3 compliance samples in 2 categories" in captured.out

    def test_run_compliance_exception(self, temp_dir, capsys):
        """Test exception handling."""
        args = argparse.Namespace(output=str(temp_dir / "compliance"))

        with patch(
            "dicom_fuzzer.generators.compliance_violations.generator.ComplianceViolationGenerator",
            side_effect=RuntimeError("Compliance failed"),
        ):
            result = samples.run_compliance(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Failed" in captured.out




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
        assert "Original:" in captured.out
        assert "Stripped:" in captured.out
        assert "Saved:" in captured.out

    def test_run_strip_pixel_data_file_failed(self, temp_dir, capsys):
        """Test stripping single file when strip fails."""
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
            mock_strip.return_value = (False, 0)  # Failed to strip

            result = samples.run_strip_pixel_data(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Failed to process" in captured.out

    def test_run_strip_pixel_data_directory(self, temp_dir, capsys):
        """Test stripping a directory of files."""
        # Create test files
        (temp_dir / "file1.dcm").write_bytes(b"\x00" * 1000)
        (temp_dir / "file2.dcm").write_bytes(b"\x00" * 2000)
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            strip_pixel_data=str(temp_dir),
            output=str(output_dir),
            verbose=False,
        )

        mock_stats = {
            "files_processed": 2,
            "files_optimized": 2,
            "files_skipped": 0,
            "original_size_mb": 3.0,
            "optimized_size_mb": 1.0,
            "bytes_saved": 2 * 1024 * 1024,
            "reduction_percent": 66.7,
        }

        with patch(
            "dicom_fuzzer.utils.corpus_minimization.optimize_corpus"
        ) as mock_optimize:
            mock_optimize.return_value = mock_stats
            result = samples.run_strip_pixel_data(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Files processed:   2" in captured.out
        assert "Files optimized:   2" in captured.out
        assert "Reduction:" in captured.out
        assert "Optimized corpus is ready" in captured.out

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

    def _patch_dispatch(self, arg_name: str, mock_handler: MagicMock):
        """Helper to patch _ACTION_DISPATCH for a specific action."""
        original_dispatch = samples._ACTION_DISPATCH.copy()
        new_dispatch = [
            (name, mock_handler if name == arg_name else handler)
            for name, handler in original_dispatch
        ]
        return patch.object(samples, "_ACTION_DISPATCH", new_dispatch)

    def test_main_generate(self):
        """Test main with --generate."""
        mock_run = MagicMock(return_value=0)
        with self._patch_dispatch("generate", mock_run):
            result = samples.main(["--generate"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_list_sources(self):
        """Test main with --list-sources."""
        mock_run = MagicMock(return_value=0)
        with self._patch_dispatch("list_sources", mock_run):
            result = samples.main(["--list-sources"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_malicious(self):
        """Test main with --malicious."""
        mock_run = MagicMock(return_value=0)
        with self._patch_dispatch("malicious", mock_run):
            result = samples.main(["--malicious"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_preamble_attacks(self):
        """Test main with --preamble-attacks."""
        mock_run = MagicMock(return_value=0)
        with self._patch_dispatch("preamble_attacks", mock_run):
            result = samples.main(["--preamble-attacks"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_cve_samples(self):
        """Test main with --cve-samples."""
        mock_run = MagicMock(return_value=0)
        with self._patch_dispatch("cve_samples", mock_run):
            result = samples.main(["--cve-samples"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_parser_stress(self):
        """Test main with --parser-stress."""
        mock_run = MagicMock(return_value=0)
        with self._patch_dispatch("parser_stress", mock_run):
            result = samples.main(["--parser-stress"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_compliance(self):
        """Test main with --compliance."""
        mock_run = MagicMock(return_value=0)
        with self._patch_dispatch("compliance", mock_run):
            result = samples.main(["--compliance"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_strip_pixel_data(self):
        """Test main with --strip-pixel-data."""
        mock_run = MagicMock(return_value=0)
        with self._patch_dispatch("strip_pixel_data", mock_run):
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
        mock_run = MagicMock(return_value=0)
        with patch("sys.argv", ["samples", "--list-sources"]):
            with self._patch_dispatch("list_sources", mock_run):
                result = samples.main(None)

        assert result == 0
        mock_run.assert_called_once()
