"""Tests for corpus --generate-study CLI functionality.

Tests argument parsing, validation, and execution of study corpus generation.
"""

import json
from pathlib import Path

import pytest


class TestGenerateStudyParser:
    """Test --generate-study argument parsing."""

    def test_generate_study_action(self):
        """Test --generate-study action is recognized."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        args = parser.parse_args(["--generate-study", "./source", "-o", "./output"])
        assert args.generate_study == "./source"
        assert args.output == "./output"

    def test_default_values(self):
        """Test default values for generation options."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        args = parser.parse_args(["--generate-study", "./source", "-o", "./output"])

        assert args.count == 50
        assert args.strategy == "all"
        assert args.severity == "aggressive"
        assert args.mutations_per_study == 5
        assert args.verbose is False

    def test_count_argument(self):
        """Test -c/--count argument."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--generate-study", "./source", "-o", "./output", "-c", "100"]
        )
        assert args.count == 100

        args = parser.parse_args(
            ["--generate-study", "./source", "-o", "./output", "--count", "25"]
        )
        assert args.count == 25

    def test_strategy_choices(self):
        """Test valid strategy choices are accepted."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        valid_strategies = [
            "cross-series",
            "frame-of-reference",
            "patient-consistency",
            "study-metadata",
            "mixed-modality",
            "all",
        ]

        for strategy in valid_strategies:
            args = parser.parse_args(
                [
                    "--generate-study",
                    "./source",
                    "-o",
                    "./output",
                    "--strategy",
                    strategy,
                ]
            )
            assert args.strategy == strategy

    def test_invalid_strategy_rejected(self):
        """Test invalid strategy is rejected."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                [
                    "--generate-study",
                    "./source",
                    "-o",
                    "./output",
                    "--strategy",
                    "invalid",
                ]
            )

    def test_severity_choices(self):
        """Test valid severity choices are accepted."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        for severity in ["minimal", "moderate", "aggressive", "extreme"]:
            args = parser.parse_args(
                [
                    "--generate-study",
                    "./source",
                    "-o",
                    "./output",
                    "--severity",
                    severity,
                ]
            )
            assert args.severity == severity

    def test_invalid_severity_rejected(self):
        """Test invalid severity is rejected."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                [
                    "--generate-study",
                    "./source",
                    "-o",
                    "./output",
                    "--severity",
                    "wrong",
                ]
            )

    def test_mutations_per_study_argument(self):
        """Test --mutations-per-study argument."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        args = parser.parse_args(
            [
                "--generate-study",
                "./source",
                "-o",
                "./output",
                "--mutations-per-study",
                "10",
            ]
        )
        assert args.mutations_per_study == 10

    def test_verbose_flag(self):
        """Test -v/--verbose flag."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        args = parser.parse_args(
            ["--generate-study", "./source", "-o", "./output", "-v"]
        )
        assert args.verbose is True


class TestGenerateStudyValidation:
    """Test input validation for --generate-study."""

    def test_source_not_found_error(self, tmp_path, capsys):
        """Test error when source study doesn't exist."""
        from dicom_fuzzer.cli.corpus import main

        result = main(
            [
                "--generate-study",
                str(tmp_path / "nonexistent"),
                "-o",
                str(tmp_path / "output"),
            ]
        )
        assert result == 1

        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_output_required_error(self, tmp_path, capsys):
        """Test error when --output not provided."""
        from dicom_fuzzer.cli.corpus import main

        # Create a source directory
        source = tmp_path / "source"
        source.mkdir()

        result = main(["--generate-study", str(source)])
        assert result == 1

        captured = capsys.readouterr()
        assert "--output is required" in captured.out


class TestGenerateStudyExecution:
    """Test study corpus generation execution."""

    @pytest.fixture
    def sample_study(self, tmp_path):
        """Create a sample DICOM study with multiple series for testing."""
        study_dir = tmp_path / "sample_study"
        study_dir.mkdir()

        # Create two series
        for series_num in range(2):
            series_dir = study_dir / f"series_{series_num:03d}"
            series_dir.mkdir()
            for slice_num in range(3):
                _create_minimal_dicom(
                    series_dir / f"slice_{slice_num:04d}.dcm",
                    series_uid=f"1.2.3.4.5.{series_num}",
                    instance_num=slice_num,
                )

        return study_dir

    def test_generation_creates_output_directory(self, tmp_path, sample_study, capsys):
        """Test output directory is created."""
        from dicom_fuzzer.cli.corpus import main

        output_dir = tmp_path / "output" / "nested"

        result = main(
            [
                "--generate-study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "2",  # Just 2 studies for speed
            ]
        )

        assert result == 0
        assert output_dir.exists()

    def test_generation_creates_corpus_index(self, tmp_path, sample_study, capsys):
        """Test corpus index file is created."""
        from dicom_fuzzer.cli.corpus import main

        output_dir = tmp_path / "output"

        result = main(
            [
                "--generate-study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "2",
            ]
        )

        assert result == 0
        index_file = output_dir / "study_corpus_index.json"
        assert index_file.exists()

        with open(index_file) as f:
            index_data = json.load(f)
            assert "studies" in index_data
            assert len(index_data["studies"]) == 2

    def test_generation_copies_studies_to_corpus(self, tmp_path, sample_study, capsys):
        """Test studies are copied to corpus directory."""
        from dicom_fuzzer.cli.corpus import main

        output_dir = tmp_path / "output"

        result = main(
            [
                "--generate-study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "1",
            ]
        )

        assert result == 0
        studies_dir = output_dir / "studies"
        assert studies_dir.exists()

        # Should have one study directory
        study_dirs = list(studies_dir.glob("study_*"))
        assert len(study_dirs) == 1

    def test_generation_with_specific_strategy(self, tmp_path, sample_study, capsys):
        """Test generation with specific strategy."""
        from dicom_fuzzer.cli.corpus import main

        output_dir = tmp_path / "output"

        result = main(
            [
                "--generate-study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "2",
                "--strategy",
                "cross-series",
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "cross-series" in captured.out

    def test_generation_with_verbose_output(self, tmp_path, sample_study, capsys):
        """Test verbose output shows mutation details."""
        from dicom_fuzzer.cli.corpus import main

        output_dir = tmp_path / "output"

        result = main(
            [
                "--generate-study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "2",
                "-v",
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        # Verbose output should show progress for each study
        assert "[1/2]" in captured.out or "[2/2]" in captured.out

    def test_generation_summary_output(self, tmp_path, sample_study, capsys):
        """Test summary output is displayed."""
        from dicom_fuzzer.cli.corpus import main

        output_dir = tmp_path / "output"

        result = main(
            [
                "--generate-study",
                str(sample_study),
                "-o",
                str(output_dir),
                "-c",
                "3",
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "Generation Complete" in captured.out
        assert "Generated:" in captured.out
        assert "Total slices:" in captured.out


class TestGenerateStudyMutualExclusion:
    """Test mutual exclusion with other corpus actions."""

    def test_cannot_combine_with_analyze(self):
        """Test --generate-study cannot be combined with --analyze."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--generate-study", "./source", "--analyze", "./corpus"])

    def test_cannot_combine_with_dedup(self):
        """Test --generate-study cannot be combined with --dedup."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--generate-study", "./source", "--dedup", "./corpus"])

    def test_cannot_combine_with_minimize_study(self):
        """Test --generate-study cannot be combined with --minimize-study."""
        from dicom_fuzzer.cli.corpus import create_parser

        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(
                ["--generate-study", "./source", "--minimize-study", "./crash"]
            )


# Helper functions


def _create_minimal_dicom(
    filepath: Path,
    series_uid: str = "1.2.3.4.5.6.7",
    instance_num: int = 0,
) -> None:
    """Create a minimal valid DICOM file for testing."""
    from pydicom.dataset import FileDataset, FileMetaDataset
    from pydicom.uid import UID

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = UID("1.2.840.10008.5.1.4.1.1.2")
    file_meta.MediaStorageSOPInstanceUID = UID(f"1.2.3.4.5.6.7.8.{instance_num}")
    file_meta.TransferSyntaxUID = UID("1.2.840.10008.1.2.1")

    ds = FileDataset(
        str(filepath),
        {},
        file_meta=file_meta,
        preamble=b"\x00" * 128,
    )

    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.PatientID = "TEST001"
    ds.PatientName = "Test^Patient"
    ds.StudyInstanceUID = UID("1.2.3.4.5.6")
    ds.SeriesInstanceUID = UID(series_uid)
    ds.Modality = "CT"
    ds.InstanceNumber = instance_num

    filepath.parent.mkdir(parents=True, exist_ok=True)
    ds.save_as(str(filepath))
