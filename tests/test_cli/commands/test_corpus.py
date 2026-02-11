"""Tests for cli/corpus.py - Corpus Subcommand.

Tests cover argument parsing, analyze, dedup, merge, and minimize-study functions.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.cli.commands.corpus import (
    create_parser,
    main,
    run_analyze,
    run_dedup,
    run_merge,
    run_minimize_study,
)


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created."""
        parser = create_parser()
        assert parser is not None

    def test_analyze_action(self):
        """Test --analyze action."""
        parser = create_parser()
        args = parser.parse_args(["--analyze", "./corpus"])
        assert args.analyze == "./corpus"

    def test_dedup_action(self):
        """Test --dedup action."""
        parser = create_parser()
        args = parser.parse_args(["--dedup", "./corpus", "-o", "./output"])
        assert args.dedup == "./corpus"
        assert args.output == "./output"

    def test_merge_action(self):
        """Test --merge action."""
        parser = create_parser()
        args = parser.parse_args(
            ["--merge", "./corpus1", "./corpus2", "-o", "./merged"]
        )
        assert args.merge == ["./corpus1", "./corpus2"]
        assert args.output == "./merged"

    def test_minimize_study_action(self):
        """Test --minimize-study action."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--minimize-study",
                "./study",
                "-t",
                "./target.exe",
                "-o",
                "./output",
            ]
        )
        assert args.minimize_study == "./study"
        assert args.target == "./target.exe"

    def test_target_options(self):
        """Test target options for minimize-study."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--minimize-study",
                "./study",
                "-t",
                "./target.exe",
                "--timeout",
                "60",
                "--max-iterations",
                "200",
            ]
        )
        assert args.timeout == 60.0
        assert args.max_iterations == 200

    def test_output_options(self):
        """Test output options."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--analyze",
                "./corpus",
                "--format",
                "json",
                "-v",
            ]
        )
        assert args.format == "json"
        assert args.verbose is True

    def test_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--analyze", "./a", "--dedup", "./b"])


class TestRunAnalyze:
    """Test run_analyze function."""

    def test_analyze_corpus(self, tmp_path, capsys):
        """Test analyzing corpus."""
        # Create test files
        (tmp_path / "file1.dcm").write_bytes(b"\x00" * 100)
        (tmp_path / "file2.dcm").write_bytes(b"\x00" * 200)
        (tmp_path / "file3.dcm").write_bytes(b"\x00" * 500)

        args = MagicMock()
        args.analyze = str(tmp_path)
        args.format = "text"

        result = run_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total files:" in captured.out
        assert "3" in captured.out

    def test_analyze_corpus_json_format(self, tmp_path, capsys):
        """Test analyzing corpus with JSON output."""
        (tmp_path / "file1.dcm").write_bytes(b"\x00" * 1000)

        args = MagicMock()
        args.analyze = str(tmp_path)
        args.format = "json"

        result = run_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        # JSON output should start with '{'
        json_start = captured.out.find("{")
        assert json_start >= 0
        data = json.loads(captured.out[json_start:])
        assert "total_files" in data
        assert data["total_files"] == 1

    def test_analyze_empty_corpus(self, tmp_path, capsys):
        """Test analyzing empty corpus."""
        args = MagicMock()
        args.analyze = str(tmp_path)
        args.format = "text"

        result = run_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total files:" in captured.out
        assert "0" in captured.out

    def test_analyze_nonexistent_directory(self, tmp_path, capsys):
        """Test analyzing nonexistent directory."""
        args = MagicMock()
        args.analyze = str(tmp_path / "nonexistent")
        args.format = "text"

        result = run_analyze(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_analyze_shows_size_distribution(self, tmp_path, capsys):
        """Test that analysis shows size distribution."""
        # Create files of various sizes
        (tmp_path / "tiny.dcm").write_bytes(b"\x00" * 100)
        (tmp_path / "small.dcm").write_bytes(b"\x00" * 5000)
        (tmp_path / "medium.dcm").write_bytes(b"\x00" * 50000)
        (tmp_path / "large.dcm").write_bytes(b"\x00" * 500000)

        args = MagicMock()
        args.analyze = str(tmp_path)
        args.format = "text"

        result = run_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Size Distribution" in captured.out


class TestRunDedup:
    """Test run_dedup function."""

    def test_dedup_removes_duplicates(self, tmp_path, capsys):
        """Test deduplication removes duplicates."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()

        # Create duplicate files
        content = b"\x00" * 100
        (input_dir / "file1.dcm").write_bytes(content)
        (input_dir / "file2.dcm").write_bytes(content)  # Duplicate
        (input_dir / "file3.dcm").write_bytes(b"\x01" * 100)  # Unique

        output_dir = tmp_path / "output"

        args = MagicMock()
        args.dedup = str(input_dir)
        args.output = str(output_dir)
        args.verbose = False

        result = run_dedup(args)

        assert result == 0
        assert output_dir.exists()
        output_files = list(output_dir.glob("*"))
        assert len(output_files) == 2  # Only unique files

    def test_dedup_verbose_output(self, tmp_path, capsys):
        """Test dedup verbose output shows duplicates."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()

        content = b"\x00" * 100
        (input_dir / "file1.dcm").write_bytes(content)
        (input_dir / "file2.dcm").write_bytes(content)

        args = MagicMock()
        args.dedup = str(input_dir)
        args.output = str(tmp_path / "output")
        args.verbose = True

        result = run_dedup(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "DUP" in captured.out

    def test_dedup_nonexistent_input(self, tmp_path, capsys):
        """Test dedup with nonexistent input directory."""
        args = MagicMock()
        args.dedup = str(tmp_path / "nonexistent")
        args.output = str(tmp_path / "output")

        result = run_dedup(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_dedup_creates_output_if_missing(self, tmp_path, capsys):
        """Test dedup creates output directory if missing."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "file.dcm").write_bytes(b"\x00" * 100)

        output_dir = tmp_path / "new" / "nested" / "output"

        args = MagicMock()
        args.dedup = str(input_dir)
        args.output = str(output_dir)
        args.verbose = False

        result = run_dedup(args)

        assert result == 0
        assert output_dir.exists()

    def test_dedup_default_output(self, tmp_path, capsys):
        """Test dedup with default output directory."""
        input_dir = tmp_path / "corpus"
        input_dir.mkdir()
        (input_dir / "file.dcm").write_bytes(b"\x00" * 100)

        args = MagicMock()
        args.dedup = str(input_dir)
        args.output = None  # No output specified
        args.verbose = False

        result = run_dedup(args)

        assert result == 0
        default_output = tmp_path / "corpus_unique"
        assert default_output.exists()


class TestRunMerge:
    """Test run_merge function."""

    def test_merge_corpora(self, tmp_path, capsys):
        """Test merging multiple corpora."""
        corpus1 = tmp_path / "corpus1"
        corpus1.mkdir()
        (corpus1 / "file1.dcm").write_bytes(b"\x01" * 100)

        corpus2 = tmp_path / "corpus2"
        corpus2.mkdir()
        (corpus2 / "file2.dcm").write_bytes(b"\x02" * 100)

        output_dir = tmp_path / "merged"

        args = MagicMock()
        args.merge = [str(corpus1), str(corpus2)]
        args.output = str(output_dir)

        result = run_merge(args)

        assert result == 0
        assert output_dir.exists()
        merged_files = list(output_dir.glob("*"))
        assert len(merged_files) == 2

    def test_merge_deduplicates(self, tmp_path, capsys):
        """Test merge removes duplicates across corpora."""
        corpus1 = tmp_path / "corpus1"
        corpus1.mkdir()
        content = b"\x00" * 100
        (corpus1 / "file1.dcm").write_bytes(content)

        corpus2 = tmp_path / "corpus2"
        corpus2.mkdir()
        (corpus2 / "file2.dcm").write_bytes(content)  # Same content

        output_dir = tmp_path / "merged"

        args = MagicMock()
        args.merge = [str(corpus1), str(corpus2)]
        args.output = str(output_dir)

        result = run_merge(args)

        assert result == 0
        merged_files = list(output_dir.glob("*"))
        assert len(merged_files) == 1  # Deduplicated

    def test_merge_skips_missing_source(self, tmp_path, capsys):
        """Test merge skips missing source directories."""
        corpus1 = tmp_path / "corpus1"
        corpus1.mkdir()
        (corpus1 / "file.dcm").write_bytes(b"\x00" * 100)

        output_dir = tmp_path / "merged"

        args = MagicMock()
        args.merge = [str(corpus1), str(tmp_path / "nonexistent")]
        args.output = str(output_dir)

        result = run_merge(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Skipping missing" in captured.out

    def test_merge_requires_output(self, tmp_path, capsys):
        """Test merge requires --output."""
        args = MagicMock()
        args.merge = [str(tmp_path)]
        args.output = None

        result = run_merge(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "--output is required" in captured.out


class TestRunMinimizeStudy:
    """Test run_minimize_study function."""

    def test_minimize_study_not_found(self, tmp_path, capsys):
        """Test error when study directory not found."""
        target = tmp_path / "target.exe"
        target.write_bytes(b"fake")

        args = MagicMock()
        args.minimize_study = str(tmp_path / "nonexistent")
        args.target = str(target)
        args.output = None
        args.timeout = 30.0
        args.max_iterations = 100
        args.verbose = False

        result = run_minimize_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_minimize_study_requires_target(self, tmp_path, capsys):
        """Test error when target not provided."""
        study_dir = tmp_path / "study"
        study_dir.mkdir()

        args = MagicMock()
        args.minimize_study = str(study_dir)
        args.target = None
        args.output = None
        args.timeout = 30.0
        args.max_iterations = 100
        args.verbose = False

        result = run_minimize_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "--target is required" in captured.out

    def test_minimize_study_target_not_found(self, tmp_path, capsys):
        """Test error when target executable not found."""
        study_dir = tmp_path / "study"
        study_dir.mkdir()

        args = MagicMock()
        args.minimize_study = str(study_dir)
        args.target = str(tmp_path / "nonexistent.exe")
        args.output = None
        args.timeout = 30.0
        args.max_iterations = 100
        args.verbose = False

        result = run_minimize_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out


class TestMain:
    """Test main function."""

    def test_main_analyze(self, tmp_path, capsys):
        """Test main with --analyze."""
        (tmp_path / "file.dcm").write_bytes(b"\x00" * 100)

        result = main(["--analyze", str(tmp_path)])

        assert result == 0
        captured = capsys.readouterr()
        assert "Corpus Analysis" in captured.out

    def test_main_dedup(self, tmp_path, capsys):
        """Test main with --dedup."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "file.dcm").write_bytes(b"\x00" * 100)

        result = main(
            [
                "--dedup",
                str(input_dir),
                "-o",
                str(tmp_path / "output"),
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "Deduplication complete" in captured.out

    def test_main_merge(self, tmp_path, capsys):
        """Test main with --merge."""
        corpus1 = tmp_path / "corpus1"
        corpus1.mkdir()
        (corpus1 / "file.dcm").write_bytes(b"\x00" * 100)

        result = main(
            [
                "--merge",
                str(corpus1),
                "-o",
                str(tmp_path / "merged"),
            ]
        )

        assert result == 0
        captured = capsys.readouterr()
        assert "Merge complete" in captured.out

    def test_main_no_action(self):
        """Test main without any action."""
        with pytest.raises(SystemExit):
            main([])

    def test_main_help(self):
        """Test main with --help."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--help"])

        assert exc_info.value.code == 0


# Helper function
def _create_minimal_dicom(filepath: Path) -> None:
    """Create a minimal valid DICOM file for testing."""
    from pydicom.dataset import FileDataset, FileMetaDataset
    from pydicom.uid import UID

    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = UID("1.2.840.10008.5.1.4.1.1.2")
    file_meta.MediaStorageSOPInstanceUID = UID("1.2.3.4.5.6.7.8.9")
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
    ds.SeriesInstanceUID = UID("1.2.3.4.5.6.7")
    ds.Modality = "CT"

    filepath.parent.mkdir(parents=True, exist_ok=True)
    ds.save_as(str(filepath))
