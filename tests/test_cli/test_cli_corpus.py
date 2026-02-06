"""Tests for corpus management CLI subcommand.

Tests for dicom_fuzzer.cli.corpus module.
"""

import argparse
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from dicom_fuzzer.cli.commands import corpus


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created with required arguments."""
        parser = corpus.create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_analyze_action(self):
        """Test --analyze argument."""
        parser = corpus.create_parser()
        args = parser.parse_args(["--analyze", "./corpus"])
        assert args.analyze == "./corpus"

    def test_parser_dedup_action(self):
        """Test --dedup argument."""
        parser = corpus.create_parser()
        args = parser.parse_args(["--dedup", "./corpus"])
        assert args.dedup == "./corpus"

    def test_parser_merge_action(self):
        """Test --merge argument."""
        parser = corpus.create_parser()
        args = parser.parse_args(["--merge", "./corpus1", "./corpus2"])
        assert args.merge == ["./corpus1", "./corpus2"]

    def test_parser_mutually_exclusive(self):
        """Test that actions are mutually exclusive."""
        parser = corpus.create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--analyze", "./c1", "--dedup", "./c2"])

    def test_parser_output_options(self):
        """Test output options."""
        parser = corpus.create_parser()
        args = parser.parse_args(
            ["--analyze", "./corpus", "-o", "./output", "--format", "json", "-v"]
        )
        assert args.output == "./output"
        assert args.format == "json"
        assert args.verbose is True

    def test_parser_defaults(self):
        """Test default values."""
        parser = corpus.create_parser()
        args = parser.parse_args(["--analyze", "./corpus"])
        assert args.output is None
        assert args.format == "text"
        assert args.verbose is False


class TestRunAnalyze:
    """Test run_analyze function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_analyze_dir_not_found(self, capsys):
        """Test error when directory not found."""
        args = argparse.Namespace(
            analyze="/nonexistent/dir",
            format="text",
        )

        result = corpus.run_analyze(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_analyze_text_output(self, temp_dir, capsys):
        """Test analyze with text output."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()

        # Create test files of varying sizes
        (corpus_dir / "small.dcm").write_bytes(b"\x00" * 500)
        (corpus_dir / "medium.dcm").write_bytes(b"\x00" * 50000)
        (corpus_dir / "large.dcm").write_bytes(b"\x00" * 500000)

        args = argparse.Namespace(
            analyze=str(corpus_dir),
            format="text",
        )

        result = corpus.run_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total files:" in captured.out
        assert "3" in captured.out
        assert "Size Distribution" in captured.out

    def test_run_analyze_json_output(self, temp_dir, capsys):
        """Test analyze with JSON output."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test.dcm").write_bytes(b"\x00" * 1000)

        args = argparse.Namespace(
            analyze=str(corpus_dir),
            format="json",
        )

        result = corpus.run_analyze(args)

        assert result == 0
        captured = capsys.readouterr()

        # Output includes header + JSON, extract JSON part
        output_lines = captured.out.strip().split("\n")
        # Find line that starts with {
        json_start = next(
            i for i, line in enumerate(output_lines) if line.strip().startswith("{")
        )
        json_text = "\n".join(output_lines[json_start:])
        data = json.loads(json_text)
        assert "total_files" in data
        assert data["total_files"] == 1

    def test_run_analyze_empty_dir(self, temp_dir, capsys):
        """Test analyze with empty directory."""
        corpus_dir = temp_dir / "empty"
        corpus_dir.mkdir()

        args = argparse.Namespace(
            analyze=str(corpus_dir),
            format="text",
        )

        result = corpus.run_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total files:" in captured.out
        assert "0" in captured.out

    def test_run_analyze_non_dcm_files(self, temp_dir, capsys):
        """Test analyze falls back to all files when no .dcm files."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test.bin").write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            analyze=str(corpus_dir),
            format="text",
        )

        result = corpus.run_analyze(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Total files:" in captured.out
        assert "1" in captured.out

    def test_run_analyze_exception(self, temp_dir, capsys):
        """Test analyze handles exceptions."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()

        args = argparse.Namespace(
            analyze=str(corpus_dir),
            format="text",
        )

        with patch.object(Path, "glob", side_effect=PermissionError("Access denied")):
            result = corpus.run_analyze(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Analysis failed" in captured.out


class TestRunDedup:
    """Test run_dedup function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_dedup_dir_not_found(self, capsys):
        """Test error when directory not found."""
        args = argparse.Namespace(
            dedup="/nonexistent/dir",
            output=None,
            verbose=False,
        )

        result = corpus.run_dedup(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_dedup_basic(self, temp_dir, capsys):
        """Test basic deduplication."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()

        # Create files with same content (duplicates)
        content = b"same content"
        (input_dir / "file1.dcm").write_bytes(content)
        (input_dir / "file2.dcm").write_bytes(content)
        (input_dir / "file3.dcm").write_bytes(b"different content")

        args = argparse.Namespace(
            dedup=str(input_dir),
            output=None,
            verbose=False,
        )

        result = corpus.run_dedup(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Original:   3" in captured.out
        assert "Unique:     2" in captured.out
        assert "Duplicates: 1" in captured.out

        # Check default output directory
        output_dir = temp_dir / "corpus_unique"
        assert output_dir.exists()
        assert len(list(output_dir.glob("*"))) == 2

    def test_run_dedup_with_output(self, temp_dir, capsys):
        """Test deduplication with custom output."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()
        output_dir = temp_dir / "unique"

        (input_dir / "file1.dcm").write_bytes(b"content1")
        (input_dir / "file2.dcm").write_bytes(b"content2")

        args = argparse.Namespace(
            dedup=str(input_dir),
            output=str(output_dir),
            verbose=False,
        )

        result = corpus.run_dedup(args)

        assert result == 0
        assert output_dir.exists()
        assert len(list(output_dir.glob("*"))) == 2

    def test_run_dedup_verbose(self, temp_dir, capsys):
        """Test deduplication with verbose output."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()

        content = b"duplicate"
        (input_dir / "original.dcm").write_bytes(content)
        (input_dir / "duplicate.dcm").write_bytes(content)

        args = argparse.Namespace(
            dedup=str(input_dir),
            output=None,
            verbose=True,
        )

        result = corpus.run_dedup(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "[DUP]" in captured.out

    def test_run_dedup_skips_directories(self, temp_dir, capsys):
        """Test deduplication skips subdirectories."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()
        (input_dir / "subdir").mkdir()
        (input_dir / "file.dcm").write_bytes(b"content")

        args = argparse.Namespace(
            dedup=str(input_dir),
            output=None,
            verbose=False,
        )

        result = corpus.run_dedup(args)

        assert result == 0
        captured = capsys.readouterr()
        # Should only count the file, not the directory
        assert "Unique:     1" in captured.out

    def test_run_dedup_exception(self, temp_dir, capsys):
        """Test deduplication handles exceptions."""
        input_dir = temp_dir / "corpus"
        input_dir.mkdir()
        # Create a file that will be processed
        (input_dir / "test.dcm").write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            dedup=str(input_dir),
            output=None,
            verbose=False,
        )

        # Patch shutil.copy2 to simulate copy error during dedup
        with patch("shutil.copy2", side_effect=RuntimeError("Copy error")):
            result = corpus.run_dedup(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Deduplication failed" in captured.out


class TestRunMerge:
    """Test run_merge function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_merge_no_output(self, temp_dir, capsys):
        """Test error when output not specified."""
        args = argparse.Namespace(
            merge=[str(temp_dir)],
            output=None,
            verbose=False,
        )

        result = corpus.run_merge(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "--output is required" in captured.out

    def test_run_merge_basic(self, temp_dir, capsys):
        """Test basic merge."""
        corpus1 = temp_dir / "corpus1"
        corpus1.mkdir()
        (corpus1 / "file1.dcm").write_bytes(b"content1")

        corpus2 = temp_dir / "corpus2"
        corpus2.mkdir()
        (corpus2 / "file2.dcm").write_bytes(b"content2")

        output_dir = temp_dir / "merged"

        args = argparse.Namespace(
            merge=[str(corpus1), str(corpus2)],
            output=str(output_dir),
            verbose=False,
        )

        result = corpus.run_merge(args)

        assert result == 0
        assert output_dir.exists()
        assert len(list(output_dir.glob("*"))) == 2
        captured = capsys.readouterr()
        assert "Total processed: 2" in captured.out
        assert "Merged (unique): 2" in captured.out

    def test_run_merge_deduplication(self, temp_dir, capsys):
        """Test merge deduplicates across corpora."""
        corpus1 = temp_dir / "corpus1"
        corpus1.mkdir()
        content = b"same content"
        (corpus1 / "file1.dcm").write_bytes(content)

        corpus2 = temp_dir / "corpus2"
        corpus2.mkdir()
        (corpus2 / "file2.dcm").write_bytes(content)

        output_dir = temp_dir / "merged"

        args = argparse.Namespace(
            merge=[str(corpus1), str(corpus2)],
            output=str(output_dir),
            verbose=False,
        )

        result = corpus.run_merge(args)

        assert result == 0
        # Should only have 1 unique file
        assert len(list(output_dir.glob("*"))) == 1
        captured = capsys.readouterr()
        assert "Total processed: 2" in captured.out
        assert "Merged (unique): 1" in captured.out

    def test_run_merge_missing_source(self, temp_dir, capsys):
        """Test merge handles missing source directories."""
        corpus1 = temp_dir / "corpus1"
        corpus1.mkdir()
        (corpus1 / "file.dcm").write_bytes(b"content")

        output_dir = temp_dir / "merged"

        args = argparse.Namespace(
            merge=[str(corpus1), str(temp_dir / "nonexistent")],
            output=str(output_dir),
            verbose=False,
        )

        result = corpus.run_merge(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Skipping missing" in captured.out

    def test_run_merge_skips_directories(self, temp_dir, capsys):
        """Test merge skips subdirectories."""
        corpus1 = temp_dir / "corpus1"
        corpus1.mkdir()
        (corpus1 / "subdir").mkdir()
        (corpus1 / "file.dcm").write_bytes(b"content")

        output_dir = temp_dir / "merged"

        args = argparse.Namespace(
            merge=[str(corpus1)],
            output=str(output_dir),
            verbose=False,
        )

        result = corpus.run_merge(args)

        assert result == 0
        # Should only have 1 file, not the directory
        assert len(list(output_dir.glob("*"))) == 1

    def test_run_merge_exception(self, temp_dir, capsys):
        """Test merge handles exceptions."""
        corpus1 = temp_dir / "corpus1"
        corpus1.mkdir()

        output_dir = temp_dir / "merged"

        args = argparse.Namespace(
            merge=[str(corpus1)],
            output=str(output_dir),
            verbose=False,
        )

        with patch.object(Path, "glob", side_effect=RuntimeError("Glob error")):
            result = corpus.run_merge(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Merge failed" in captured.out


class TestValidateMinimizeStudyArgs:
    """Test _validate_minimize_study_args helper function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_validate_study_not_found(self, temp_dir, capsys):
        """Test validation fails when study directory not found."""
        args = argparse.Namespace(
            minimize_study="/nonexistent/study",
            target=None,
            output=None,
        )

        result = corpus._validate_minimize_study_args(args)

        assert result is None
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_validate_target_required(self, temp_dir, capsys):
        """Test validation fails when target not specified."""
        study_dir = temp_dir / "study"
        study_dir.mkdir()

        args = argparse.Namespace(
            minimize_study=str(study_dir),
            target=None,
            output=None,
        )

        result = corpus._validate_minimize_study_args(args)

        assert result is None
        captured = capsys.readouterr()
        assert "--target is required" in captured.out

    def test_validate_target_not_found(self, temp_dir, capsys):
        """Test validation fails when target executable not found."""
        study_dir = temp_dir / "study"
        study_dir.mkdir()

        args = argparse.Namespace(
            minimize_study=str(study_dir),
            target="/nonexistent/target.exe",
            output=None,
        )

        result = corpus._validate_minimize_study_args(args)

        assert result is None
        captured = capsys.readouterr()
        assert "Target executable not found" in captured.out

    def test_validate_success_with_output(self, temp_dir):
        """Test validation succeeds with all required arguments."""
        study_dir = temp_dir / "study"
        study_dir.mkdir()
        target = temp_dir / "target.exe"
        target.write_text("fake executable")
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            minimize_study=str(study_dir),
            target=str(target),
            output=str(output_dir),
        )

        result = corpus._validate_minimize_study_args(args)

        assert result is not None
        study, target_path, output = result
        assert study == study_dir
        assert target_path == target
        assert output == output_dir

    def test_validate_success_default_output(self, temp_dir):
        """Test validation generates default output directory."""
        study_dir = temp_dir / "study"
        study_dir.mkdir()
        target = temp_dir / "target.exe"
        target.write_text("fake executable")

        args = argparse.Namespace(
            minimize_study=str(study_dir),
            target=str(target),
            output=None,
        )

        result = corpus._validate_minimize_study_args(args)

        assert result is not None
        study, target_path, output = result
        assert output.name == "study_minimized"


class TestRunMinimizeStudy:
    """Test run_minimize_study function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_minimize_study_validation_failed(self, capsys):
        """Test minimize fails when validation fails."""
        args = argparse.Namespace(
            minimize_study="/nonexistent/study",
            target=None,
            output=None,
            verbose=False,
        )

        result = corpus.run_minimize_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_minimize_study_success(self, temp_dir, capsys):
        """Test successful study minimization."""
        from unittest.mock import MagicMock, patch

        study_dir = temp_dir / "study"
        study_dir.mkdir()
        target = temp_dir / "target.exe"
        target.write_text("fake")
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            minimize_study=str(study_dir),
            target=str(target),
            output=str(output_dir),
            timeout=30.0,
            max_iterations=10,
            verbose=False,
        )

        # Mock the minimizer result
        mock_result = MagicMock()
        mock_result.original_slice_count = 10
        mock_result.minimal_slice_count = 1
        mock_result.reduction_ratio = 0.1
        mock_result.iterations = 5
        mock_result.minimization_time_seconds = 10.5
        mock_result.crash_reproducible = True
        mock_result.trigger_slice = MagicMock(name="slice_0003.dcm")
        mock_result.notes = ["Single slice triggers crash"]

        mock_minimizer = MagicMock()
        mock_minimizer.minimize.return_value = mock_result

        with (
            patch(
                "dicom_fuzzer.core.harness.target_runner.TargetRunner"
            ) as mock_runner_cls,
            patch(
                "dicom_fuzzer.core.corpus.study_minimizer.StudyMinimizer",
                return_value=mock_minimizer,
            ),
            patch(
                "dicom_fuzzer.core.corpus.study_minimizer.create_crash_test_from_runner"
            ),
        ):
            result = corpus.run_minimize_study(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Study Minimization" in captured.out
        assert "TRIGGER SLICE FOUND" in captured.out
        assert "Minimized study saved to" in captured.out

    def test_run_minimize_study_multi_slice_bug(self, temp_dir, capsys):
        """Test minimization result with multi-slice bug."""
        from unittest.mock import MagicMock, patch

        study_dir = temp_dir / "study"
        study_dir.mkdir()
        target = temp_dir / "target.exe"
        target.write_text("fake")

        args = argparse.Namespace(
            minimize_study=str(study_dir),
            target=str(target),
            output=None,
            timeout=30.0,
            max_iterations=10,
            verbose=False,
        )

        mock_result = MagicMock()
        mock_result.original_slice_count = 10
        mock_result.minimal_slice_count = 3  # Multi-slice bug
        mock_result.reduction_ratio = 0.3
        mock_result.iterations = 8
        mock_result.minimization_time_seconds = 15.0
        mock_result.crash_reproducible = True
        mock_result.trigger_slice = None  # No single trigger
        mock_result.notes = []

        mock_minimizer = MagicMock()
        mock_minimizer.minimize.return_value = mock_result

        with (
            patch("dicom_fuzzer.core.harness.target_runner.TargetRunner"),
            patch(
                "dicom_fuzzer.core.corpus.study_minimizer.StudyMinimizer",
                return_value=mock_minimizer,
            ),
            patch(
                "dicom_fuzzer.core.corpus.study_minimizer.create_crash_test_from_runner"
            ),
        ):
            result = corpus.run_minimize_study(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Multi-slice bug: requires 3 slices" in captured.out

    def test_run_minimize_study_file_not_found(self, temp_dir, capsys):
        """Test minimize handles FileNotFoundError."""
        from unittest.mock import patch

        study_dir = temp_dir / "study"
        study_dir.mkdir()
        target = temp_dir / "target.exe"
        target.write_text("fake")

        args = argparse.Namespace(
            minimize_study=str(study_dir),
            target=str(target),
            output=None,
            timeout=30.0,
            max_iterations=10,
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.core.harness.target_runner.TargetRunner",
            side_effect=FileNotFoundError("Missing file"),
        ):
            result = corpus.run_minimize_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "File not found" in captured.out

    def test_run_minimize_study_exception(self, temp_dir, capsys):
        """Test minimize handles general exceptions."""
        from unittest.mock import patch

        study_dir = temp_dir / "study"
        study_dir.mkdir()
        target = temp_dir / "target.exe"
        target.write_text("fake")

        args = argparse.Namespace(
            minimize_study=str(study_dir),
            target=str(target),
            output=None,
            timeout=30.0,
            max_iterations=10,
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.core.harness.target_runner.TargetRunner",
            side_effect=RuntimeError("Runner error"),
        ):
            result = corpus.run_minimize_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Minimization failed" in captured.out


class TestRunGenerateStudy:
    """Test run_generate_study function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_generate_study_source_not_found(self, capsys):
        """Test generate fails when source not found."""
        args = argparse.Namespace(
            generate_study="/nonexistent/source",
            output="./output",
            verbose=False,
        )

        result = corpus.run_generate_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_generate_study_output_required(self, temp_dir, capsys):
        """Test generate fails when output not specified."""
        source_dir = temp_dir / "source"
        source_dir.mkdir()

        args = argparse.Namespace(
            generate_study=str(source_dir),
            output=None,
            verbose=False,
        )

        result = corpus.run_generate_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "--output is required" in captured.out

    def test_run_generate_study_success(self, temp_dir, capsys):
        """Test successful study generation."""
        from unittest.mock import MagicMock, patch

        source_dir = temp_dir / "source"
        source_dir.mkdir()
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            generate_study=str(source_dir),
            output=str(output_dir),
            count=5,
            strategy="all",
            severity="aggressive",
            mutations_per_study=3,
            verbose=True,
        )

        # Mock the study and mutator
        mock_study = MagicMock()
        mock_study.series_count = 2
        mock_study.get_total_slices.return_value = 20

        mock_mutator = MagicMock()
        mock_mutator.load_study.return_value = mock_study
        mock_mutator.mutate_study.return_value = (
            [[MagicMock(), MagicMock()]],
            [MagicMock(strategy="test", tag="0x00100010")],
        )

        mock_corpus = MagicMock()
        mock_entry = MagicMock()
        mock_entry.study_id = "study_001"
        mock_corpus.add_study.return_value = mock_entry
        mock_corpus.get_statistics.return_value = {
            "total_slices": 100,
            "modality_distribution": {"CT": 50, "MR": 50},
        }

        with (
            patch(
                "dicom_fuzzer.attacks.series.study_mutator.StudyMutator",
                return_value=mock_mutator,
            ),
            patch(
                "dicom_fuzzer.core.corpus.study_corpus.StudyCorpusManager",
                return_value=mock_corpus,
            ),
        ):
            result = corpus.run_generate_study(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Study Corpus Generation" in captured.out
        assert "Generation Complete" in captured.out
        assert "Generated:  5 studies" in captured.out

    def test_run_generate_study_specific_strategy(self, temp_dir, capsys):
        """Test generation with specific strategy."""
        from unittest.mock import MagicMock, patch

        source_dir = temp_dir / "source"
        source_dir.mkdir()
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            generate_study=str(source_dir),
            output=str(output_dir),
            count=2,
            strategy="cross-series",
            severity="minimal",
            mutations_per_study=1,
            verbose=False,
        )

        mock_study = MagicMock()
        mock_study.series_count = 1
        mock_study.get_total_slices.return_value = 5

        mock_mutator = MagicMock()
        mock_mutator.load_study.return_value = mock_study
        mock_mutator.mutate_study.return_value = ([[MagicMock()]], [])

        mock_corpus = MagicMock()
        mock_corpus.add_study.return_value = MagicMock(study_id="test")
        mock_corpus.get_statistics.return_value = {
            "total_slices": 10,
            "modality_distribution": {},
        }

        with (
            patch(
                "dicom_fuzzer.attacks.series.study_mutator.StudyMutator",
                return_value=mock_mutator,
            ),
            patch(
                "dicom_fuzzer.core.corpus.study_corpus.StudyCorpusManager",
                return_value=mock_corpus,
            ),
        ):
            result = corpus.run_generate_study(args)

        assert result == 0

    def test_run_generate_study_with_errors(self, temp_dir, capsys):
        """Test generation continues despite errors."""
        from unittest.mock import MagicMock, patch

        source_dir = temp_dir / "source"
        source_dir.mkdir()
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            generate_study=str(source_dir),
            output=str(output_dir),
            count=3,
            strategy="all",
            severity="aggressive",
            mutations_per_study=2,
            verbose=True,
        )

        mock_study = MagicMock()
        mock_study.series_count = 1
        mock_study.get_total_slices.return_value = 5

        mock_mutator = MagicMock()
        mock_mutator.load_study.return_value = mock_study
        # First call succeeds, second fails, third succeeds
        mock_mutator.mutate_study.side_effect = [
            ([[MagicMock()]], []),
            RuntimeError("Mutation failed"),
            ([[MagicMock()]], []),
        ]

        mock_corpus = MagicMock()
        mock_corpus.add_study.return_value = MagicMock(study_id="test")
        mock_corpus.get_statistics.return_value = {
            "total_slices": 10,
            "modality_distribution": {},
        }

        with (
            patch(
                "dicom_fuzzer.attacks.series.study_mutator.StudyMutator",
                return_value=mock_mutator,
            ),
            patch(
                "dicom_fuzzer.core.corpus.study_corpus.StudyCorpusManager",
                return_value=mock_corpus,
            ),
        ):
            result = corpus.run_generate_study(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Generated:  2 studies" in captured.out
        assert "Errors:     1" in captured.out

    def test_run_generate_study_exception(self, temp_dir, capsys):
        """Test generation handles fatal exceptions."""
        from unittest.mock import patch

        source_dir = temp_dir / "source"
        source_dir.mkdir()
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            generate_study=str(source_dir),
            output=str(output_dir),
            count=1,
            strategy="all",
            severity="aggressive",
            mutations_per_study=1,
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.attacks.series.study_mutator.StudyMutator",
            side_effect=RuntimeError("Import failed"),
        ):
            result = corpus.run_generate_study(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Generation failed" in captured.out


class TestMain:
    """Test main function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_main_analyze(self, temp_dir):
        """Test main with --analyze."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()

        with patch.object(corpus, "run_analyze", return_value=0) as mock_run:
            result = corpus.main(["--analyze", str(corpus_dir)])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_dedup(self, temp_dir):
        """Test main with --dedup."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()

        with patch.object(corpus, "run_dedup", return_value=0) as mock_run:
            result = corpus.main(["--dedup", str(corpus_dir)])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_merge(self, temp_dir):
        """Test main with --merge."""
        corpus1 = temp_dir / "corpus1"
        corpus1.mkdir()
        output_dir = temp_dir / "output"

        with patch.object(corpus, "run_merge", return_value=0) as mock_run:
            result = corpus.main(["--merge", str(corpus1), "-o", str(output_dir)])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_no_args(self):
        """Test main with no arguments shows help."""
        with pytest.raises(SystemExit) as exc_info:
            corpus.main([])

        assert exc_info.value.code != 0

    def test_main_none_argv(self):
        """Test main with None argv uses sys.argv."""
        with patch("sys.argv", ["corpus", "--analyze", "."]):
            with patch.object(corpus, "run_analyze", return_value=0) as mock_run:
                result = corpus.main(None)

        assert result == 0
        mock_run.assert_called_once()
