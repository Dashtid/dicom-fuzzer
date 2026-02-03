"""Tests for persistent mode fuzzing CLI subcommand.

Tests for dicom_fuzzer.cli.persistent module.
"""

import argparse
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli import persistent


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created with required arguments."""
        parser = persistent.create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_corpus_action(self):
        """Test --corpus argument."""
        parser = persistent.create_parser()
        args = parser.parse_args(["--corpus", "./seeds"])
        assert args.corpus == "./seeds"

    def test_parser_list_schedules_action(self):
        """Test --list-schedules argument."""
        parser = persistent.create_parser()
        args = parser.parse_args(["--list-schedules"])
        assert args.list_schedules is True

    def test_parser_mutually_exclusive(self):
        """Test that actions are mutually exclusive."""
        parser = persistent.create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--corpus", "./seeds", "--list-schedules"])

    def test_parser_target_options(self):
        """Test target options."""
        parser = persistent.create_parser()
        args = parser.parse_args(["--corpus", "./seeds", "--target", "pydicom"])
        assert args.target == "pydicom"

    def test_parser_timeout_option(self):
        """Test timeout option."""
        parser = persistent.create_parser()
        args = parser.parse_args(["--corpus", "./seeds", "--timeout", "2000"])
        assert args.timeout == 2000

    def test_parser_fuzzing_options(self):
        """Test fuzzing options."""
        parser = persistent.create_parser()
        args = parser.parse_args(
            ["--corpus", "./seeds", "-n", "500", "--mopt", "--schedule", "explore"]
        )
        assert args.iterations == 500
        assert args.mopt is True
        assert args.schedule == "explore"

    def test_parser_output_options(self):
        """Test output options."""
        parser = persistent.create_parser()
        args = parser.parse_args(["--corpus", "./seeds", "-o", "./output", "-v"])
        assert args.output == "./output"
        assert args.verbose is True

    def test_parser_defaults(self):
        """Test default values."""
        parser = persistent.create_parser()
        args = parser.parse_args(["--corpus", "./seeds"])
        assert args.target == "pydicom"
        assert args.timeout == 1000
        assert args.iterations == 1000
        assert args.mopt is False
        assert args.schedule == "fast"
        assert args.output == "./artifacts/persistent"
        assert args.verbose is False


class TestRunFuzz:
    """Test run_fuzz function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_fuzz_corpus_not_found(self, temp_dir, capsys):
        """Test error when corpus directory not found."""
        args = argparse.Namespace(
            corpus=str(temp_dir / "nonexistent"),
            target="pydicom",
            timeout=1000,
            iterations=10,
            mopt=False,
            schedule="fast",
            output=str(temp_dir / "output"),
            verbose=False,
        )

        result = persistent.run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_run_fuzz_basic(self, temp_dir, capsys):
        """Test basic fuzzing run."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "seed.dcm").write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            target="pydicom",
            timeout=1000,
            iterations=10,
            mopt=False,
            schedule="fast",
            output=str(temp_dir / "output"),
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {"iterations": 10}

        with patch(
            "dicom_fuzzer.core.engine.persistent_fuzzer.PersistentFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.engine.persistent_fuzzer.PersistentFuzzerConfig"
            ) as mock_config:
                result = persistent.run_fuzz(args)

        assert result == 0
        mock_fuzzer.load_corpus.assert_called_once()
        mock_fuzzer.run.assert_called_once()
        captured = capsys.readouterr()
        assert "Persistent Mode" in captured.out

    def test_run_fuzz_keyboard_interrupt(self, temp_dir, capsys):
        """Test KeyboardInterrupt handling."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "seed.dcm").write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            target="pydicom",
            timeout=1000,
            iterations=10,
            mopt=False,
            schedule="fast",
            output=str(temp_dir / "output"),
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.run.side_effect = KeyboardInterrupt()
        mock_fuzzer.get_statistics.return_value = {}

        with patch(
            "dicom_fuzzer.core.engine.persistent_fuzzer.PersistentFuzzer",
            return_value=mock_fuzzer,
        ):
            with patch(
                "dicom_fuzzer.core.engine.persistent_fuzzer.PersistentFuzzerConfig"
            ):
                result = persistent.run_fuzz(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Interrupted by user" in captured.out

    def test_run_fuzz_import_error(self, temp_dir, capsys):
        """Test handling of import error."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "seed.dcm").write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            target="pydicom",
            timeout=1000,
            iterations=10,
            mopt=False,
            schedule="fast",
            output=str(temp_dir / "output"),
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.core.engine.persistent_fuzzer.PersistentFuzzer",
            side_effect=ImportError("Module not found"),
        ):
            result = persistent.run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not available" in captured.out

    def test_run_fuzz_exception_verbose(self, temp_dir, capsys):
        """Test exception handling with verbose flag."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "seed.dcm").write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            target="pydicom",
            timeout=1000,
            iterations=10,
            mopt=False,
            schedule="fast",
            output=str(temp_dir / "output"),
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.core.engine.persistent_fuzzer.PersistentFuzzer",
            side_effect=RuntimeError("Test error"),
        ):
            result = persistent.run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Fuzzing failed" in captured.out


class TestRunListSchedules:
    """Test run_list_schedules function."""

    def test_list_schedules_output(self, capsys):
        """Test list schedules displays all schedules."""
        args = argparse.Namespace()

        result = persistent.run_list_schedules(args)

        assert result == 0
        captured = capsys.readouterr()

        # Verify all schedules are listed
        assert "fast" in captured.out
        assert "explore" in captured.out
        assert "exploit" in captured.out

        # Verify descriptions
        assert "Fast schedule" in captured.out or "prioritizes" in captured.out
        assert "Exploration" in captured.out or "broad" in captured.out
        assert "Exploitation" in captured.out or "deep" in captured.out


class TestMain:
    """Test main function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_main_corpus(self, temp_dir):
        """Test main with --corpus."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()

        with patch.object(persistent, "run_fuzz", return_value=0) as mock_run:
            result = persistent.main(["--corpus", str(corpus_dir)])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_list_schedules(self):
        """Test main with --list-schedules."""
        with patch.object(persistent, "run_list_schedules", return_value=0) as mock_run:
            result = persistent.main(["--list-schedules"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_no_args(self):
        """Test main with no arguments shows help."""
        with pytest.raises(SystemExit) as exc_info:
            persistent.main([])

        assert exc_info.value.code != 0

    def test_main_none_argv(self):
        """Test main with None argv uses sys.argv."""
        with patch("sys.argv", ["persistent", "--list-schedules"]):
            with patch.object(
                persistent, "run_list_schedules", return_value=0
            ) as mock_run:
                result = persistent.main(None)

        assert result == 0
        mock_run.assert_called_once()
