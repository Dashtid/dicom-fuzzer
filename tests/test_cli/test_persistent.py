"""Tests for persistent.py - Persistent Mode Fuzzing CLI.

Tests cover argument parsing, persistent fuzzing, and schedule listing.
"""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.persistent import (
    create_parser,
    main,
    run_fuzz,
    run_list_schedules,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_requires_action(self):
        """Test that parser requires mutually exclusive action."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_corpus_action(self):
        """Test --corpus action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--corpus", "./seeds"])

        assert args.corpus == "./seeds"
        assert args.list_schedules is False

    def test_parser_list_schedules_action(self):
        """Test --list-schedules action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--list-schedules"])

        assert args.list_schedules is True
        assert args.corpus is None

    def test_parser_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--corpus", "./seeds", "--list-schedules"])

    def test_parser_target_choices(self):
        """Test target argument choices."""
        parser = create_parser()
        args = parser.parse_args(["--corpus", "./seeds", "--target", "pydicom"])
        assert args.target == "pydicom"

    def test_parser_invalid_target(self):
        """Test invalid target raises error."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--corpus", "./seeds", "--target", "invalid"])

    def test_parser_schedule_choices(self):
        """Test schedule argument choices."""
        parser = create_parser()

        for schedule in ["fast", "explore", "exploit"]:
            args = parser.parse_args(["--corpus", "./seeds", "--schedule", schedule])
            assert args.schedule == schedule

    def test_parser_invalid_schedule(self):
        """Test invalid schedule raises error."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--corpus", "./seeds", "--schedule", "invalid"])

    def test_parser_defaults(self):
        """Test default values."""
        parser = create_parser()
        args = parser.parse_args(["--corpus", "./seeds"])

        assert args.target == "pydicom"
        assert args.timeout == 1000
        assert args.iterations == 1000
        assert args.mopt is False
        assert args.schedule == "fast"
        assert args.output == "./artifacts/persistent"
        assert args.verbose is False

    def test_parser_fuzz_options(self):
        """Test fuzzing options parsing."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--corpus",
                "./seeds",
                "-n",
                "5000",
                "--mopt",
                "--schedule",
                "explore",
                "--timeout",
                "2000",
                "-o",
                "/custom/output",
                "-v",
            ]
        )

        assert args.iterations == 5000
        assert args.mopt is True
        assert args.schedule == "explore"
        assert args.timeout == 2000
        assert args.output == "/custom/output"
        assert args.verbose is True


class TestRunFuzz:
    """Test run_fuzz function."""

    def test_fuzz_corpus_not_found(self, tmp_path, capsys):
        """Test error when corpus directory not found."""
        args = argparse.Namespace(
            corpus=str(tmp_path / "nonexistent"),
            output=str(tmp_path / "output"),
            target="pydicom",
            iterations=100,
            timeout=1000,
            mopt=False,
            schedule="fast",
            verbose=False,
        )

        result = run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Corpus directory not found" in captured.out

    def test_fuzz_success(self, tmp_path, capsys):
        """Test successful persistent fuzzing."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        output_dir = tmp_path / "output"

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {"iterations": 100, "crashes": 0}

        mock_config_class = MagicMock()
        mock_fuzzer_class = MagicMock(return_value=mock_fuzzer)

        mock_module = MagicMock()
        mock_module.PersistentFuzzer = mock_fuzzer_class
        mock_module.PersistentFuzzerConfig = mock_config_class

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            output=str(output_dir),
            target="pydicom",
            iterations=100,
            timeout=1000,
            mopt=False,
            schedule="fast",
            verbose=False,
        )

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.engine.persistent_fuzzer": mock_module}
        ):
            result = run_fuzz(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Persistent Mode" in captured.out
        assert "Fuzzing complete" in captured.out

    def test_fuzz_with_mopt(self, tmp_path, capsys):
        """Test fuzzing with MOpt enabled."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {}

        mock_module = MagicMock()
        mock_module.PersistentFuzzer = MagicMock(return_value=mock_fuzzer)
        mock_module.PersistentFuzzerConfig = MagicMock()

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            output=str(tmp_path / "output"),
            target="pydicom",
            iterations=100,
            timeout=1000,
            mopt=True,
            schedule="fast",
            verbose=False,
        )

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.engine.persistent_fuzzer": mock_module}
        ):
            result = run_fuzz(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "MOpt:       Enabled" in captured.out

    def test_fuzz_import_error(self, tmp_path, capsys):
        """Test handling of import error."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            output=str(tmp_path / "output"),
            target="pydicom",
            iterations=100,
            timeout=1000,
            mopt=False,
            schedule="fast",
            verbose=False,
        )

        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if "persistent_fuzzer" in name:
                raise ImportError("Module not available")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", mock_import):
            result = run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Persistent fuzzer not available" in captured.out

    def test_fuzz_generic_error(self, tmp_path, capsys):
        """Test handling of generic exception."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        mock_module = MagicMock()
        mock_module.PersistentFuzzer = MagicMock(side_effect=RuntimeError("Test error"))
        mock_module.PersistentFuzzerConfig = MagicMock()

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            output=str(tmp_path / "output"),
            target="pydicom",
            iterations=100,
            timeout=1000,
            mopt=False,
            schedule="fast",
            verbose=True,
        )

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.engine.persistent_fuzzer": mock_module}
        ):
            result = run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Fuzzing failed" in captured.out


class TestRunListSchedules:
    """Test run_list_schedules function."""

    def test_list_schedules_returns_zero(self, capsys):
        """Test that list_schedules returns 0."""
        args = argparse.Namespace()
        result = run_list_schedules(args)
        assert result == 0

    def test_list_schedules_output(self, capsys):
        """Test that list_schedules prints schedule information."""
        args = argparse.Namespace()
        run_list_schedules(args)
        captured = capsys.readouterr()

        assert "Power Schedules" in captured.out
        assert "fast" in captured.out
        assert "explore" in captured.out
        assert "exploit" in captured.out

    def test_list_schedules_descriptions(self, capsys):
        """Test that list_schedules shows descriptions."""
        args = argparse.Namespace()
        run_list_schedules(args)
        captured = capsys.readouterr()

        assert "prioritizes recently discovered seeds" in captured.out
        assert "Exploration-focused" in captured.out
        assert "Exploitation-focused" in captured.out


class TestMain:
    """Test main entry point."""

    def test_main_fuzz_dispatch(self, tmp_path, capsys):
        """Test main dispatches to run_fuzz."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()

        with patch("dicom_fuzzer.cli.persistent.run_fuzz", return_value=0) as mock_run:
            result = main(["--corpus", str(corpus_dir)])
            assert result == 0
            mock_run.assert_called_once()

    def test_main_list_schedules_dispatch(self, capsys):
        """Test main dispatches to run_list_schedules."""
        result = main(["--list-schedules"])
        assert result == 0
        captured = capsys.readouterr()
        assert "Power Schedules" in captured.out

    def test_main_no_args_fails(self, capsys):
        """Test main with no args fails."""
        with pytest.raises(SystemExit):
            main([])
