"""Tests for state.py - State-Aware Fuzzing CLI.

Tests cover argument parsing, state fuzzing, export, and list operations.
"""

import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.commands.state import (
    create_parser,
    main,
    run_export_sm,
    run_fuzz,
    run_list_states,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_requires_action(self):
        """Test that parser requires mutually exclusive action."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_fuzz_action(self):
        """Test --fuzz action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--fuzz"])

        assert args.fuzz is True
        assert args.export_sm is None
        assert args.list_states is False

    def test_parser_export_sm_action(self):
        """Test --export-sm action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--export-sm", "output.json"])

        assert args.export_sm == "output.json"
        assert args.fuzz is False
        assert args.list_states is False

    def test_parser_list_states_action(self):
        """Test --list-states action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--list-states"])

        assert args.list_states is True
        assert args.fuzz is False
        assert args.export_sm is None

    def test_parser_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--fuzz", "--list-states"])

    def test_parser_fuzz_options(self):
        """Test fuzzing options."""
        parser = create_parser()
        args = parser.parse_args(
            ["--fuzz", "--corpus", "./seeds", "-n", "5000", "-o", "./output", "-v"]
        )

        assert args.corpus == "./seeds"
        assert args.iterations == 5000
        assert args.output == "./output"
        assert args.verbose is True

    def test_parser_default_iterations(self):
        """Test default iterations value."""
        parser = create_parser()
        args = parser.parse_args(["--fuzz"])

        assert args.iterations == 1000

    def test_parser_defaults(self):
        """Test default values."""
        parser = create_parser()
        args = parser.parse_args(["--fuzz"])

        assert args.corpus is None
        assert args.output is None
        assert args.verbose is False


class TestRunFuzz:
    """Test run_fuzz function."""

    def test_fuzz_success(self, capsys):
        """Test successful fuzzing run."""
        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {"iterations": 100, "crashes": 0}

        mock_module = MagicMock()
        mock_module.StateAwareFuzzer = MagicMock(return_value=mock_fuzzer)

        args = argparse.Namespace(
            corpus=None,
            iterations=100,
            output=None,
            verbose=False,
        )

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.state_aware_fuzzer": mock_module}
        ):
            result = run_fuzz(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "State-Aware Protocol Fuzzing" in captured.out
        assert "Fuzzing complete" in captured.out

    def test_fuzz_with_corpus(self, tmp_path, capsys):
        """Test fuzzing with corpus directory."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test.dcm").write_bytes(b"test dicom data")

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {"iterations": 100}

        mock_module = MagicMock()
        mock_module.StateAwareFuzzer = MagicMock(return_value=mock_fuzzer)

        args = argparse.Namespace(
            corpus=str(corpus_dir),
            iterations=100,
            output=None,
            verbose=False,
        )

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.state_aware_fuzzer": mock_module}
        ):
            result = run_fuzz(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Loaded 1 seeds" in captured.out

    def test_fuzz_with_output(self, tmp_path, capsys):
        """Test fuzzing with output directory."""
        output_dir = tmp_path / "output"

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {"iterations": 100}

        mock_module = MagicMock()
        mock_module.StateAwareFuzzer = MagicMock(return_value=mock_fuzzer)

        args = argparse.Namespace(
            corpus=None,
            iterations=100,
            output=str(output_dir),
            verbose=False,
        )

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.state_aware_fuzzer": mock_module}
        ):
            result = run_fuzz(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Results saved to" in captured.out

    def test_fuzz_import_error(self, capsys):
        """Test handling of import error."""
        args = argparse.Namespace(
            corpus=None,
            iterations=100,
            output=None,
            verbose=False,
        )

        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if "state_aware_fuzzer" in name:
                raise ImportError("Module not available")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", mock_import):
            result = run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "State fuzzer not available" in captured.out

    def test_fuzz_generic_error(self, capsys):
        """Test handling of generic exception."""
        mock_module = MagicMock()
        mock_module.StateAwareFuzzer = MagicMock(side_effect=RuntimeError("Test error"))

        args = argparse.Namespace(
            corpus=None,
            iterations=100,
            output=None,
            verbose=True,
        )

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.state_aware_fuzzer": mock_module}
        ):
            result = run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Fuzzing failed" in captured.out


class TestRunExportSM:
    """Test run_export_sm function."""

    def test_export_success(self, tmp_path, capsys):
        """Test successful state machine export."""
        output_file = tmp_path / "state_machine.json"

        mock_fuzzer = MagicMock()
        mock_fuzzer.export_state_machine.return_value = {"states": ["STA1", "STA6"]}

        mock_module = MagicMock()
        mock_module.StateAwareFuzzer = MagicMock(return_value=mock_fuzzer)

        args = argparse.Namespace(export_sm=str(output_file))

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.state_aware_fuzzer": mock_module}
        ):
            result = run_export_sm(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "State machine exported" in captured.out

        # Verify file was written
        assert output_file.exists()
        data = json.loads(output_file.read_text())
        assert "states" in data

    def test_export_failure(self, tmp_path, capsys):
        """Test export failure handling."""
        output_file = tmp_path / "state_machine.json"

        mock_module = MagicMock()
        mock_module.StateAwareFuzzer = MagicMock(
            side_effect=RuntimeError("Export failed")
        )

        args = argparse.Namespace(export_sm=str(output_file))

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.core.state_aware_fuzzer": mock_module}
        ):
            result = run_export_sm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Export failed" in captured.out


class TestRunListStates:
    """Test run_list_states function."""

    def test_list_states_returns_zero(self, capsys):
        """Test that list_states returns 0."""
        args = argparse.Namespace()
        result = run_list_states(args)
        assert result == 0

    def test_list_states_output(self, capsys):
        """Test that list_states prints state information."""
        args = argparse.Namespace()
        run_list_states(args)
        captured = capsys.readouterr()

        assert "DICOM Protocol States" in captured.out
        assert "STA1" in captured.out
        assert "STA6" in captured.out
        assert "Established" in captured.out
        assert "Idle" in captured.out


class TestMain:
    """Test main entry point."""

    def test_main_fuzz_dispatch(self, capsys):
        """Test main dispatches to run_fuzz."""
        with patch(
            "dicom_fuzzer.cli.commands.state.run_fuzz", return_value=0
        ) as mock_run:
            result = main(["--fuzz"])
            assert result == 0
            mock_run.assert_called_once()

    def test_main_export_dispatch(self, tmp_path):
        """Test main dispatches to run_export_sm."""
        with patch(
            "dicom_fuzzer.cli.commands.state.run_export_sm", return_value=0
        ) as mock_run:
            result = main(["--export-sm", str(tmp_path / "out.json")])
            assert result == 0
            mock_run.assert_called_once()

    def test_main_list_dispatch(self, capsys):
        """Test main dispatches to run_list_states."""
        result = main(["--list-states"])
        assert result == 0
        captured = capsys.readouterr()
        assert "DICOM Protocol States" in captured.out

    def test_main_no_args_fails(self, capsys):
        """Test main with no args fails."""
        with pytest.raises(SystemExit):
            main([])
