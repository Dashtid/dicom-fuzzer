"""Tests for state-aware fuzzing CLI subcommand.

Tests for dicom_fuzzer.cli.state module.
"""

import argparse
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.commands import state


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created with required arguments."""
        parser = state.create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_fuzz_action(self):
        """Test --fuzz argument."""
        parser = state.create_parser()
        args = parser.parse_args(["--fuzz"])
        assert args.fuzz is True

    def test_parser_export_sm_action(self):
        """Test --export-sm argument."""
        parser = state.create_parser()
        args = parser.parse_args(["--export-sm", "output.json"])
        assert args.export_sm == "output.json"

    def test_parser_list_states_action(self):
        """Test --list-states argument."""
        parser = state.create_parser()
        args = parser.parse_args(["--list-states"])
        assert args.list_states is True

    def test_parser_mutually_exclusive(self):
        """Test that actions are mutually exclusive."""
        parser = state.create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--fuzz", "--list-states"])

    def test_parser_fuzzing_options(self):
        """Test fuzzing options."""
        parser = state.create_parser()
        args = parser.parse_args(["--fuzz", "--corpus", "./seeds", "-n", "500"])
        assert args.corpus == "./seeds"
        assert args.iterations == 500

    def test_parser_output_options(self):
        """Test output options."""
        parser = state.create_parser()
        args = parser.parse_args(["--fuzz", "-o", "./output", "-v"])
        assert args.output == "./output"
        assert args.verbose is True

    def test_parser_defaults(self):
        """Test default values."""
        parser = state.create_parser()
        args = parser.parse_args(["--fuzz"])
        assert args.iterations == 1000
        assert args.corpus is None
        assert args.output is None
        assert args.verbose is False


class TestRunFuzz:
    """Test run_fuzz function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_fuzz_basic(self, capsys):
        """Test basic fuzzing run."""
        args = argparse.Namespace(
            iterations=10,
            corpus=None,
            output=None,
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {"iterations": 10}

        with patch(
            "dicom_fuzzer.attacks.network.stateful.state_aware_fuzzer.StateAwareFuzzer",
            return_value=mock_fuzzer,
        ):
            result = state.run_fuzz(args)

        assert result == 0
        mock_fuzzer.run.assert_called_once_with(iterations=10)
        captured = capsys.readouterr()
        assert "State-Aware Protocol Fuzzing" in captured.out

    def test_run_fuzz_with_corpus(self, temp_dir, capsys):
        """Test fuzzing with corpus directory."""
        corpus_dir = temp_dir / "corpus"
        corpus_dir.mkdir()

        # Create seed files
        for i in range(3):
            seed_file = corpus_dir / f"seed_{i}.dcm"
            seed_file.write_bytes(b"\x00" * 100)

        args = argparse.Namespace(
            iterations=5,
            corpus=str(corpus_dir),
            output=None,
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {}

        with patch(
            "dicom_fuzzer.attacks.network.stateful.state_aware_fuzzer.StateAwareFuzzer",
            return_value=mock_fuzzer,
        ):
            result = state.run_fuzz(args)

        assert result == 0
        mock_fuzzer.add_seed.assert_called_once()
        captured = capsys.readouterr()
        assert "Loaded 3 seeds" in captured.out

    def test_run_fuzz_with_output(self, temp_dir, capsys):
        """Test fuzzing with output directory."""
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            iterations=5,
            corpus=None,
            output=str(output_dir),
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {}

        with patch(
            "dicom_fuzzer.attacks.network.stateful.state_aware_fuzzer.StateAwareFuzzer",
            return_value=mock_fuzzer,
        ):
            result = state.run_fuzz(args)

        assert result == 0
        assert output_dir.exists()
        mock_fuzzer.save_corpus.assert_called_once()
        captured = capsys.readouterr()
        assert "Results saved" in captured.out

    def test_run_fuzz_import_error(self, capsys):
        """Test handling of import error."""
        args = argparse.Namespace(
            iterations=10,
            corpus=None,
            output=None,
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.attacks.network.stateful.state_aware_fuzzer.StateAwareFuzzer",
            side_effect=ImportError("Module not found"),
        ):
            result = state.run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not available" in captured.out

    def test_run_fuzz_exception_verbose(self, capsys):
        """Test exception handling with verbose flag."""
        args = argparse.Namespace(
            iterations=10,
            corpus=None,
            output=None,
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.attacks.network.stateful.state_aware_fuzzer.StateAwareFuzzer",
            side_effect=RuntimeError("Test error"),
        ):
            result = state.run_fuzz(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Fuzzing failed" in captured.out

    def test_run_fuzz_empty_corpus(self, temp_dir, capsys):
        """Test fuzzing with empty corpus directory."""
        corpus_dir = temp_dir / "empty_corpus"
        corpus_dir.mkdir()

        args = argparse.Namespace(
            iterations=5,
            corpus=str(corpus_dir),
            output=None,
            verbose=False,
        )

        mock_fuzzer = MagicMock()
        mock_fuzzer.get_statistics.return_value = {}

        with patch(
            "dicom_fuzzer.attacks.network.stateful.state_aware_fuzzer.StateAwareFuzzer",
            return_value=mock_fuzzer,
        ):
            result = state.run_fuzz(args)

        assert result == 0
        # add_seed should not be called for empty corpus
        mock_fuzzer.add_seed.assert_not_called()


class TestRunExportSm:
    """Test run_export_sm function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_export_sm_success(self, temp_dir, capsys):
        """Test successful state machine export."""
        output_file = temp_dir / "state_machine.json"

        args = argparse.Namespace(export_sm=str(output_file))

        mock_fuzzer = MagicMock()
        mock_fuzzer.export_state_machine.return_value = {
            "states": ["STA1", "STA6"],
            "transitions": [],
        }

        with patch(
            "dicom_fuzzer.attacks.network.stateful.state_aware_fuzzer.StateAwareFuzzer",
            return_value=mock_fuzzer,
        ):
            result = state.run_export_sm(args)

        assert result == 0
        assert output_file.exists()

        # Verify JSON content
        with open(output_file) as f:
            data = json.load(f)
        assert "states" in data

        captured = capsys.readouterr()
        assert "State machine exported" in captured.out

    def test_export_sm_failure(self, temp_dir, capsys):
        """Test export failure."""
        output_file = temp_dir / "output.json"
        args = argparse.Namespace(export_sm=str(output_file))

        with patch(
            "dicom_fuzzer.attacks.network.stateful.state_aware_fuzzer.StateAwareFuzzer",
            side_effect=RuntimeError("Export failed"),
        ):
            result = state.run_export_sm(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Export failed" in captured.out


class TestRunListStates:
    """Test run_list_states function."""

    def test_list_states_output(self, capsys):
        """Test list states displays all states."""
        args = argparse.Namespace()

        result = state.run_list_states(args)

        assert result == 0
        captured = capsys.readouterr()

        # Verify all states are listed
        assert "STA1" in captured.out
        assert "STA2" in captured.out
        assert "STA3" in captured.out
        assert "STA5" in captured.out
        assert "STA6" in captured.out
        assert "STA7" in captured.out
        assert "STA13" in captured.out

        # Verify descriptions
        assert "Idle" in captured.out
        assert "Established" in captured.out
        assert "DICOM PS3.7" in captured.out


class TestMain:
    """Test main function."""

    def test_main_fuzz(self):
        """Test main with --fuzz."""
        with patch.object(state, "run_fuzz", return_value=0) as mock_run:
            result = state.main(["--fuzz"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_export_sm(self):
        """Test main with --export-sm."""
        with patch.object(state, "run_export_sm", return_value=0) as mock_run:
            result = state.main(["--export-sm", "output.json"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_list_states(self):
        """Test main with --list-states."""
        with patch.object(state, "run_list_states", return_value=0) as mock_run:
            result = state.main(["--list-states"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_no_args(self, capsys):
        """Test main with no arguments shows help."""
        with pytest.raises(SystemExit) as exc_info:
            state.main([])

        assert exc_info.value.code != 0

    def test_main_none_argv(self):
        """Test main with None argv uses sys.argv."""
        with patch("sys.argv", ["state", "--list-states"]):
            with patch.object(state, "run_list_states", return_value=0) as mock_run:
                result = state.main(None)

        assert result == 0
        mock_run.assert_called_once()
