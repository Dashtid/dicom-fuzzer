"""Tests for llm.py - LLM-Assisted Fuzzing CLI.

Tests cover argument parsing, mutation generation, and backend listing.
"""

import argparse
import os
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.llm import (
    SUPPORTED_BACKENDS,
    create_parser,
    main,
    run_generate,
    run_list_backends,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_requires_action(self):
        """Test that parser requires mutually exclusive action."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_generate_action(self):
        """Test --generate action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--generate"])

        assert args.generate is True
        assert args.list_backends is False

    def test_parser_list_backends_action(self):
        """Test --list-backends action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--list-backends"])

        assert args.list_backends is True
        assert args.generate is False

    def test_parser_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--generate", "--list-backends"])

    def test_parser_backend_choices(self):
        """Test backend argument choices."""
        parser = create_parser()

        for backend in SUPPORTED_BACKENDS:
            args = parser.parse_args(["--generate", "--backend", backend])
            assert args.backend == backend

    def test_parser_invalid_backend(self):
        """Test invalid backend raises error."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--generate", "--backend", "invalid"])

    def test_parser_defaults(self):
        """Test default values."""
        parser = create_parser()
        args = parser.parse_args(["--generate"])

        assert args.backend == "mock"
        assert args.model == "gpt-4"
        assert args.output == "./artifacts/llm"
        assert args.count == 10
        assert args.verbose is False

    def test_parser_output_options(self):
        """Test output options."""
        parser = create_parser()
        args = parser.parse_args(
            ["--generate", "-o", "/custom/output", "-c", "20", "-v"]
        )

        assert args.output == "/custom/output"
        assert args.count == 20
        assert args.verbose is True


class TestRunGenerate:
    """Test run_generate function."""

    def test_generate_success(self, tmp_path, capsys):
        """Test successful mutation generation."""
        mock_mutation = MagicMock()
        mock_mutation.to_dict.return_value = {"target": "PatientID", "mutation": "test"}
        mock_mutation.target_element = "PatientID"

        mock_fuzzer = MagicMock()
        mock_fuzzer.generate_fuzzing_corpus.return_value = [mock_mutation]

        mock_module = MagicMock()
        mock_module.create_llm_fuzzer = MagicMock(return_value=mock_fuzzer)

        args = argparse.Namespace(
            backend="mock",
            model="gpt-4",
            output=str(tmp_path),
            count=5,
            verbose=True,
        )

        with patch.dict("sys.modules", {"dicom_fuzzer.core.llm_fuzzer": mock_module}):
            result = run_generate(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "LLM-Assisted Mutation Generation" in captured.out
        assert "Generated" in captured.out

    def test_generate_creates_output_dir(self, tmp_path, capsys):
        """Test that generate creates output directory."""
        output_dir = tmp_path / "new_output"

        mock_fuzzer = MagicMock()
        mock_fuzzer.generate_fuzzing_corpus.return_value = []

        mock_module = MagicMock()
        mock_module.create_llm_fuzzer = MagicMock(return_value=mock_fuzzer)

        args = argparse.Namespace(
            backend="mock",
            model="gpt-4",
            output=str(output_dir),
            count=5,
            verbose=False,
        )

        with patch.dict("sys.modules", {"dicom_fuzzer.core.llm_fuzzer": mock_module}):
            run_generate(args)

        assert output_dir.exists()

    def test_generate_import_error(self, tmp_path, capsys):
        """Test handling of import error."""
        args = argparse.Namespace(
            backend="mock",
            model="gpt-4",
            output=str(tmp_path),
            count=5,
            verbose=False,
        )

        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if "llm_fuzzer" in name:
                raise ImportError("Module not available")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", mock_import):
            result = run_generate(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "LLM fuzzer not available" in captured.out

    def test_generate_generic_error(self, tmp_path, capsys):
        """Test handling of generic exception."""
        mock_module = MagicMock()
        mock_module.create_llm_fuzzer = MagicMock(
            side_effect=RuntimeError("Test error")
        )

        args = argparse.Namespace(
            backend="mock",
            model="gpt-4",
            output=str(tmp_path),
            count=5,
            verbose=True,
        )

        with patch.dict("sys.modules", {"dicom_fuzzer.core.llm_fuzzer": mock_module}):
            result = run_generate(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Generation failed" in captured.out


class TestRunListBackends:
    """Test run_list_backends function."""

    def test_list_backends_returns_zero(self, capsys):
        """Test that list_backends returns 0."""
        args = argparse.Namespace()
        result = run_list_backends(args)
        assert result == 0

    def test_list_backends_output(self, capsys):
        """Test that list_backends prints backend information."""
        args = argparse.Namespace()
        run_list_backends(args)
        captured = capsys.readouterr()

        assert "Available LLM Backends" in captured.out
        assert "mock" in captured.out
        assert "openai" in captured.out
        assert "anthropic" in captured.out
        assert "ollama" in captured.out

    def test_list_backends_shows_env_vars(self, capsys):
        """Test that list_backends shows environment variable info."""
        args = argparse.Namespace()
        run_list_backends(args)
        captured = capsys.readouterr()

        assert "OPENAI_API_KEY" in captured.out
        assert "ANTHROPIC_API_KEY" in captured.out

    def test_list_backends_with_api_key(self, capsys):
        """Test list_backends shows configured status when API key set."""
        args = argparse.Namespace()

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            run_list_backends(args)

        captured = capsys.readouterr()
        assert "configured" in captured.out


class TestMain:
    """Test main entry point."""

    def test_main_generate_dispatch(self, tmp_path):
        """Test main dispatches to run_generate."""
        with patch("dicom_fuzzer.cli.llm.run_generate", return_value=0) as mock_run:
            result = main(["--generate", "-o", str(tmp_path)])
            assert result == 0
            mock_run.assert_called_once()

    def test_main_list_backends_dispatch(self, capsys):
        """Test main dispatches to run_list_backends."""
        result = main(["--list-backends"])
        assert result == 0
        captured = capsys.readouterr()
        assert "Available LLM Backends" in captured.out

    def test_main_no_args_fails(self, capsys):
        """Test main with no args fails."""
        with pytest.raises(SystemExit):
            main([])
