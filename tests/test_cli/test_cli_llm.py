"""Tests for LLM-assisted fuzzing CLI subcommand.

Tests for dicom_fuzzer.cli.llm module.
"""

import argparse
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli import llm


class TestConstants:
    """Test module constants."""

    def test_supported_backends(self):
        """Test SUPPORTED_BACKENDS contains expected backends."""
        assert "mock" in llm.SUPPORTED_BACKENDS
        assert "openai" in llm.SUPPORTED_BACKENDS
        assert "anthropic" in llm.SUPPORTED_BACKENDS
        assert "ollama" in llm.SUPPORTED_BACKENDS


class TestCreateParser:
    """Test create_parser function."""

    def test_parser_creation(self):
        """Test parser is created with required arguments."""
        parser = llm.create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_generate_action(self):
        """Test --generate argument."""
        parser = llm.create_parser()
        args = parser.parse_args(["--generate"])
        assert args.generate is True

    def test_parser_list_backends_action(self):
        """Test --list-backends argument."""
        parser = llm.create_parser()
        args = parser.parse_args(["--list-backends"])
        assert args.list_backends is True

    def test_parser_mutually_exclusive(self):
        """Test that actions are mutually exclusive."""
        parser = llm.create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--generate", "--list-backends"])

    def test_parser_backend_options(self):
        """Test backend options."""
        parser = llm.create_parser()
        args = parser.parse_args(
            ["--generate", "--backend", "openai", "--model", "gpt-4o"]
        )
        assert args.backend == "openai"
        assert args.model == "gpt-4o"

    def test_parser_output_options(self):
        """Test output options."""
        parser = llm.create_parser()
        args = parser.parse_args(["--generate", "-o", "./output", "-c", "20", "-v"])
        assert args.output == "./output"
        assert args.count == 20
        assert args.verbose is True

    def test_parser_defaults(self):
        """Test default values."""
        parser = llm.create_parser()
        args = parser.parse_args(["--generate"])
        assert args.backend == "mock"
        assert args.model == "gpt-4"
        assert args.output == "./llm_output"
        assert args.count == 10
        assert args.verbose is False


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
            backend="mock",
            model="test-model",
            output=str(output_dir),
            count=3,
            verbose=False,
        )

        # Create mock mutations
        mock_mutations = []
        for i in range(3):
            mock_mutation = MagicMock()
            mock_mutation.target_element = "(0010,0010)"
            mock_mutation.to_dict.return_value = {
                "id": i,
                "target": "(0010,0010)",
                "strategy": "boundary",
            }
            mock_mutations.append(mock_mutation)

        mock_fuzzer = MagicMock()
        mock_fuzzer.generate_fuzzing_corpus.return_value = mock_mutations

        with patch(
            "dicom_fuzzer.core.llm_fuzzer.create_llm_fuzzer", return_value=mock_fuzzer
        ):
            result = llm.run_generate(args)

        assert result == 0
        assert output_dir.exists()

        # Verify output files
        mutation_files = list(output_dir.glob("mutation_*.json"))
        assert len(mutation_files) == 3

        captured = capsys.readouterr()
        assert "LLM-Assisted Mutation Generation" in captured.out
        assert "Generated 3 mutation specifications" in captured.out

    def test_run_generate_verbose(self, temp_dir, capsys):
        """Test generation with verbose output."""
        output_dir = temp_dir / "output"

        args = argparse.Namespace(
            backend="mock",
            model="test-model",
            output=str(output_dir),
            count=2,
            verbose=True,
        )

        mock_mutation = MagicMock()
        mock_mutation.target_element = "(0008,0018)"
        mock_mutation.to_dict.return_value = {"id": 0}

        mock_fuzzer = MagicMock()
        mock_fuzzer.generate_fuzzing_corpus.return_value = [
            mock_mutation,
            mock_mutation,
        ]

        with patch(
            "dicom_fuzzer.core.llm_fuzzer.create_llm_fuzzer", return_value=mock_fuzzer
        ):
            result = llm.run_generate(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "(0008,0018)" in captured.out

    def test_run_generate_import_error(self, temp_dir, capsys):
        """Test handling of import error."""
        args = argparse.Namespace(
            backend="mock",
            model="test-model",
            output=str(temp_dir / "output"),
            count=5,
            verbose=False,
        )

        with patch(
            "dicom_fuzzer.core.llm_fuzzer.create_llm_fuzzer",
            side_effect=ImportError("Module not found"),
        ):
            result = llm.run_generate(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not available" in captured.out

    def test_run_generate_exception_verbose(self, temp_dir, capsys):
        """Test exception handling with verbose flag."""
        args = argparse.Namespace(
            backend="openai",
            model="gpt-4",
            output=str(temp_dir / "output"),
            count=5,
            verbose=True,
        )

        with patch(
            "dicom_fuzzer.core.llm_fuzzer.create_llm_fuzzer",
            side_effect=RuntimeError("API error"),
        ):
            result = llm.run_generate(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Generation failed" in captured.out

    def test_run_generate_creates_output_dir(self, temp_dir, capsys):
        """Test that output directory is created if it doesn't exist."""
        output_dir = temp_dir / "nested" / "output"

        args = argparse.Namespace(
            backend="mock",
            model="test-model",
            output=str(output_dir),
            count=1,
            verbose=False,
        )

        mock_mutation = MagicMock()
        mock_mutation.target_element = "(0010,0010)"
        mock_mutation.to_dict.return_value = {"id": 0}

        mock_fuzzer = MagicMock()
        mock_fuzzer.generate_fuzzing_corpus.return_value = [mock_mutation]

        with patch(
            "dicom_fuzzer.core.llm_fuzzer.create_llm_fuzzer", return_value=mock_fuzzer
        ):
            result = llm.run_generate(args)

        assert result == 0
        assert output_dir.exists()


class TestRunListBackends:
    """Test run_list_backends function."""

    def test_list_backends_output(self, capsys):
        """Test list backends displays all backends."""
        args = argparse.Namespace()

        result = llm.run_list_backends(args)

        assert result == 0
        captured = capsys.readouterr()

        # Verify backends are listed
        assert "mock" in captured.out
        assert "openai" in captured.out
        assert "anthropic" in captured.out
        assert "ollama" in captured.out

        # Verify descriptions
        assert "Mock backend" in captured.out or "testing" in captured.out
        assert "OpenAI" in captured.out
        assert "Anthropic" in captured.out or "Claude" in captured.out
        assert "Ollama" in captured.out or "local" in captured.out

    def test_list_backends_env_vars(self, capsys):
        """Test list backends shows environment variable status."""
        args = argparse.Namespace()

        # Clear env vars first
        with patch.dict(os.environ, {}, clear=True):
            result = llm.run_list_backends(args)

        assert result == 0
        captured = capsys.readouterr()

        # Verify env var info
        assert "OPENAI_API_KEY" in captured.out
        assert "ANTHROPIC_API_KEY" in captured.out

    def test_list_backends_with_api_key(self, capsys):
        """Test list backends shows configured status when API key present."""
        args = argparse.Namespace()

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            result = llm.run_list_backends(args)

        assert result == 0
        captured = capsys.readouterr()
        # Should show openai as available
        assert "[+] openai" in captured.out or "configured" in captured.out


class TestMain:
    """Test main function."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_main_generate(self):
        """Test main with --generate."""
        with patch.object(llm, "run_generate", return_value=0) as mock_run:
            result = llm.main(["--generate"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_list_backends(self):
        """Test main with --list-backends."""
        with patch.object(llm, "run_list_backends", return_value=0) as mock_run:
            result = llm.main(["--list-backends"])

        assert result == 0
        mock_run.assert_called_once()

    def test_main_no_args(self):
        """Test main with no arguments shows help."""
        with pytest.raises(SystemExit) as exc_info:
            llm.main([])

        assert exc_info.value.code != 0

    def test_main_none_argv(self):
        """Test main with None argv uses sys.argv."""
        with patch("sys.argv", ["llm", "--list-backends"]):
            with patch.object(llm, "run_list_backends", return_value=0) as mock_run:
                result = llm.main(None)

        assert result == 0
        mock_run.assert_called_once()
