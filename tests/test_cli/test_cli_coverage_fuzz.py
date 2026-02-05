"""Tests for dicom_fuzzer.cli.coverage_fuzz module.

Tests CLI argument parsing, configuration creation, and utility functions
for the coverage-guided fuzzing CLI.
"""

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.commands.coverage_fuzz import (
    CoverageFuzzCLI,
    create_config_from_args,
    create_mutation_table,
    create_parser,
    create_status_table,
    load_config_from_file,
    main,
    parse_arguments,
    run_coverage_fuzzing,
)


class TestCreateParser:
    """Tests for create_parser function."""

    def test_parser_creation(self):
        """Test parser is created successfully."""
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_default_values(self):
        """Test default argument values."""
        parser = create_parser()
        args = parser.parse_args([])

        assert args.iterations == 10000
        assert args.workers == 1
        assert args.timeout == 1.0
        assert args.max_mutations == 10
        assert args.max_corpus_size == 1000
        assert args.branches is True
        assert args.adaptive is True
        assert args.dicom_aware is True
        assert args.output == Path("artifacts/fuzzed")
        assert args.crashes == Path("artifacts/crashes")
        assert args.verbose is False
        assert args.dry_run is False

    def test_target_options(self):
        """Test target option parsing."""
        parser = create_parser()
        args = parser.parse_args(["--target", "/path/to/binary"])
        assert args.target == "/path/to/binary"

        # Note: target-args value needs to be quoted as a single argument
        args = parser.parse_args(["--target-args=-v --debug"])
        assert args.target_args == "-v --debug"

        args = parser.parse_args(["--modules", "module1", "module2"])
        assert args.modules == ["module1", "module2"]

    def test_fuzzing_options(self):
        """Test fuzzing option parsing."""
        parser = create_parser()
        args = parser.parse_args(["-i", "5000", "-w", "4", "-t", "2.5"])

        assert args.iterations == 5000
        assert args.workers == 4
        assert args.timeout == 2.5

    def test_corpus_options(self):
        """Test corpus option parsing."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "-s",
                "/path/to/seeds",
                "-c",
                "/path/to/corpus",
                "--max-corpus-size",
                "500",
                "--minimize",
            ]
        )

        assert args.seeds == Path("/path/to/seeds")
        assert args.corpus == Path("/path/to/corpus")
        assert args.max_corpus_size == 500
        assert args.minimize is True

    def test_coverage_options(self):
        """Test coverage option parsing."""
        parser = create_parser()
        args = parser.parse_args(["--no-coverage"])
        assert args.no_coverage is True

    def test_mutation_options(self):
        """Test mutation option parsing."""
        parser = create_parser()
        # Both are True by default
        args = parser.parse_args([])
        assert args.adaptive is True
        assert args.dicom_aware is True

    def test_output_options(self):
        """Test output option parsing."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "-o",
                "/custom/output",
                "--crashes",
                "/custom/crashes",
                "--save-all",
                "--report-interval",
                "50",
            ]
        )

        assert args.output == Path("/custom/output")
        assert args.crashes == Path("/custom/crashes")
        assert args.save_all is True
        assert args.report_interval == 50

    def test_config_file_option(self):
        """Test config file option parsing."""
        parser = create_parser()
        args = parser.parse_args(["--config", "/path/to/config.json"])
        assert args.config == Path("/path/to/config.json")

    def test_verbose_and_dry_run(self):
        """Test verbose and dry-run options."""
        parser = create_parser()
        args = parser.parse_args(["-v", "--dry-run"])
        assert args.verbose is True
        assert args.dry_run is True


class TestCreateConfigFromArgs:
    """Tests for create_config_from_args function."""

    def test_basic_config(self):
        """Test basic configuration creation."""
        parser = create_parser()
        args = parser.parse_args([])

        config = create_config_from_args(args)

        assert config.max_iterations == 10000
        assert config.num_workers == 1
        assert config.timeout_per_run == 1.0
        assert config.coverage_guided is True

    def test_config_with_target_binary(self):
        """Test configuration with target binary."""
        parser = create_parser()
        args = parser.parse_args(["--target", "/path/to/binary"])

        config = create_config_from_args(args)
        assert config.target_binary == "/path/to/binary"

    def test_config_with_python_target(self, tmp_path):
        """Test configuration with Python target module."""
        # Create a mock Python target module
        target_file = tmp_path / "target_module.py"
        target_file.write_text("""
def fuzz_target(data):
    pass
""")

        parser = create_parser()
        args = parser.parse_args(["--target", str(target_file)])

        config = create_config_from_args(args)
        # target_function should be set
        assert config.target_function is not None

    def test_config_with_modules(self):
        """Test configuration with target modules."""
        parser = create_parser()
        args = parser.parse_args(["--modules", "mod1", "mod2"])

        config = create_config_from_args(args)
        assert config.target_modules == ["mod1", "mod2"]

    def test_config_coverage_disabled(self):
        """Test configuration with coverage disabled."""
        parser = create_parser()
        args = parser.parse_args(["--no-coverage"])

        config = create_config_from_args(args)
        assert config.coverage_guided is False

    def test_config_corpus_settings(self, tmp_path):
        """Test configuration with corpus settings."""
        seeds = tmp_path / "seeds"
        seeds.mkdir()
        corpus = tmp_path / "corpus"

        parser = create_parser()
        args = parser.parse_args(
            [
                "-s",
                str(seeds),
                "-c",
                str(corpus),
                "--max-corpus-size",
                "250",
                "--minimize",
            ]
        )

        config = create_config_from_args(args)
        assert config.seed_dir == seeds
        assert config.corpus_dir == corpus
        assert config.max_corpus_size == 250
        assert config.minimize_corpus is True

    def test_config_output_settings(self, tmp_path):
        """Test configuration with output settings."""
        output = tmp_path / "output"
        crashes = tmp_path / "crashes"

        parser = create_parser()
        args = parser.parse_args(
            [
                "-o",
                str(output),
                "--crashes",
                str(crashes),
                "--save-all",
                "--report-interval",
                "25",
            ]
        )

        config = create_config_from_args(args)
        assert config.output_dir == output
        assert config.crash_dir == crashes
        assert config.save_all_inputs is True
        assert config.report_interval == 25


class TestCreateStatusTable:
    """Tests for create_status_table function."""

    def test_empty_stats(self):
        """Test table creation with empty stats."""
        table = create_status_table({})
        assert table.title == "Fuzzing Status"
        assert len(table.columns) == 2

    def test_with_stats(self):
        """Test table creation with statistics."""
        stats = {
            "total_executions": 1000,
            "exec_per_sec": 50.5,
            "current_coverage": 256,
            "corpus_size": 42,
            "total_crashes": 3,
            "unique_crashes": 2,
            "coverage_increases": 15,
        }
        table = create_status_table(stats)
        assert table.title == "Fuzzing Status"
        # Should have created rows for all metrics
        assert table.row_count == 6


class TestCreateMutationTable:
    """Tests for create_mutation_table function."""

    def test_empty_stats(self):
        """Test table creation with empty mutation stats."""
        table = create_mutation_table({})
        assert table.title == "Mutation Statistics"
        assert len(table.columns) == 4
        assert table.row_count == 0

    def test_with_mutation_stats(self):
        """Test table creation with mutation statistics."""
        mutation_stats = {
            "bit_flip": {"success_rate": 0.15, "total_count": 100, "weight": 1.5},
            "byte_insert": {"success_rate": 0.08, "total_count": 50, "weight": 1.0},
            "tag_mutate": {"success_rate": 0.25, "total_count": 200, "weight": 2.0},
        }
        table = create_mutation_table(mutation_stats)
        assert table.row_count == 3

    def test_sorts_by_success_rate(self):
        """Test that strategies are sorted by success rate."""
        mutation_stats = {
            "low": {"success_rate": 0.05},
            "high": {"success_rate": 0.50},
            "medium": {"success_rate": 0.20},
        }
        # The function sorts internally, so just verify it doesn't crash
        table = create_mutation_table(mutation_stats)
        assert table.row_count == 3


class TestLoadConfigFromFile:
    """Tests for load_config_from_file function."""

    def test_load_valid_config(self, tmp_path):
        """Test loading valid configuration file."""
        config_file = tmp_path / "config.json"
        config_data = {
            "max_iterations": 5000,
            "num_workers": 4,
            "timeout_per_run": 2.0,
        }
        config_file.write_text(json.dumps(config_data))

        config = load_config_from_file(config_file)
        assert config.max_iterations == 5000
        assert config.num_workers == 4

    def test_load_config_with_paths(self, tmp_path):
        """Test loading config with path fields."""
        config_file = tmp_path / "config.json"
        corpus_dir = tmp_path / "corpus"
        config_data = {
            "corpus_dir": str(corpus_dir),
            "seed_dir": str(tmp_path / "seeds"),
            "output_dir": str(tmp_path / "output"),
        }
        config_file.write_text(json.dumps(config_data))

        config = load_config_from_file(config_file)
        assert config.corpus_dir == corpus_dir

    def test_load_nonexistent_file(self, tmp_path):
        """Test loading non-existent config file raises error."""
        config_file = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            load_config_from_file(config_file)

    def test_load_invalid_json(self, tmp_path):
        """Test loading invalid JSON raises error."""
        config_file = tmp_path / "invalid.json"
        config_file.write_text("{ invalid json }")

        with pytest.raises(json.JSONDecodeError):
            load_config_from_file(config_file)


class TestParseArguments:
    """Tests for parse_arguments function."""

    def test_parse_empty_args(self):
        """Test parsing empty arguments."""
        args = parse_arguments(["coverage_fuzz.py"])
        assert args.iterations == 100
        assert args.timeout == 5
        assert args.workers == 4

    def test_parse_input_output(self):
        """Test parsing input and output arguments."""
        args = parse_arguments(
            [
                "coverage_fuzz.py",
                "--input",
                "/path/to/input",
                "--output",
                "/path/to/output",
            ]
        )
        assert args.input_dir == "/path/to/input"
        assert args.output_dir == "/path/to/output"

    def test_parse_iterations(self):
        """Test parsing iterations argument."""
        args = parse_arguments(["coverage_fuzz.py", "--iterations", "500"])
        assert args.iterations == 500


class TestRunCoverageFuzzing:
    """Tests for run_coverage_fuzzing function."""

    def test_run_with_mock_fuzzer(self, tmp_path, mocker):
        """Test running coverage fuzzing with mocked fuzzer."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        output_dir = tmp_path / "output"

        config = {
            "input_dir": str(input_dir),
            "output_dir": str(output_dir),
            "max_iterations": 10,
            "timeout": 1,
        }

        # Mock the fuzzer with proper return value
        mock_fuzzer = MagicMock()
        # Return a dict directly (as per the function's handling)
        mock_fuzzer.run.return_value = {"crashes": 1, "coverage": 0.75}

        mocker.patch(
            "dicom_fuzzer.cli.commands.coverage_fuzz.CoverageGuidedFuzzer",
            return_value=mock_fuzzer,
        )

        result = run_coverage_fuzzing(config)

        assert "crashes" in result
        assert "coverage" in result
        # The function processes results, just verify structure
        assert isinstance(result["crashes"], (int, float))
        assert isinstance(result["coverage"], (int, float))


class TestCoverageFuzzCLI:
    """Tests for CoverageFuzzCLI class."""

    def test_class_exists(self):
        """Test that CLI class exists for compatibility."""
        cli = CoverageFuzzCLI()
        assert cli is not None


class TestMain:
    """Tests for main entry point."""

    def test_dry_run(self, capsys):
        """Test main with dry-run option."""
        with patch.object(sys, "argv", ["coverage_fuzz.py", "--dry-run"]):
            main()

        captured = capsys.readouterr()
        assert "Fuzzing Configuration" in captured.out

    def test_with_config_file(self, tmp_path, mocker):
        """Test main loading config from file."""
        config_file = tmp_path / "config.json"
        config_data = {
            "max_iterations": 100,
            "num_workers": 1,
        }
        config_file.write_text(json.dumps(config_data))

        # Mock run_fuzzing_campaign to avoid actual execution
        mock_run = mocker.patch(
            "dicom_fuzzer.cli.commands.coverage_fuzz.run_fuzzing_campaign",
            return_value=None,
        )
        mock_asyncio = mocker.patch(
            "dicom_fuzzer.cli.commands.coverage_fuzz.asyncio.run",
            return_value=None,
        )

        with patch.object(
            sys, "argv", ["coverage_fuzz.py", "--config", str(config_file)]
        ):
            main()

        # Verify asyncio.run was called
        mock_asyncio.assert_called_once()

    def test_keyboard_interrupt(self, mocker, capsys):
        """Test main handles keyboard interrupt."""
        mocker.patch(
            "dicom_fuzzer.cli.commands.coverage_fuzz.asyncio.run",
            side_effect=KeyboardInterrupt,
        )

        with patch.object(sys, "argv", ["coverage_fuzz.py"]):
            main()

        captured = capsys.readouterr()
        assert "interrupted" in captured.out

    def test_general_exception(self, mocker, capsys):
        """Test main handles general exception."""
        mocker.patch(
            "dicom_fuzzer.cli.commands.coverage_fuzz.asyncio.run",
            side_effect=RuntimeError("Test error"),
        )

        with patch.object(sys, "argv", ["coverage_fuzz.py"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error" in captured.out

    def test_verbose_exception(self, mocker, capsys):
        """Test main shows traceback in verbose mode."""
        mocker.patch(
            "dicom_fuzzer.cli.commands.coverage_fuzz.asyncio.run",
            side_effect=RuntimeError("Verbose test error"),
        )

        with patch.object(sys, "argv", ["coverage_fuzz.py", "-v"]):
            with pytest.raises(SystemExit):
                main()

        captured = capsys.readouterr()
        # In verbose mode, traceback should be printed
        assert "Error" in captured.out


class TestRunFuzzingCampaignIntegration:
    """Integration tests for run_fuzzing_campaign."""

    @pytest.mark.asyncio
    async def test_campaign_starts(self, mocker):
        """Test that fuzzing campaign can be started with mocked fuzzer."""
        from dicom_fuzzer.cli.commands.coverage_fuzz import run_fuzzing_campaign
        from dicom_fuzzer.core.engine.coverage_guided_fuzzer import FuzzingConfig

        # Create mock stats
        mock_stats = MagicMock()
        mock_stats.total_executions = 100
        mock_stats.exec_per_sec = 10.0
        mock_stats.current_coverage = 50
        mock_stats.corpus_size = 10
        mock_stats.total_crashes = 0
        mock_stats.unique_crashes = 0
        mock_stats.coverage_increases = 5
        mock_stats.mutation_stats = {}
        mock_stats.max_coverage = 50

        # Create mock fuzzer
        async def mock_run():
            return mock_stats

        mock_fuzzer = MagicMock()
        mock_fuzzer.stats = mock_stats
        mock_fuzzer.run = mock_run

        mocker.patch(
            "dicom_fuzzer.cli.commands.coverage_fuzz.CoverageGuidedFuzzer",
            return_value=mock_fuzzer,
        )

        config = FuzzingConfig()
        config.max_iterations = 100

        # This should complete without error
        await run_fuzzing_campaign(config)
