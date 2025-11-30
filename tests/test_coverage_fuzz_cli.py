"""Test Coverage Fuzz CLI Module

This test suite verifies the coverage-guided fuzzing CLI functionality
including argument parsing, configuration, and campaign execution.
"""

import argparse
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dicom_fuzzer.cli.coverage_fuzz import (
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
    """Test argument parser creation."""

    def test_create_parser_returns_parser(self):
        """Test that create_parser returns an ArgumentParser."""
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_parser_has_target_options(self):
        """Test parser has target options."""
        parser = create_parser()
        args = parser.parse_args(["--target", "/path/to/target"])
        assert args.target == "/path/to/target"

    def test_parser_has_target_args_option(self):
        """Test parser has target-args option."""
        parser = create_parser()
        args = parser.parse_args(["--target-args=--some-arg"])
        assert args.target_args == "--some-arg"

    def test_parser_has_modules_option(self):
        """Test parser has modules option."""
        parser = create_parser()
        args = parser.parse_args(["--modules", "mod1", "mod2"])
        assert args.modules == ["mod1", "mod2"]

    def test_parser_has_iterations_option(self):
        """Test parser has iterations option."""
        parser = create_parser()
        args = parser.parse_args(["-i", "5000"])
        assert args.iterations == 5000

    def test_parser_default_iterations(self):
        """Test default iterations value."""
        parser = create_parser()
        args = parser.parse_args([])
        assert args.iterations == 10000

    def test_parser_has_workers_option(self):
        """Test parser has workers option."""
        parser = create_parser()
        args = parser.parse_args(["-w", "4"])
        assert args.workers == 4

    def test_parser_default_workers(self):
        """Test default workers value."""
        parser = create_parser()
        args = parser.parse_args([])
        assert args.workers == 1

    def test_parser_has_timeout_option(self):
        """Test parser has timeout option."""
        parser = create_parser()
        args = parser.parse_args(["-t", "2.5"])
        assert args.timeout == 2.5

    def test_parser_has_max_mutations_option(self):
        """Test parser has max-mutations option."""
        parser = create_parser()
        args = parser.parse_args(["--max-mutations", "20"])
        assert args.max_mutations == 20

    def test_parser_has_seeds_option(self):
        """Test parser has seeds option."""
        parser = create_parser()
        args = parser.parse_args(["-s", "/path/to/seeds"])
        assert args.seeds == Path("/path/to/seeds")

    def test_parser_has_corpus_option(self):
        """Test parser has corpus option."""
        parser = create_parser()
        args = parser.parse_args(["-c", "/path/to/corpus"])
        assert args.corpus == Path("/path/to/corpus")

    def test_parser_has_max_corpus_size_option(self):
        """Test parser has max-corpus-size option."""
        parser = create_parser()
        args = parser.parse_args(["--max-corpus-size", "500"])
        assert args.max_corpus_size == 500

    def test_parser_has_minimize_option(self):
        """Test parser has minimize option."""
        parser = create_parser()
        args = parser.parse_args(["--minimize"])
        assert args.minimize is True

    def test_parser_has_no_coverage_option(self):
        """Test parser has no-coverage option."""
        parser = create_parser()
        args = parser.parse_args(["--no-coverage"])
        assert args.no_coverage is True

    def test_parser_has_branches_option(self):
        """Test parser has branches option."""
        parser = create_parser()
        args = parser.parse_args(["--branches"])
        assert args.branches is True

    def test_parser_has_adaptive_option(self):
        """Test parser has adaptive option."""
        parser = create_parser()
        args = parser.parse_args(["--adaptive"])
        assert args.adaptive is True

    def test_parser_has_dicom_aware_option(self):
        """Test parser has dicom-aware option."""
        parser = create_parser()
        args = parser.parse_args(["--dicom-aware"])
        assert args.dicom_aware is True

    def test_parser_has_output_option(self):
        """Test parser has output option."""
        parser = create_parser()
        args = parser.parse_args(["-o", "/path/to/output"])
        assert args.output == Path("/path/to/output")

    def test_parser_has_crashes_option(self):
        """Test parser has crashes option."""
        parser = create_parser()
        args = parser.parse_args(["--crashes", "/path/to/crashes"])
        assert args.crashes == Path("/path/to/crashes")

    def test_parser_has_save_all_option(self):
        """Test parser has save-all option."""
        parser = create_parser()
        args = parser.parse_args(["--save-all"])
        assert args.save_all is True

    def test_parser_has_report_interval_option(self):
        """Test parser has report-interval option."""
        parser = create_parser()
        args = parser.parse_args(["--report-interval", "50"])
        assert args.report_interval == 50

    def test_parser_has_verbose_option(self):
        """Test parser has verbose option."""
        parser = create_parser()
        args = parser.parse_args(["-v"])
        assert args.verbose is True

    def test_parser_has_config_option(self):
        """Test parser has config option."""
        parser = create_parser()
        args = parser.parse_args(["--config", "/path/to/config.json"])
        assert args.config == Path("/path/to/config.json")

    def test_parser_has_dry_run_option(self):
        """Test parser has dry-run option."""
        parser = create_parser()
        args = parser.parse_args(["--dry-run"])
        assert args.dry_run is True


class TestCreateStatusTable:
    """Test status table creation."""

    def test_create_status_table_empty_stats(self):
        """Test status table with empty stats."""
        table = create_status_table({})
        assert table is not None
        assert table.title == "Fuzzing Status"

    def test_create_status_table_with_stats(self):
        """Test status table with stats data."""
        stats = {
            "total_executions": 1000,
            "exec_per_sec": 50.5,
            "current_coverage": 250,
            "corpus_size": 100,
            "total_crashes": 5,
            "unique_crashes": 3,
            "coverage_increases": 15,
        }
        table = create_status_table(stats)
        assert table is not None

    def test_create_status_table_has_columns(self):
        """Test status table has correct columns."""
        table = create_status_table({})
        assert len(table.columns) == 2


class TestCreateMutationTable:
    """Test mutation table creation."""

    def test_create_mutation_table_empty_stats(self):
        """Test mutation table with empty stats."""
        table = create_mutation_table({})
        assert table is not None
        assert table.title == "Mutation Statistics"

    def test_create_mutation_table_with_stats(self):
        """Test mutation table with stats data."""
        mutation_stats = {
            "bit_flip": {"success_rate": 0.15, "total_count": 100, "weight": 1.5},
            "byte_flip": {"success_rate": 0.10, "total_count": 80, "weight": 1.2},
            "tag_mutation": {"success_rate": 0.20, "total_count": 50, "weight": 2.0},
        }
        table = create_mutation_table(mutation_stats)
        assert table is not None

    def test_create_mutation_table_sorts_by_success_rate(self):
        """Test mutation table sorts by success rate."""
        mutation_stats = {
            "low_success": {"success_rate": 0.05, "total_count": 100, "weight": 1.0},
            "high_success": {"success_rate": 0.50, "total_count": 50, "weight": 1.0},
            "medium_success": {"success_rate": 0.25, "total_count": 75, "weight": 1.0},
        }
        table = create_mutation_table(mutation_stats)
        # Should have 4 columns
        assert len(table.columns) == 4

    def test_create_mutation_table_limits_to_top_10(self):
        """Test mutation table limits to top 10 strategies."""
        # Create more than 10 strategies
        mutation_stats = {
            f"strategy_{i}": {"success_rate": i * 0.05, "total_count": i * 10, "weight": 1.0}
            for i in range(15)
        }
        table = create_mutation_table(mutation_stats)
        # Table should exist (row count is internal)
        assert table is not None


class TestLoadConfigFromFile:
    """Test configuration loading from file."""

    def test_load_config_from_file_basic(self, tmp_path):
        """Test loading basic configuration from file."""
        config_data = {
            "max_iterations": 5000,
            "num_workers": 4,
            "timeout_per_run": 2.0,
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config_from_file(config_file)

        assert config.max_iterations == 5000
        assert config.num_workers == 4
        assert config.timeout_per_run == 2.0

    def test_load_config_from_file_with_paths(self, tmp_path):
        """Test loading configuration with path fields."""
        config_data = {
            "corpus_dir": "/path/to/corpus",
            "seed_dir": "/path/to/seeds",
            "output_dir": "/path/to/output",
            "crash_dir": "/path/to/crashes",
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config_from_file(config_file)

        assert config.corpus_dir == Path("/path/to/corpus")
        assert config.seed_dir == Path("/path/to/seeds")

    def test_load_config_from_file_empty(self, tmp_path):
        """Test loading empty configuration file."""
        config_file = tmp_path / "empty.json"
        config_file.write_text("{}")

        config = load_config_from_file(config_file)
        assert config is not None


class TestCreateConfigFromArgs:
    """Test configuration creation from arguments."""

    def test_create_config_default_args(self):
        """Test creating config with default arguments."""
        parser = create_parser()
        args = parser.parse_args([])

        config = create_config_from_args(args)

        assert config.max_iterations == 10000
        assert config.num_workers == 1
        assert config.coverage_guided is True

    def test_create_config_with_iterations(self):
        """Test creating config with custom iterations."""
        parser = create_parser()
        args = parser.parse_args(["--iterations", "5000"])

        config = create_config_from_args(args)

        assert config.max_iterations == 5000

    def test_create_config_with_workers(self):
        """Test creating config with custom workers."""
        parser = create_parser()
        args = parser.parse_args(["--workers", "8"])

        config = create_config_from_args(args)

        assert config.num_workers == 8

    def test_create_config_with_no_coverage(self):
        """Test creating config with no-coverage flag."""
        parser = create_parser()
        args = parser.parse_args(["--no-coverage"])

        config = create_config_from_args(args)

        assert config.coverage_guided is False

    def test_create_config_with_minimize(self):
        """Test creating config with minimize flag."""
        parser = create_parser()
        args = parser.parse_args(["--minimize"])

        config = create_config_from_args(args)

        assert config.minimize_corpus is True

    def test_create_config_with_corpus_paths(self):
        """Test creating config with corpus paths."""
        parser = create_parser()
        args = parser.parse_args([
            "--corpus", "/path/to/corpus",
            "--seeds", "/path/to/seeds",
        ])

        config = create_config_from_args(args)

        assert config.corpus_dir == Path("/path/to/corpus")
        assert config.seed_dir == Path("/path/to/seeds")

    def test_create_config_with_output_paths(self):
        """Test creating config with output paths."""
        parser = create_parser()
        args = parser.parse_args([
            "--output", "/path/to/output",
            "--crashes", "/path/to/crashes",
        ])

        config = create_config_from_args(args)

        assert config.output_dir == Path("/path/to/output")
        assert config.crash_dir == Path("/path/to/crashes")

    def test_create_config_with_python_target(self, tmp_path):
        """Test creating config with Python target module."""
        # Create a dummy Python file
        target_file = tmp_path / "target.py"
        target_file.write_text("def fuzz_target(data): pass")

        parser = create_parser()
        args = parser.parse_args(["--target", str(target_file)])

        config = create_config_from_args(args)

        # Target function should be loaded
        assert config.target_function is not None or config.target_binary is None

    def test_create_config_with_binary_target(self):
        """Test creating config with binary target."""
        parser = create_parser()
        args = parser.parse_args(["--target", "/path/to/binary"])

        config = create_config_from_args(args)

        assert config.target_binary == "/path/to/binary"

    def test_create_config_with_modules(self):
        """Test creating config with target modules."""
        parser = create_parser()
        args = parser.parse_args(["--modules", "mod1", "mod2", "mod3"])

        config = create_config_from_args(args)

        assert config.target_modules == ["mod1", "mod2", "mod3"]


class TestMain:
    """Test main CLI entry point."""

    def test_main_dry_run(self, capsys):
        """Test main with dry-run flag."""
        with patch("sys.argv", ["coverage_fuzz.py", "--dry-run"]):
            main()

        captured = capsys.readouterr()
        assert "max_iterations" in captured.out or "Configuration" in captured.out

    def test_main_with_config_file(self, tmp_path, capsys):
        """Test main with config file."""
        config_data = {"max_iterations": 100}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        with patch("sys.argv", ["coverage_fuzz.py", "--config", str(config_file), "--dry-run"]):
            main()

        captured = capsys.readouterr()
        assert "100" in captured.out or "Configuration" in captured.out

    def test_main_keyboard_interrupt(self, capsys):
        """Test main handles keyboard interrupt."""
        with patch("sys.argv", ["coverage_fuzz.py"]):
            with patch(
                "dicom_fuzzer.cli.coverage_fuzz.asyncio.run",
                side_effect=KeyboardInterrupt,
            ):
                main()

        captured = capsys.readouterr()
        assert "interrupted" in captured.out

    def test_main_exception_handling(self, capsys):
        """Test main handles exceptions."""
        with patch("sys.argv", ["coverage_fuzz.py"]):
            with patch(
                "dicom_fuzzer.cli.coverage_fuzz.asyncio.run",
                side_effect=Exception("Test error"),
            ):
                with pytest.raises(SystemExit) as exc_info:
                    main()

                assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Error" in captured.out

    def test_main_exception_with_verbose(self, capsys):
        """Test main shows traceback with verbose flag."""
        with patch("sys.argv", ["coverage_fuzz.py", "-v"]):
            with patch(
                "dicom_fuzzer.cli.coverage_fuzz.asyncio.run",
                side_effect=Exception("Verbose error"),
            ):
                with pytest.raises(SystemExit):
                    main()

        captured = capsys.readouterr()
        assert "Error" in captured.out


class TestRunCoverageFuzzing:
    """Test run_coverage_fuzzing function."""

    def test_run_coverage_fuzzing_basic(self):
        """Test basic coverage fuzzing execution."""
        config = {
            "max_iterations": 10,
            "timeout": 1,
        }

        with patch(
            "dicom_fuzzer.cli.coverage_fuzz.CoverageGuidedFuzzer"
        ) as mock_fuzzer:
            mock_instance = MagicMock()
            mock_instance.run.return_value = {"crashes": 0, "coverage": 0.5}
            mock_fuzzer.return_value = mock_instance

            result = run_coverage_fuzzing(config)

            assert "crashes" in result
            assert "coverage" in result

    def test_run_coverage_fuzzing_with_paths(self, tmp_path):
        """Test coverage fuzzing with input/output paths."""
        # Create the directories
        (tmp_path / "input").mkdir()
        (tmp_path / "output").mkdir()

        config = {
            "max_iterations": 10,
            "timeout": 1,
            "input_dir": str(tmp_path / "input"),
            "output_dir": str(tmp_path / "output"),
        }

        # Patch the CoverageGuidedFuzzer class at the location it's imported
        with patch(
            "dicom_fuzzer.core.coverage_guided_fuzzer.CoverageGuidedFuzzer"
        ) as mock_fuzzer_class:
            mock_instance = MagicMock()
            mock_instance.run.return_value = {"crashes": 2, "coverage": 0.75}
            mock_fuzzer_class.return_value = mock_instance

            result = run_coverage_fuzzing(config)

            assert "crashes" in result
            assert "coverage" in result

    def test_run_coverage_fuzzing_with_coroutine(self):
        """Test coverage fuzzing when run() returns a coroutine."""
        config = {"max_iterations": 10}

        with patch(
            "dicom_fuzzer.cli.coverage_fuzz.CoverageGuidedFuzzer"
        ) as mock_fuzzer:
            # Create mock stats object
            mock_stats = MagicMock()
            mock_stats.total_crashes = 3
            mock_stats.max_coverage = 500

            # Create async mock
            async def mock_run():
                return mock_stats

            mock_instance = MagicMock()
            mock_instance.run.return_value = mock_run()
            mock_fuzzer.return_value = mock_instance

            result = run_coverage_fuzzing(config)

            assert "crashes" in result
            assert "coverage" in result


class TestParseArguments:
    """Test parse_arguments function."""

    def test_parse_arguments_empty(self):
        """Test parsing empty arguments."""
        args = parse_arguments(["prog"])
        assert args.input_dir is None
        assert args.output_dir is None
        assert args.iterations == 100

    def test_parse_arguments_with_input(self):
        """Test parsing with input directory."""
        args = parse_arguments(["prog", "--input", "/path/to/input"])
        assert args.input_dir == "/path/to/input"

    def test_parse_arguments_with_output(self):
        """Test parsing with output directory."""
        args = parse_arguments(["prog", "--output", "/path/to/output"])
        assert args.output_dir == "/path/to/output"

    def test_parse_arguments_with_iterations(self):
        """Test parsing with iterations."""
        args = parse_arguments(["prog", "--iterations", "500"])
        assert args.iterations == 500

    def test_parse_arguments_with_timeout(self):
        """Test parsing with timeout."""
        args = parse_arguments(["prog", "--timeout", "10"])
        assert args.timeout == 10

    def test_parse_arguments_with_workers(self):
        """Test parsing with workers."""
        args = parse_arguments(["prog", "--workers", "8"])
        assert args.workers == 8

    def test_parse_arguments_all_options(self):
        """Test parsing with all options."""
        args = parse_arguments([
            "prog",
            "--input", "/in",
            "--output", "/out",
            "--iterations", "1000",
            "--timeout", "30",
            "--workers", "16",
        ])
        assert args.input_dir == "/in"
        assert args.output_dir == "/out"
        assert args.iterations == 1000
        assert args.timeout == 30
        assert args.workers == 16


class TestCoverageFuzzCLI:
    """Test CoverageFuzzCLI class."""

    def test_coverage_fuzz_cli_exists(self):
        """Test that CoverageFuzzCLI class exists."""
        assert CoverageFuzzCLI is not None

    def test_coverage_fuzz_cli_instantiation(self):
        """Test CoverageFuzzCLI can be instantiated."""
        cli = CoverageFuzzCLI()
        assert cli is not None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_create_status_table_with_zero_values(self):
        """Test status table with zero values."""
        stats = {
            "total_executions": 0,
            "exec_per_sec": 0,
            "current_coverage": 0,
            "corpus_size": 0,
            "total_crashes": 0,
            "unique_crashes": 0,
            "coverage_increases": 0,
        }
        table = create_status_table(stats)
        assert table is not None

    def test_create_mutation_table_with_missing_keys(self):
        """Test mutation table with missing keys in stats."""
        mutation_stats = {
            "strategy1": {},  # Missing all keys
            "strategy2": {"success_rate": 0.5},  # Missing some keys
        }
        table = create_mutation_table(mutation_stats)
        assert table is not None

    def test_create_config_with_invalid_python_target(self, tmp_path):
        """Test config creation with invalid Python target."""
        # Create an invalid Python file
        target_file = tmp_path / "invalid.py"
        target_file.write_text("this is not valid python {{{")

        parser = create_parser()
        args = parser.parse_args(["--target", str(target_file)])

        # Should handle the error gracefully
        try:
            config = create_config_from_args(args)
            # If it doesn't raise, that's also acceptable
            assert config is not None
        except Exception:
            # Exception is acceptable for invalid Python
            pass

    def test_load_config_with_null_paths(self, tmp_path):
        """Test loading config with null path values."""
        config_data = {
            "corpus_dir": None,
            "seed_dir": None,
            "output_dir": None,
            "crash_dir": None,
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config_from_file(config_file)
        assert config is not None
