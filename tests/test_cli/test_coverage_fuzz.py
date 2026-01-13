"""Tests for coverage_fuzz.py - Coverage-Guided Fuzzing CLI.

Tests cover argument parsing, configuration, table creation, and main execution.
"""

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.coverage_fuzz import (
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

    def test_parser_defaults(self):
        """Test parser default values."""
        parser = create_parser()
        args = parser.parse_args([])

        assert args.iterations == 10000
        assert args.workers == 1
        assert args.timeout == 1.0
        assert args.max_mutations == 10
        assert args.max_corpus_size == 1000
        assert args.verbose is False

    def test_parser_target_options(self):
        """Test target options parsing."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--target",
                "/path/to/binary",
                "--target-args",
                "--input FILE",
                "--modules",
                "pydicom",
                "numpy",
            ]
        )

        assert args.target == "/path/to/binary"
        assert args.target_args == "--input FILE"
        assert args.modules == ["pydicom", "numpy"]

    def test_parser_fuzzing_options(self):
        """Test fuzzing options parsing."""
        parser = create_parser()
        args = parser.parse_args(
            ["-i", "5000", "-w", "4", "-t", "2.5", "--max-mutations", "20"]
        )

        assert args.iterations == 5000
        assert args.workers == 4
        assert args.timeout == 2.5
        assert args.max_mutations == 20

    def test_parser_corpus_options(self):
        """Test corpus options parsing."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "-s",
                "./seeds",
                "-c",
                "./corpus",
                "--max-corpus-size",
                "500",
                "--minimize",
            ]
        )

        assert args.seeds == Path("./seeds")
        assert args.corpus == Path("./corpus")
        assert args.max_corpus_size == 500
        assert args.minimize is True

    def test_parser_coverage_options(self):
        """Test coverage options parsing."""
        parser = create_parser()
        args = parser.parse_args(["--no-coverage"])

        assert args.no_coverage is True

    def test_parser_mutation_options(self):
        """Test mutation options parsing."""
        parser = create_parser()
        # Default values
        args = parser.parse_args([])

        assert args.adaptive is True
        assert args.dicom_aware is True

    def test_parser_output_options(self):
        """Test output options parsing."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "-o",
                "./output",
                "--crashes",
                "./crashes",
                "--save-all",
                "--report-interval",
                "50",
            ]
        )

        assert args.output == Path("./output")
        assert args.crashes == Path("./crashes")
        assert args.save_all is True
        assert args.report_interval == 50

    def test_parser_other_options(self):
        """Test other options parsing."""
        parser = create_parser()
        args = parser.parse_args(["-v", "--config", "config.json", "--dry-run"])

        assert args.verbose is True
        assert args.config == Path("config.json")
        assert args.dry_run is True


class TestCreateStatusTable:
    """Test create_status_table function."""

    def test_status_table_with_stats(self):
        """Test status table creation with statistics."""
        stats = {
            "total_executions": 1000,
            "exec_per_sec": 50.5,
            "current_coverage": 250,
            "corpus_size": 100,
            "total_crashes": 5,
            "unique_crashes": 2,
            "coverage_increases": 15,
        }

        table = create_status_table(stats)

        assert table.title == "Fuzzing Status"
        assert len(table.columns) == 2

    def test_status_table_empty_stats(self):
        """Test status table with empty statistics."""
        table = create_status_table({})

        assert table.title == "Fuzzing Status"
        # Should handle missing keys gracefully


class TestCreateMutationTable:
    """Test create_mutation_table function."""

    def test_mutation_table_with_stats(self):
        """Test mutation table creation with statistics."""
        mutation_stats = {
            "bit_flip": {"success_rate": 0.15, "total_count": 500, "weight": 1.2},
            "byte_insert": {"success_rate": 0.08, "total_count": 300, "weight": 0.8},
            "tag_mutate": {"success_rate": 0.25, "total_count": 200, "weight": 1.5},
        }

        table = create_mutation_table(mutation_stats)

        assert table.title == "Mutation Statistics"
        assert len(table.columns) == 4

    def test_mutation_table_empty_stats(self):
        """Test mutation table with empty statistics."""
        table = create_mutation_table({})

        assert table.title == "Mutation Statistics"


class TestLoadConfigFromFile:
    """Test load_config_from_file function."""

    def test_load_basic_config(self, tmp_path):
        """Test loading basic configuration from JSON file."""
        config_file = tmp_path / "config.json"
        config_data = {
            "max_iterations": 5000,
            "num_workers": 2,
            "timeout_per_run": 2.0,
        }
        config_file.write_text(json.dumps(config_data))

        config = load_config_from_file(config_file)

        assert config.max_iterations == 5000
        assert config.num_workers == 2
        assert config.timeout_per_run == 2.0

    def test_load_config_with_paths(self, tmp_path):
        """Test loading configuration with path values."""
        config_file = tmp_path / "config.json"
        config_data = {
            "corpus_dir": str(tmp_path / "corpus"),
            "seed_dir": str(tmp_path / "seeds"),
            "output_dir": str(tmp_path / "output"),
            "crash_dir": str(tmp_path / "crashes"),
        }
        config_file.write_text(json.dumps(config_data))

        config = load_config_from_file(config_file)

        assert config.corpus_dir == Path(tmp_path / "corpus")
        assert config.seed_dir == Path(tmp_path / "seeds")
        assert config.output_dir == Path(tmp_path / "output")
        assert config.crash_dir == Path(tmp_path / "crashes")

    def test_load_config_missing_file(self, tmp_path):
        """Test loading configuration from non-existent file."""
        config_file = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError):
            load_config_from_file(config_file)


class TestCreateConfigFromArgs:
    """Test create_config_from_args function."""

    def test_config_from_basic_args(self):
        """Test creating configuration from basic arguments."""
        args = argparse.Namespace(
            target=None,
            modules=None,
            iterations=5000,
            workers=2,
            timeout=2.0,
            max_mutations=15,
            no_coverage=False,
            branches=True,
            minimize=False,
            corpus=None,
            seeds=None,
            max_corpus_size=500,
            adaptive=True,
            dicom_aware=True,
            output=Path("./output"),
            crashes=Path("./crashes"),
            save_all=False,
            report_interval=100,
            verbose=False,
        )

        config = create_config_from_args(args)

        assert config.max_iterations == 5000
        assert config.num_workers == 2
        assert config.timeout_per_run == 2.0
        assert config.max_mutations == 15
        assert config.coverage_guided is True
        assert config.adaptive_mutations is True
        assert config.dicom_aware is True

    def test_config_from_args_with_python_target(self, tmp_path):
        """Test creating configuration with Python target."""
        # Create a mock Python target file
        target_file = tmp_path / "target.py"
        target_file.write_text("""
def fuzz_target(data):
    pass
""")

        args = argparse.Namespace(
            target=str(target_file),
            modules=["pydicom"],
            iterations=1000,
            workers=1,
            timeout=1.0,
            max_mutations=10,
            no_coverage=False,
            branches=True,
            minimize=False,
            corpus=None,
            seeds=None,
            max_corpus_size=1000,
            adaptive=True,
            dicom_aware=True,
            output=Path("./output"),
            crashes=Path("./crashes"),
            save_all=False,
            report_interval=100,
            verbose=True,
        )

        config = create_config_from_args(args)

        assert config.target_modules == ["pydicom"]
        assert config.verbose is True

    def test_config_from_args_with_binary_target(self):
        """Test creating configuration with binary target."""
        args = argparse.Namespace(
            target="/usr/bin/dcmdump",
            modules=None,
            iterations=1000,
            workers=1,
            timeout=1.0,
            max_mutations=10,
            no_coverage=True,
            branches=True,
            minimize=False,
            corpus=None,
            seeds=None,
            max_corpus_size=1000,
            adaptive=True,
            dicom_aware=True,
            output=Path("./output"),
            crashes=Path("./crashes"),
            save_all=False,
            report_interval=100,
            verbose=False,
        )

        config = create_config_from_args(args)

        assert config.target_binary == "/usr/bin/dcmdump"
        assert config.coverage_guided is False


class TestMain:
    """Test main entry point."""

    def test_main_dry_run(self, capsys):
        """Test main with --dry-run flag."""
        with patch("sys.argv", ["coverage_fuzz", "--dry-run"]):
            with patch("dicom_fuzzer.cli.coverage_fuzz.console"):
                result = main()  # Should not raise with --dry-run
                assert result is None  # main() completes without error

    def test_main_with_config_file(self, tmp_path, capsys):
        """Test main loading configuration from file."""
        config_file = tmp_path / "config.json"
        config_data = {"max_iterations": 100}
        config_file.write_text(json.dumps(config_data))

        with patch(
            "sys.argv", ["coverage_fuzz", "--config", str(config_file), "--dry-run"]
        ):
            with patch("dicom_fuzzer.cli.coverage_fuzz.console"):
                result = main()  # Should not raise
                assert result is None  # main() completes without error

    def test_main_keyboard_interrupt(self, capsys):
        """Test main handles keyboard interrupt."""
        with patch("sys.argv", ["coverage_fuzz"]):
            with patch(
                "dicom_fuzzer.cli.coverage_fuzz.asyncio.run",
                side_effect=KeyboardInterrupt(),
            ):
                with patch("dicom_fuzzer.cli.coverage_fuzz.console"):
                    result = main()  # Should not raise, handles interrupt
                    assert result is None  # Gracefully handled keyboard interrupt


class TestRunCoverageFuzzing:
    """Test run_coverage_fuzzing function."""

    def test_run_coverage_fuzzing_basic(self, tmp_path):
        """Test running coverage fuzzing with basic config."""
        input_dir = tmp_path / "input"
        input_dir.mkdir()
        (input_dir / "test.dcm").write_bytes(b"test")

        output_dir = tmp_path / "output"

        mock_fuzzer = MagicMock()
        mock_fuzzer.run.return_value = {"crashes": 0, "coverage": 0.5}

        with patch(
            "dicom_fuzzer.cli.coverage_fuzz.CoverageGuidedFuzzer",
            return_value=mock_fuzzer,
        ):
            result = run_coverage_fuzzing(
                {
                    "input_dir": str(input_dir),
                    "output_dir": str(output_dir),
                    "max_iterations": 100,
                    "timeout": 5,
                }
            )

            assert "crashes" in result
            assert "coverage" in result

    def test_run_coverage_fuzzing_with_results(self, tmp_path):
        """Test run_coverage_fuzzing returns proper results."""
        mock_stats = MagicMock()
        mock_stats.total_crashes = 2
        mock_stats.max_coverage = 500

        mock_fuzzer = MagicMock()

        # Return a coroutine-like result
        async def mock_run():
            return mock_stats

        mock_fuzzer.run.return_value = mock_run()

        with patch(
            "dicom_fuzzer.cli.coverage_fuzz.CoverageGuidedFuzzer",
            return_value=mock_fuzzer,
        ):
            result = run_coverage_fuzzing(
                {
                    "max_iterations": 100,
                }
            )

            assert "crashes" in result
            assert "coverage" in result


class TestParseArguments:
    """Test parse_arguments function."""

    def test_parse_basic_arguments(self):
        """Test parsing basic arguments."""
        args = parse_arguments(["prog", "--input", "./input", "--output", "./output"])

        assert args.input_dir == "./input"
        assert args.output_dir == "./output"

    def test_parse_all_arguments(self):
        """Test parsing all arguments."""
        args = parse_arguments(
            [
                "prog",
                "--input",
                "./input",
                "--output",
                "./output",
                "--iterations",
                "5000",
                "--timeout",
                "10",
                "--workers",
                "8",
            ]
        )

        assert args.input_dir == "./input"
        assert args.output_dir == "./output"
        assert args.iterations == 5000
        assert args.timeout == 10
        assert args.workers == 8

    def test_parse_default_values(self):
        """Test default values for arguments."""
        args = parse_arguments(["prog"])

        assert args.iterations == 100
        assert args.timeout == 5
        assert args.workers == 4


class TestRunFuzzingCampaign:
    """Test run_fuzzing_campaign async function."""

    @pytest.mark.asyncio
    async def test_run_fuzzing_campaign_basic(self, tmp_path):
        """Test running a fuzzing campaign."""
        from dicom_fuzzer.cli.coverage_fuzz import run_fuzzing_campaign
        from dicom_fuzzer.core.coverage_guided_fuzzer import FuzzingConfig

        config = FuzzingConfig()
        config.max_iterations = 10
        config.output_dir = tmp_path / "output"

        mock_stats = MagicMock()
        mock_stats.total_executions = 10
        mock_stats.exec_per_sec = 5.0
        mock_stats.current_coverage = 100
        mock_stats.corpus_size = 5
        mock_stats.total_crashes = 0
        mock_stats.unique_crashes = 0
        mock_stats.coverage_increases = 3
        mock_stats.mutation_stats = {}
        mock_stats.max_coverage = 100

        mock_fuzzer = MagicMock()
        mock_fuzzer.stats = mock_stats

        async def mock_run():
            return mock_stats

        mock_fuzzer.run = mock_run

        with (
            patch(
                "dicom_fuzzer.cli.coverage_fuzz.CoverageGuidedFuzzer",
                return_value=mock_fuzzer,
            ),
            patch("dicom_fuzzer.cli.coverage_fuzz.console"),
            patch("dicom_fuzzer.cli.coverage_fuzz.Live"),
        ):
            await run_fuzzing_campaign(config)


class TestCoverageFuzzCLI:
    """Test CoverageFuzzCLI class."""

    def test_class_exists(self):
        """Test that CoverageFuzzCLI class exists for compatibility."""
        from dicom_fuzzer.cli.coverage_fuzz import CoverageFuzzCLI

        # Just verify the class exists
        assert CoverageFuzzCLI is not None
        cli = CoverageFuzzCLI()
        assert cli is not None
