"""Tests for stress.py - Stress Testing CLI.

Tests cover argument parsing, scenario listing, series generation, and stress test execution.
"""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.stress import (
    create_parser,
    main,
    parse_dimensions,
    run_generate_series,
    run_list_scenarios,
    run_stress_test,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_requires_action(self):
        """Test that parser requires mutually exclusive action."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_generate_series_action(self):
        """Test --generate-series action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--generate-series"])

        assert args.generate_series is True
        assert args.run_test is False
        assert args.list_scenarios is False

    def test_parser_run_test_action(self):
        """Test --run-test action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--run-test"])

        assert args.run_test is True
        assert args.generate_series is False
        assert args.list_scenarios is False

    def test_parser_list_scenarios_action(self):
        """Test --list-scenarios action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--list-scenarios"])

        assert args.list_scenarios is True
        assert args.generate_series is False
        assert args.run_test is False

    def test_parser_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--generate-series", "--run-test"])

    def test_parser_generation_defaults(self):
        """Test default values for generation options."""
        parser = create_parser()
        args = parser.parse_args(["--generate-series"])

        assert args.slices == 100
        assert args.dimensions == "512x512"
        assert args.pattern == "gradient"
        assert args.modality == "CT"

    def test_parser_generation_options(self):
        """Test custom generation options."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--generate-series",
                "--slices",
                "500",
                "--dimensions",
                "1024x1024",
                "--pattern",
                "random",
                "--modality",
                "MR",
            ]
        )

        assert args.slices == 500
        assert args.dimensions == "1024x1024"
        assert args.pattern == "random"
        assert args.modality == "MR"

    def test_parser_testing_options(self):
        """Test stress testing options."""
        parser = create_parser()
        args = parser.parse_args(
            ["--run-test", "--escalation-steps", "50,100,200", "--memory-limit", "8192"]
        )

        assert args.escalation_steps == "50,100,200"
        assert args.memory_limit == 8192

    def test_parser_output_options(self):
        """Test output options."""
        parser = create_parser()
        args = parser.parse_args(["--generate-series", "-o", "/custom/output", "-v"])

        assert args.output == "/custom/output"
        assert args.verbose is True


class TestParseDimensions:
    """Test parse_dimensions function."""

    def test_parse_valid_dimensions(self):
        """Test parsing valid dimension string."""
        width, height = parse_dimensions("512x512")
        assert width == 512
        assert height == 512

    def test_parse_different_dimensions(self):
        """Test parsing different width and height."""
        width, height = parse_dimensions("1024x768")
        assert width == 1024
        assert height == 768

    def test_parse_uppercase_x(self):
        """Test parsing with uppercase X."""
        width, height = parse_dimensions("256X256")
        assert width == 256
        assert height == 256

    def test_parse_invalid_format(self):
        """Test parsing invalid format raises error."""
        with pytest.raises(ValueError, match="Invalid dimensions format"):
            parse_dimensions("512")

    def test_parse_non_numeric(self):
        """Test parsing non-numeric values raises error."""
        with pytest.raises(ValueError, match="Invalid dimensions format"):
            parse_dimensions("abcxdef")


class TestRunListScenarios:
    """Test run_list_scenarios function."""

    def test_list_scenarios_returns_zero(self, capsys):
        """Test that list_scenarios returns 0."""
        result = run_list_scenarios()
        assert result == 0

    def test_list_scenarios_output(self, capsys):
        """Test that list_scenarios prints scenario information."""
        run_list_scenarios()
        captured = capsys.readouterr()

        assert "Stress Test Scenarios" in captured.out
        assert "Large Series" in captured.out
        assert "High Resolution" in captured.out
        assert "Memory Escalation" in captured.out


class TestRunGenerateSeries:
    """Test run_generate_series function."""

    def test_generate_series_success(self, tmp_path, capsys):
        """Test successful series generation."""
        mock_tester = MagicMock()
        mock_tester.estimate_memory_usage.return_value = {
            "slice_mb": 0.5,
            "series_pixel_data_mb": 50.0,
            "estimated_viewer_mb": 100.0,
        }

        series_path = tmp_path / "series"
        series_path.mkdir()
        (series_path / "slice_001.dcm").write_bytes(b"test" * 1000)
        mock_tester.generate_large_series.return_value = series_path

        args = argparse.Namespace(
            slices=100,
            dimensions="512x512",
            pattern="gradient",
            modality="CT",
            output=str(tmp_path),
            memory_limit=4096,
            verbose=False,
        )

        mock_module = MagicMock()
        mock_module.StressTestConfig = MagicMock()
        mock_module.StressTester = MagicMock(return_value=mock_tester)

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.harness.stress_tester": mock_module}
        ):
            result = run_generate_series(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Large Series Generation" in captured.out

    def test_generate_series_import_error(self, tmp_path, capsys):
        """Test handling of import error."""
        args = argparse.Namespace(
            slices=100,
            dimensions="512x512",
            pattern="gradient",
            modality="CT",
            output=str(tmp_path),
            memory_limit=4096,
            verbose=False,
        )

        with patch.dict("sys.modules", {"dicom_fuzzer.harness.stress_tester": None}):
            # Force ImportError by making the import fail
            import builtins

            original_import = builtins.__import__

            def mock_import(name, *args, **kwargs):
                if "stress_tester" in name:
                    raise ImportError("Module not available")
                return original_import(name, *args, **kwargs)

            with patch.object(builtins, "__import__", mock_import):
                result = run_generate_series(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Module not available" in captured.out

    def test_generate_series_invalid_dimensions(self, tmp_path, capsys):
        """Test handling of invalid dimensions."""
        args = argparse.Namespace(
            slices=100,
            dimensions="invalid",
            pattern="gradient",
            modality="CT",
            output=str(tmp_path),
            memory_limit=4096,
            verbose=True,
        )

        mock_module = MagicMock()
        mock_module.StressTestConfig = MagicMock()
        mock_module.StressTester = MagicMock()

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.harness.stress_tester": mock_module}
        ):
            result = run_generate_series(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Failed" in captured.out


class TestRunStressTest:
    """Test run_stress_test function."""

    def test_stress_test_success(self, tmp_path, capsys):
        """Test successful stress test execution."""
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.slice_count = 100
        mock_result.duration_seconds = 5.0
        mock_result.memory_peak_mb = 500.0
        mock_result.errors = []

        mock_tester = MagicMock()
        mock_tester.run_memory_stress_test.return_value = [mock_result]

        args = argparse.Namespace(
            escalation_steps="100,250",
            dimensions="512x512",
            memory_limit=4096,
            output=str(tmp_path),
            verbose=False,
        )

        mock_module = MagicMock()
        mock_module.StressTestConfig = MagicMock()
        mock_module.StressTester = MagicMock(return_value=mock_tester)

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.harness.stress_tester": mock_module}
        ):
            result = run_stress_test(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Stress Test Results" in captured.out
        assert "1/1 steps successful" in captured.out

    def test_stress_test_with_failures(self, tmp_path, capsys):
        """Test stress test with some failures."""
        mock_success = MagicMock()
        mock_success.success = True
        mock_success.slice_count = 100
        mock_success.duration_seconds = 5.0
        mock_success.memory_peak_mb = 500.0
        mock_success.errors = []

        mock_failure = MagicMock()
        mock_failure.success = False
        mock_failure.slice_count = 500
        mock_failure.duration_seconds = 10.0
        mock_failure.memory_peak_mb = 3500.0
        mock_failure.errors = ["Out of memory"]

        mock_tester = MagicMock()
        mock_tester.run_memory_stress_test.return_value = [mock_success, mock_failure]

        args = argparse.Namespace(
            escalation_steps="100,500",
            dimensions="512x512",
            memory_limit=4096,
            output=str(tmp_path),
            verbose=False,
        )

        mock_module = MagicMock()
        mock_module.StressTestConfig = MagicMock()
        mock_module.StressTester = MagicMock(return_value=mock_tester)

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.harness.stress_tester": mock_module}
        ):
            result = run_stress_test(args)

        assert result == 1  # Not all steps successful
        captured = capsys.readouterr()
        assert "1/2 steps successful" in captured.out


class TestMain:
    """Test main entry point."""

    def test_main_list_scenarios(self, capsys):
        """Test main with --list-scenarios."""
        result = main(["--list-scenarios"])
        assert result == 0
        captured = capsys.readouterr()
        assert "Stress Test Scenarios" in captured.out

    def test_main_generate_series(self, tmp_path):
        """Test main with --generate-series dispatches correctly."""
        with patch(
            "dicom_fuzzer.cli.stress.run_generate_series", return_value=0
        ) as mock_run:
            result = main(["--generate-series", "-o", str(tmp_path)])
            assert result == 0
            mock_run.assert_called_once()

    def test_main_run_test(self, tmp_path):
        """Test main with --run-test dispatches correctly."""
        with patch(
            "dicom_fuzzer.cli.stress.run_stress_test", return_value=0
        ) as mock_run:
            result = main(["--run-test", "-o", str(tmp_path)])
            assert result == 0
            mock_run.assert_called_once()

    def test_main_no_args_shows_help(self, capsys):
        """Test main with no args shows help."""
        with pytest.raises(SystemExit):
            main([])
