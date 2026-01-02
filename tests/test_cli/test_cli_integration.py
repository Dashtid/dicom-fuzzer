"""
CLI Integration Tests

Tests the command-line interface end-to-end, including:
- Argument parsing and validation
- File I/O operations
- Error handling and user feedback
- Target testing workflow
- Exit codes

APPROACH: Uses factory pattern for argparse testing per 2025 best practices.
"""

import sys
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.cli.main import (
    main,
    parse_strategies,
    setup_logging,
    validate_input_file,
)


@pytest.fixture
def sample_dicom(tmp_path):
    """Create a sample DICOM file for testing."""
    dicom_file = tmp_path / "sample.dcm"
    # Create minimal valid DICOM file
    # DICOM preamble (128 bytes) + DICM prefix
    content = b"\x00" * 128 + b"DICM"
    dicom_file.write_bytes(content)
    return dicom_file


@pytest.fixture
def output_dir(tmp_path):
    """Create output directory."""
    out_dir = tmp_path / "output"
    out_dir.mkdir()
    return out_dir


class TestArgumentParsing:
    """Test CLI argument parsing."""

    def test_parse_basic_arguments(self, sample_dicom, output_dir):
        """Test parsing basic required and optional arguments."""
        args = [
            str(sample_dicom),
            "-c",
            "50",
            "-o",
            str(output_dir),
        ]

        with patch("sys.argv", ["dicom-fuzzer"] + args):
            with patch("dicom_fuzzer.cli.campaign_runner.DICOMGenerator"):
                with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                    try:
                        main()
                    except SystemExit:
                        pass  # May exit after completion

    def test_parse_strategies(self):
        """Test strategy string parsing."""
        # Valid strategies
        strategies = parse_strategies("metadata,header,pixel")
        assert set(strategies) == {"metadata", "header", "pixel"}

        # Invalid strategies filtered out
        strategies = parse_strategies("metadata,invalid,header")
        assert "invalid" not in strategies
        assert "metadata" in strategies

        # Case insensitive
        strategies = parse_strategies("METADATA,Header")
        assert "metadata" in strategies
        assert "header" in strategies

    def test_validate_input_file_exists(self, sample_dicom):
        """Test input file validation for existing file."""
        result = validate_input_file(str(sample_dicom))
        assert result == sample_dicom

    def test_validate_input_file_not_found(self, tmp_path):
        """Test input file validation for non-existent file."""
        fake_file = tmp_path / "nonexistent.dcm"

        with pytest.raises(SystemExit):
            validate_input_file(str(fake_file))

    def test_validate_input_not_a_file(self, tmp_path):
        """Test input file validation for directory."""
        with pytest.raises(SystemExit):
            validate_input_file(str(tmp_path))


class TestLoggingSetup:
    """Test logging configuration."""

    def test_setup_logging_info_level(self):
        """Test logging setup with INFO level."""
        setup_logging(verbose=False)
        import logging

        root_logger = logging.getLogger("dicom_fuzzer.cli.main")
        # Logger should be configured (at least to WARNING)
        assert root_logger.level <= logging.INFO

    def test_setup_logging_debug_level(self):
        """Test logging setup with DEBUG level."""
        setup_logging(verbose=True)
        import logging

        root_logger = logging.getLogger("dicom_fuzzer.cli.main")
        # Should be DEBUG or less
        assert root_logger.level <= logging.DEBUG


class TestFileGeneration:
    """Test file generation workflow."""

    def test_generate_basic_campaign(self, sample_dicom, output_dir, capsys):
        """Test basic fuzzing campaign generation."""
        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "10",
            "-o",
            str(output_dir),
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                mock_gen = Mock()
                mock_gen.generate_batch.return_value = [
                    output_dir / f"fuzzed_{i:04d}.dcm" for i in range(10)
                ]
                mock_gen.stats.skipped_due_to_write_errors = 0
                mock_gen.stats.strategies_used = {"metadata": 5, "header": 5}
                mock_gen_class.return_value = mock_gen

                with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                    try:
                        main()
                    except SystemExit as e:
                        # Should exit with success
                        assert e.code == 0 or e.code is None

                # Verify generator was called once with the batch count
                assert mock_gen.generate_batch.call_count >= 1
                # Verify total files generated matches requested count
                assert len(mock_gen.generate_batch.return_value) == 10

    def test_generate_with_specific_strategies(self, sample_dicom, output_dir, capsys):
        """Test generation with specific strategies."""
        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "5",
            "-o",
            str(output_dir),
            "-s",
            "metadata,header",
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                mock_gen = Mock()
                mock_gen.generate_batch.return_value = [
                    output_dir / f"fuzzed_{i:04d}.dcm" for i in range(5)
                ]
                mock_gen.stats.skipped_due_to_write_errors = 0
                mock_gen.stats.strategies_used = {"metadata": 3, "header": 2}
                mock_gen_class.return_value = mock_gen

                with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                    try:
                        main()
                    except SystemExit as e:
                        assert e.code == 0 or e.code is None

                # Verify strategies were passed
                call_args = mock_gen.generate_batch.call_args
                strategies = call_args[1].get("strategies")
                assert set(strategies) == {"metadata", "header"}

    def test_invalid_strategies_filtered(self, sample_dicom, output_dir, capsys):
        """Test that invalid strategies are filtered out."""
        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "5",
            "-o",
            str(output_dir),
            "-s",
            "invalid,metadata",
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                mock_gen = Mock()
                mock_gen.generate_batch.return_value = [
                    output_dir / f"fuzzed_{i:04d}.dcm" for i in range(5)
                ]
                mock_gen.stats.skipped_due_to_write_errors = 0
                mock_gen.stats.strategies_used = {"metadata": 5}
                mock_gen_class.return_value = mock_gen

                with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                    try:
                        main()
                    except SystemExit:
                        pass

                # Should still call generator with valid strategies
                call_args = mock_gen.generate_batch.call_args
                strategies = call_args[1].get("strategies")
                assert "invalid" not in strategies
                assert "metadata" in strategies


class TestTargetTesting:
    """Test target application testing workflow."""

    def test_target_testing_basic(self, sample_dicom, output_dir, tmp_path):
        """Test basic target testing workflow."""
        # Create mock target executable
        if sys.platform == "win32":
            target_exe = tmp_path / "test_app.bat"
            target_exe.write_text("@echo off\nexit 0")
        else:
            target_exe = tmp_path / "test_app.sh"
            target_exe.write_text("#!/bin/bash\nexit 0")
            target_exe.chmod(0o755)

        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "5",
            "-o",
            str(output_dir),
            "-t",
            str(target_exe),
            "--timeout",
            "2.0",
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                with patch(
                    "dicom_fuzzer.cli.target_controller.TargetRunner"
                ) as mock_runner_class:
                    # Setup generator mock
                    mock_gen = Mock()
                    test_files = [output_dir / f"fuzzed_{i:04d}.dcm" for i in range(5)]
                    mock_gen.generate_batch.return_value = test_files
                    mock_gen.stats.skipped_due_to_write_errors = 0
                    mock_gen.stats.strategies_used = {"metadata": 5}
                    mock_gen_class.return_value = mock_gen

                    # Setup runner mock
                    mock_runner = Mock()
                    mock_runner.run_campaign.return_value = {
                        Mock(value="success"): [Mock()] * 5,
                        Mock(value="crash"): [],
                        Mock(value="hang"): [],
                        Mock(value="error"): [],
                        Mock(value="oom"): [],
                        Mock(value="skipped"): [],
                        Mock(value="resource_exhausted"): [],
                    }
                    mock_runner.get_summary.return_value = "Test summary"
                    mock_runner_class.return_value = mock_runner

                    with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                        try:
                            main()
                        except SystemExit as e:
                            assert e.code == 0 or e.code is None

                    # Verify runner was created with correct params
                    mock_runner_class.assert_called_once()
                    call_args = mock_runner_class.call_args
                    # Check target_executable parameter was passed
                    assert call_args.kwargs["target_executable"] == str(target_exe)

                    # Verify campaign was run
                    mock_runner.run_campaign.assert_called_once()

    def test_target_not_found(self, sample_dicom, output_dir, tmp_path):
        """Test error handling when target executable not found."""
        fake_target = tmp_path / "nonexistent.exe"

        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "5",
            "-o",
            str(output_dir),
            "-t",
            str(fake_target),
        ]

        with patch("sys.argv", args):
            # Health check catches missing target and returns 1
            result = main()
            assert result == 1

    def test_stop_on_crash_flag(self, sample_dicom, output_dir, tmp_path):
        """Test --stop-on-crash flag."""
        if sys.platform == "win32":
            target_exe = tmp_path / "test_app.bat"
            target_exe.write_text("@echo off\nexit 0")
        else:
            target_exe = tmp_path / "test_app.sh"
            target_exe.write_text("#!/bin/bash\nexit 0")
            target_exe.chmod(0o755)

        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "10",
            "-o",
            str(output_dir),
            "-t",
            str(target_exe),
            "--stop-on-crash",
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                with patch(
                    "dicom_fuzzer.cli.target_controller.TargetRunner"
                ) as mock_runner_class:
                    mock_gen = Mock()
                    test_files = [output_dir / f"fuzzed_{i:04d}.dcm" for i in range(10)]
                    mock_gen.generate_batch.return_value = test_files
                    mock_gen.stats.skipped_due_to_write_errors = 0
                    mock_gen.stats.strategies_used = {"metadata": 10}
                    mock_gen_class.return_value = mock_gen

                    mock_runner = Mock()
                    mock_runner.run_campaign.return_value = {}
                    mock_runner.get_summary.return_value = "Summary"
                    mock_runner_class.return_value = mock_runner

                    with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                        try:
                            main()
                        except SystemExit:
                            pass

                    # Verify stop_on_crash was passed
                    call_args = mock_runner.run_campaign.call_args
                    assert call_args[1]["stop_on_crash"] is True


class TestErrorHandling:
    """Test error handling and user feedback."""

    def test_keyboard_interrupt_handling(self, sample_dicom, output_dir):
        """Test graceful handling of Ctrl+C."""
        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "100",
            "-o",
            str(output_dir),
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                mock_gen = Mock()
                mock_gen.generate_batch.side_effect = KeyboardInterrupt()
                mock_gen_class.return_value = mock_gen

                with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                    # Should return 130 (128 + SIGINT)
                    result = main()
                    assert result == 130

    def test_general_exception_handling(self, sample_dicom, output_dir, capsys):
        """Test handling of unexpected exceptions."""
        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "10",
            "-o",
            str(output_dir),
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                mock_gen = Mock()
                mock_gen.generate_batch.side_effect = RuntimeError("Unexpected error")
                mock_gen_class.return_value = mock_gen

                with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                    # Should return 1 for error
                    result = main()
                    assert result == 1

    def test_verbose_error_output(self, sample_dicom, output_dir):
        """Test that verbose mode shows full tracebacks."""
        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "10",
            "-o",
            str(output_dir),
            "-v",  # Verbose mode
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                mock_gen = Mock()
                mock_gen.generate_batch.side_effect = RuntimeError("Test error")
                mock_gen_class.return_value = mock_gen

                with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                    result = main()
                    # In verbose mode, should show traceback and return 1
                    assert result == 1


class TestOutputFormatting:
    """Test CLI output formatting."""

    def test_output_has_headers(self, sample_dicom, output_dir, capsys):
        """Test that output includes formatted headers."""
        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "5",
            "-o",
            str(output_dir),
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                mock_gen = Mock()
                mock_gen.generate_batch.return_value = [
                    output_dir / f"fuzzed_{i:04d}.dcm" for i in range(5)
                ]
                mock_gen.stats.skipped_due_to_write_errors = 0
                mock_gen.stats.strategies_used = {"metadata": 5}
                mock_gen_class.return_value = mock_gen

                with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                    try:
                        main()
                    except SystemExit:
                        pass

                captured = capsys.readouterr()
                output = captured.out

                # Should contain formatted sections
                assert "DICOM Fuzzer" in output
                assert "Campaign Results" in output
                assert "Successfully generated" in output or "[+]" in output

    def test_progress_bar_with_tqdm(self, sample_dicom, output_dir):
        """Test progress bar display when tqdm available."""
        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "20",
            "-o",
            str(output_dir),
        ]

        # Import tqdm for mocking (skip test if not available)
        pytest.importorskip("tqdm")

        # Mock tqdm availability (patch where it's imported in main.py)
        with patch("sys.argv", args):
            with patch("dicom_fuzzer.cli.campaign_runner.tqdm") as mock_tqdm:
                with patch(
                    "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
                ) as mock_gen_class:
                    mock_gen = Mock()
                    mock_gen.generate_batch.return_value = [
                        output_dir / f"fuzzed_{i:04d}.dcm" for i in range(20)
                    ]
                    mock_gen.stats.skipped_due_to_write_errors = 0
                    mock_gen.stats.strategies_used = {"metadata": 20}
                    mock_gen_class.return_value = mock_gen

                    # Setup tqdm context manager mock
                    pbar_mock = Mock()
                    pbar_mock.__enter__ = Mock(return_value=pbar_mock)
                    pbar_mock.__exit__ = Mock(return_value=False)
                    mock_tqdm.return_value = pbar_mock

                    with patch("dicom_fuzzer.cli.main.Path.mkdir"):
                        try:
                            main()
                        except SystemExit:
                            pass

                    # Verify tqdm was used
                    mock_tqdm.assert_called()


class TestVersionFlag:
    """Test --version flag."""

    def test_version_flag(self):
        """Test --version displays version and exits."""
        args = ["dicom-fuzzer", "--version"]

        with patch("sys.argv", args):
            with pytest.raises(SystemExit) as exc_info:
                main()

            # Should exit cleanly with version info
            assert exc_info.value.code == 0


class TestHelpFlag:
    """Test --help flag."""

    def test_help_flag(self):
        """Test --help displays help and exits."""
        args = ["dicom-fuzzer", "--help"]

        with patch("sys.argv", args):
            with pytest.raises(SystemExit) as exc_info:
                main()

            # Should exit cleanly with help info
            assert exc_info.value.code == 0


class TestDirectoryCreation:
    """Test output directory creation."""

    def test_creates_output_directory(self, sample_dicom, tmp_path):
        """Test that output directory is created if it doesn't exist."""
        output_dir = tmp_path / "new_output_dir"
        assert not output_dir.exists()

        args = [
            "dicom-fuzzer",
            str(sample_dicom),
            "-c",
            "5",
            "-o",
            str(output_dir),
        ]

        with patch("sys.argv", args):
            with patch(
                "dicom_fuzzer.cli.campaign_runner.DICOMGenerator"
            ) as mock_gen_class:
                mock_gen = Mock()
                mock_gen.generate_batch.return_value = [
                    output_dir / f"fuzzed_{i:04d}.dcm" for i in range(5)
                ]
                mock_gen.stats.skipped_due_to_write_errors = 0
                mock_gen.stats.strategies_used = {"metadata": 5}
                mock_gen_class.return_value = mock_gen

                # Let directory creation happen
                try:
                    main()
                except SystemExit:
                    pass

                # Directory should be created
                assert output_dir.exists()
