"""
Tests for output.py - CLI Output Utilities with Rich Integration.

Tests cover console initialization, status functions, formatting, and context managers.
"""

from unittest.mock import MagicMock, patch


class TestConsoleInit:
    """Test console initialization and caching."""

    def test_get_console_creates_console(self):
        """Test that _get_console creates a console instance."""
        # Reset module state for clean test
        import dicom_fuzzer.cli.utils.output as output_module

        output_module._console = None
        output_module._use_color = None

        console = output_module._get_console()

        assert console is not None
        assert output_module._console is not None

    def test_get_console_caches_instance(self):
        """Test that _get_console returns cached instance."""
        import dicom_fuzzer.cli.utils.output as output_module

        # Get console twice
        console1 = output_module._get_console()
        console2 = output_module._get_console()

        # Should be same instance
        assert console1 is console2

    def test_supports_color_detection(self):
        """Test color support detection."""
        import dicom_fuzzer.cli.utils.output as output_module

        output_module._console = None
        output_module._use_color = None

        result = output_module.supports_color()

        # Result should be boolean
        assert isinstance(result, bool)


class TestStatusFunctions:
    """Test status message functions."""

    def test_success_message(self):
        """Test success message formatting."""
        from dicom_fuzzer.cli.utils.output import success

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            success("Operation completed")

            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert "[+]" in call_args
            assert "Operation completed" in call_args

    def test_error_message(self):
        """Test error message formatting."""
        from dicom_fuzzer.cli.utils.output import error

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            error("Something failed")

            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert "[-]" in call_args
            assert "Something failed" in call_args

    def test_warning_message(self):
        """Test warning message formatting."""
        from dicom_fuzzer.cli.utils.output import warning

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            warning("Potential issue")

            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert "[!]" in call_args
            assert "Potential issue" in call_args

    def test_info_message(self):
        """Test info message formatting."""
        from dicom_fuzzer.cli.utils.output import info

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            info("Information message")

            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert "[i]" in call_args
            assert "Information message" in call_args

    def test_status_message(self):
        """Test plain status message."""
        from dicom_fuzzer.cli.utils.output import status

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            status("Plain message")

            mock_console.print.assert_called_once_with("Plain message")


class TestFormatting:
    """Test formatting functions."""

    def test_header_with_subtitle(self):
        """Test header with subtitle."""
        from dicom_fuzzer.cli.utils.output import header

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            header("Main Title", "Subtitle text")

            # Should print multiple times (blank, title, subtitle, blank)
            assert mock_console.print.call_count >= 3

    def test_header_without_subtitle(self):
        """Test header without subtitle."""
        from dicom_fuzzer.cli.utils.output import header

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            header("Title Only")

            # Should print fewer times without subtitle
            assert mock_console.print.call_count >= 2

    def test_section(self):
        """Test section header."""
        from dicom_fuzzer.cli.utils.output import section

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            section("Section Title")

            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert "Section Title" in call_args

    def test_detail(self):
        """Test detail line formatting."""
        from dicom_fuzzer.cli.utils.output import detail

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            detail("Label", "Value", indent=4)

            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert "Label" in call_args
            assert "Value" in call_args

    def test_table_row_with_widths(self):
        """Test table row with column widths."""
        from dicom_fuzzer.cli.utils.output import table_row

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            table_row(["Col1", "Col2"], widths=[10, 20])

            mock_console.print.assert_called_once()

    def test_table_row_without_widths(self):
        """Test table row without column widths."""
        from dicom_fuzzer.cli.utils.output import table_row

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            table_row(["Item1", "Item2"])

            mock_console.print.assert_called_once()

    def test_divider(self):
        """Test horizontal divider."""
        from dicom_fuzzer.cli.utils.output import divider

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            divider()

            mock_console.print.assert_called_once()
            call_args = mock_console.print.call_args[0][0]
            assert "-" in call_args


class TestProgressBar:
    """Test progress bar context manager."""

    def test_progress_bar_context_manager(self):
        """Test progress bar as context manager."""
        from dicom_fuzzer.cli.utils.output import progress_bar

        # Patch where Progress is imported from (rich.progress)
        with patch("rich.progress.Progress") as mock_progress_cls:
            mock_progress = MagicMock()
            mock_progress.__enter__ = MagicMock(return_value=mock_progress)
            mock_progress.__exit__ = MagicMock(return_value=False)
            mock_progress.add_task = MagicMock(return_value=1)
            mock_progress_cls.return_value = mock_progress

            with progress_bar("Processing", total=100) as (progress, task):
                assert progress is mock_progress
                assert task == 1

    def test_progress_bar_yields_tuple(self):
        """Test progress bar yields progress and task_id tuple."""
        from dicom_fuzzer.cli.utils.output import progress_bar

        # Use actual progress bar briefly
        with progress_bar("Test", total=10, transient=True) as (progress, task):
            # Verify we get the expected types
            assert hasattr(progress, "update")
            assert hasattr(progress, "add_task")
            # task should be a task ID (int)
            assert isinstance(task, int) or task is not None


class TestSpinner:
    """Test spinner context manager."""

    def test_spinner_context_manager(self):
        """Test spinner as context manager."""
        from dicom_fuzzer.cli.utils.output import spinner

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_status = MagicMock()
            mock_status.__enter__ = MagicMock(return_value=None)
            mock_status.__exit__ = MagicMock(return_value=False)
            mock_console.status.return_value = mock_status
            mock_get.return_value = mock_console

            with spinner("Loading"):
                pass

            mock_console.status.assert_called_once()

    def test_spinner_custom_message(self):
        """Test spinner with custom message."""
        from dicom_fuzzer.cli.utils.output import spinner

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_status = MagicMock()
            mock_status.__enter__ = MagicMock(return_value=None)
            mock_status.__exit__ = MagicMock(return_value=False)
            mock_console.status.return_value = mock_status
            mock_get.return_value = mock_console

            with spinner("Custom loading message"):
                pass

            call_args = mock_console.status.call_args[0][0]
            assert "Custom loading message" in call_args


class TestPrintSummary:
    """Test print_summary function."""

    def test_print_summary_basic(self):
        """Test basic summary printing."""
        from dicom_fuzzer.cli.utils.output import print_summary

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            stats = {"Total": 100, "Passed": 95, "Failed": 5}
            print_summary("Test Results", stats)

            mock_console.print.assert_called()

    def test_print_summary_with_success_count(self):
        """Test summary with success coloring."""
        from dicom_fuzzer.cli.utils.output import print_summary

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            stats = {"Success": 50}
            print_summary("Results", stats, success_count=50)

            mock_console.print.assert_called()

    def test_print_summary_with_error_count(self):
        """Test summary with error coloring."""
        from dicom_fuzzer.cli.utils.output import print_summary

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            stats = {"Errors": 10}
            print_summary("Results", stats, error_count=10)

            mock_console.print.assert_called()


class TestFormatCrashInfo:
    """Test format_crash_info function."""

    def test_format_crash_info_basic(self):
        """Test basic crash info formatting."""
        from dicom_fuzzer.cli.utils.output import format_crash_info

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            format_crash_info("/path/to/file.dcm", exit_code=139)

            assert mock_console.print.call_count >= 2

    def test_format_crash_info_with_memory(self):
        """Test crash info with memory info."""
        from dicom_fuzzer.cli.utils.output import format_crash_info

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            format_crash_info("/path/to/file.dcm", exit_code=1, memory_mb=512.5)

            assert mock_console.print.call_count >= 3

    def test_format_crash_info_with_error_msg(self):
        """Test crash info with error message."""
        from dicom_fuzzer.cli.utils.output import format_crash_info

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            format_crash_info(
                "/path/to/file.dcm",
                exit_code=None,
                error_msg="Segmentation fault",
            )

            assert mock_console.print.call_count >= 2

    def test_format_crash_info_all_fields(self):
        """Test crash info with all fields."""
        from dicom_fuzzer.cli.utils.output import format_crash_info

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            format_crash_info(
                "/path/to/crash.dcm",
                exit_code=11,
                memory_mb=1024.0,
                error_msg="Buffer overflow detected",
            )

            # Should print file path, exit code, memory, and error
            assert mock_console.print.call_count == 4


class TestIntegration:
    """Integration tests for output utilities."""

    def test_full_output_workflow(self):
        """Test a realistic output workflow."""
        from dicom_fuzzer.cli.utils.output import (
            divider,
            error,
            header,
            info,
            section,
            success,
        )

        with patch("dicom_fuzzer.cli.utils.output._get_console") as mock_get:
            mock_console = MagicMock()
            mock_get.return_value = mock_console

            # Simulate typical CLI output
            header("DICOM Fuzzer", "Security Testing")
            section("Configuration")
            info("Loading files...")
            success("Files loaded")
            divider()
            error("Found vulnerability")

            # Verify multiple print calls
            assert mock_console.print.call_count >= 6

    def test_module_state_reset(self):
        """Test that module state can be reset."""
        import dicom_fuzzer.cli.utils.output as output_module

        # Reset state
        output_module._console = None
        output_module._use_color = None

        # Get console
        console = output_module._get_console()

        # State should be set
        assert output_module._console is not None
        assert output_module._use_color is not None
