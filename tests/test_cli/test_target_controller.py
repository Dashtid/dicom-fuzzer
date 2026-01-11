"""Tests for TargetTestingController.

Tests the CLI target testing controller in
dicom_fuzzer.cli.target_controller module.
"""

from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.target_controller import (
    HAS_PSUTIL,
    TargetTestingController,
)


class TestDisplayHeader:
    """Tests for _display_header method."""

    def test_display_header_gui_mode(self, capsys: pytest.CaptureFixture) -> None:
        """Test header display in GUI mode."""
        args = Namespace(target="/path/to/app", timeout=10, startup_delay=2.0)
        files = [Path("test1.dcm"), Path("test2.dcm")]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=True, memory_limit=512
        )

        captured = capsys.readouterr()
        assert "GUI Application Testing" in captured.out
        assert "GUI (app killed after timeout)" in captured.out
        assert "512MB" in captured.out
        assert "2.0s delay" in captured.out

    def test_display_header_cli_mode(self, capsys: pytest.CaptureFixture) -> None:
        """Test header display in CLI mode."""
        args = Namespace(target="/path/to/app", timeout=5)
        files = [Path("test1.dcm")]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=False, memory_limit=None
        )

        captured = capsys.readouterr()
        assert "Target Application Testing" in captured.out
        assert "GUI" not in captured.out

    def test_display_header_no_memory_limit(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Test header display without memory limit."""
        args = Namespace(target="/path/to/app", timeout=5, startup_delay=0.0)
        files = [Path("test1.dcm")]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=True, memory_limit=None
        )

        captured = capsys.readouterr()
        assert "Mem limit" not in captured.out

    def test_display_header_no_startup_delay(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Test header display without startup delay."""
        args = Namespace(target="/path/to/app", timeout=5, startup_delay=0.0)
        files = [Path("test1.dcm")]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=True, memory_limit=None
        )

        captured = capsys.readouterr()
        assert "Startup" not in captured.out

    def test_display_header_shows_file_count(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Test header shows correct file count."""
        args = Namespace(target="/path/to/app", timeout=5)
        files = [Path(f"test{i}.dcm") for i in range(100)]

        TargetTestingController._display_header(
            args=args, files=files, gui_mode=False, memory_limit=None
        )

        captured = capsys.readouterr()
        assert "100" in captured.out


class TestCreateRunner:
    """Tests for _create_runner method."""

    @patch("dicom_fuzzer.cli.target_controller.TargetRunner")
    def test_create_cli_runner(self, mock_runner: MagicMock, tmp_path: Path) -> None:
        """Test creating CLI runner."""
        args = Namespace(target="/path/to/app", timeout=5)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        runner = TargetTestingController._create_runner(
            args=args,
            output_dir=output_dir,
            gui_mode=False,
            memory_limit=None,
            resource_limits=None,
        )

        mock_runner.assert_called_once()
        call_kwargs = mock_runner.call_args[1]
        assert call_kwargs["target_executable"] == "/path/to/app"
        assert call_kwargs["timeout"] == 5

    @pytest.mark.skipif(not HAS_PSUTIL, reason="psutil not installed")
    @patch("dicom_fuzzer.cli.target_controller.GUITargetRunner")
    def test_create_gui_runner_with_psutil(
        self, mock_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test creating GUI runner when psutil is available."""
        args = Namespace(target="/path/to/app", timeout=10, startup_delay=1.0)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        runner = TargetTestingController._create_runner(
            args=args,
            output_dir=output_dir,
            gui_mode=True,
            memory_limit=512,
            resource_limits=None,
        )

        mock_runner.assert_called_once()
        call_kwargs = mock_runner.call_args[1]
        assert call_kwargs["target_executable"] == "/path/to/app"
        assert call_kwargs["memory_limit_mb"] == 512
        assert call_kwargs["startup_delay"] == 1.0

    @patch("dicom_fuzzer.cli.target_controller.HAS_PSUTIL", False)
    def test_create_gui_runner_without_psutil(self, tmp_path: Path) -> None:
        """Test GUI runner creation fails without psutil."""
        args = Namespace(target="/path/to/app", timeout=10, startup_delay=0.0)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with pytest.raises(SystemExit) as exc_info:
            TargetTestingController._create_runner(
                args=args,
                output_dir=output_dir,
                gui_mode=True,
                memory_limit=None,
                resource_limits=None,
            )

        assert exc_info.value.code == 1

    @patch("dicom_fuzzer.cli.target_controller.TargetRunner")
    def test_create_runner_with_resource_limits(
        self, mock_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test creating runner with resource limits."""
        args = Namespace(target="/path/to/app", timeout=5)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_limits = MagicMock()

        TargetTestingController._create_runner(
            args=args,
            output_dir=output_dir,
            gui_mode=False,
            memory_limit=None,
            resource_limits=mock_limits,
        )

        call_kwargs = mock_runner.call_args[1]
        assert call_kwargs["resource_limits"] == mock_limits


class TestRun:
    """Tests for run method."""

    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._create_runner")
    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._display_header")
    def test_run_success(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test successful run."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        files[0].write_bytes(b"test")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_runner = MagicMock()
        mock_runner.run_campaign.return_value = [{"status": "success"}]
        mock_runner.get_summary.return_value = "Test Summary"
        mock_create_runner.return_value = mock_runner

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 0
        mock_runner.run_campaign.assert_called_once()

    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._create_runner")
    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._display_header")
    def test_run_file_not_found(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run with FileNotFoundError."""
        args = Namespace(
            target="/nonexistent/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_create_runner.side_effect = FileNotFoundError("Target not found")

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 1

    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._create_runner")
    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._display_header")
    def test_run_import_error(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run with ImportError."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_create_runner.side_effect = ImportError("Missing dependency")

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 1

    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._create_runner")
    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._display_header")
    def test_run_general_exception(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run with general exception."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_create_runner.side_effect = RuntimeError("Something went wrong")

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 1

    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._create_runner")
    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._display_header")
    def test_run_general_exception_verbose(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run with general exception in verbose mode."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=True,
        )
        files = [tmp_path / "test.dcm"]
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_create_runner.side_effect = RuntimeError("Something went wrong")

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 1

    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._create_runner")
    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._display_header")
    def test_run_with_resource_limits_logging(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run logs resource limits message."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            memory_limit=None,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        files[0].write_bytes(b"test")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_runner = MagicMock()
        mock_runner.run_campaign.return_value = []
        mock_runner.get_summary.return_value = "Summary"
        mock_create_runner.return_value = mock_runner

        mock_limits = MagicMock()

        result = TargetTestingController.run(
            args, files, output_dir, resource_limits=mock_limits
        )

        assert result == 0


class TestGetAttrDefaults:
    """Tests for getattr default value handling."""

    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._create_runner")
    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._display_header")
    def test_run_without_gui_mode_attr(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run when gui_mode attr is missing (uses default False)."""
        # Create args without gui_mode attribute
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        files[0].write_bytes(b"test")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_runner = MagicMock()
        mock_runner.run_campaign.return_value = []
        mock_runner.get_summary.return_value = "Summary"
        mock_create_runner.return_value = mock_runner

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 0
        # Should use default gui_mode=False
        call_kwargs = mock_create_runner.call_args[1]
        assert call_kwargs["gui_mode"] is False

    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._create_runner")
    @patch("dicom_fuzzer.cli.target_controller.TargetTestingController._display_header")
    def test_run_without_memory_limit_attr(
        self, mock_header: MagicMock, mock_create_runner: MagicMock, tmp_path: Path
    ) -> None:
        """Test run when memory_limit attr is missing (uses default None)."""
        args = Namespace(
            target="/path/to/app",
            timeout=5,
            gui_mode=False,
            stop_on_crash=False,
            verbose=False,
        )
        files = [tmp_path / "test.dcm"]
        files[0].write_bytes(b"test")
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        mock_runner = MagicMock()
        mock_runner.run_campaign.return_value = []
        mock_runner.get_summary.return_value = "Summary"
        mock_create_runner.return_value = mock_runner

        result = TargetTestingController.run(args, files, output_dir)

        assert result == 0
        # Should use default memory_limit=None
        call_kwargs = mock_create_runner.call_args[1]
        assert call_kwargs["memory_limit"] is None
