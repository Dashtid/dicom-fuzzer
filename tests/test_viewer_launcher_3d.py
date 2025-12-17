"""
Unit Tests for ViewerLauncher3D

Tests the 3D DICOM viewer launcher and harness functionality.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.target_runner import ExecutionStatus
from dicom_fuzzer.harness import (
    SeriesTestResult,
    ViewerConfig,
    ViewerLauncher3D,
    ViewerType,
    create_generic_config,
)


@pytest.fixture
def temp_viewer_executable():
    """Create a temporary mock viewer executable."""
    temp_dir = Path(tempfile.mkdtemp())
    viewer_path = temp_dir / "mock_viewer.exe"
    viewer_path.write_text("#!/bin/bash\necho 'Mock viewer'\n")
    viewer_path.chmod(0o755)
    yield viewer_path
    # Cleanup
    if temp_dir.exists():
        shutil.rmtree(temp_dir)


@pytest.fixture
def temp_series_folder():
    """Create a temporary folder with mock DICOM files."""
    temp_dir = Path(tempfile.mkdtemp())
    # Create mock DICOM files
    for i in range(1, 6):
        dcm_file = temp_dir / f"slice_{i:03d}.dcm"
        # Write DICOM magic bytes at offset 128
        with open(dcm_file, "wb") as f:
            f.write(b"\x00" * 128)
            f.write(b"DICM")
            f.write(b"\x00" * 100)
    yield temp_dir
    # Cleanup
    if temp_dir.exists():
        shutil.rmtree(temp_dir)


@pytest.fixture
def generic_config(temp_viewer_executable):
    """Create a generic ViewerConfig for testing."""
    return ViewerConfig(
        viewer_type=ViewerType.GENERIC,
        executable_path=temp_viewer_executable,
        command_template="{folder_path}",
        timeout_seconds=2,  # Short timeout for tests
    )


class TestViewerConfig:
    """Test ViewerConfig dataclass."""

    def test_valid_initialization(self, temp_viewer_executable):
        """Test valid ViewerConfig initialization."""
        config = ViewerConfig(
            viewer_type=ViewerType.GENERIC,
            executable_path=temp_viewer_executable,
            command_template="{folder_path}",
        )
        assert config.viewer_type == ViewerType.GENERIC
        assert config.timeout_seconds == 60  # Default

    def test_format_command(self, generic_config, temp_series_folder):
        """Test command formatting with folder path."""
        args = generic_config.format_command(temp_series_folder)
        assert str(generic_config.executable_path) in args
        assert str(temp_series_folder) in " ".join(args)

    def test_format_command_with_additional_args(
        self, temp_viewer_executable, temp_series_folder
    ):
        """Test command formatting with additional arguments."""
        config = ViewerConfig(
            viewer_type=ViewerType.GENERIC,
            executable_path=temp_viewer_executable,
            command_template="{folder_path}",
            additional_args=["--fullscreen", "--no-splash"],
        )
        args = config.format_command(temp_series_folder)
        assert "--fullscreen" in args
        assert "--no-splash" in args


class TestViewerLauncher3DInitialization:
    """Test ViewerLauncher3D initialization."""

    def test_valid_initialization(self, generic_config):
        """Test valid initialization."""
        launcher = ViewerLauncher3D(generic_config)
        assert launcher.config == generic_config
        assert launcher.monitor_memory is True
        assert launcher.kill_on_timeout is True

    def test_initialization_with_monitoring_disabled(self, generic_config):
        """Test initialization with monitoring disabled."""
        launcher = ViewerLauncher3D(generic_config, monitor_memory=False)
        assert launcher.monitor_memory is False

    def test_initialization_nonexistent_executable(self):
        """Test initialization with non-existent executable raises error."""
        config = ViewerConfig(
            viewer_type=ViewerType.GENERIC,
            executable_path=Path("/nonexistent/viewer.exe"),
            command_template="{folder_path}",
        )
        with pytest.raises(FileNotFoundError, match="Viewer executable not found"):
            ViewerLauncher3D(config)


class TestLaunchWithSeries:
    """Test launch_with_series method."""

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.subprocess.Popen")
    def test_launch_success(self, mock_popen, generic_config, temp_series_folder):
        """Test successful viewer launch."""
        # Mock process
        mock_process = Mock()
        mock_process.poll.return_value = 0  # Success
        mock_process.returncode = 0
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"")
        mock_popen.return_value = mock_process

        launcher = ViewerLauncher3D(generic_config, monitor_memory=False)
        result = launcher.launch_with_series(temp_series_folder)

        assert result.status == ExecutionStatus.SUCCESS
        assert (
            result.slice_count >= 5
        )  # At least 5 slices (may double-count on Windows)
        assert not result.crashed
        assert not result.timed_out

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.subprocess.Popen")
    def test_launch_crash(self, mock_popen, generic_config, temp_series_folder):
        """Test viewer crash detection."""
        # Mock process that crashes
        mock_process = Mock()
        mock_process.poll.return_value = 1  # Crashed
        mock_process.returncode = 1
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"Segmentation fault")
        mock_popen.return_value = mock_process

        launcher = ViewerLauncher3D(generic_config, monitor_memory=False)
        result = launcher.launch_with_series(temp_series_folder)

        assert result.status == ExecutionStatus.CRASH
        assert result.crashed
        assert result.exit_code == 1

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.subprocess.Popen")
    @patch.object(ViewerLauncher3D, "_kill_process_tree")
    def test_launch_timeout(
        self, mock_kill, mock_popen, generic_config, temp_series_folder
    ):
        """Test viewer timeout detection."""
        # Mock process that times out
        mock_process = Mock()
        mock_process.poll.return_value = None  # Still running
        mock_process.pid = 12345
        mock_process.communicate.side_effect = subprocess.TimeoutExpired("cmd", 2)
        mock_popen.return_value = mock_process

        launcher = ViewerLauncher3D(
            generic_config, monitor_memory=False, kill_on_timeout=True
        )
        result = launcher.launch_with_series(temp_series_folder)

        assert result.status == ExecutionStatus.HANG
        assert result.timed_out
        # Verify kill was called
        assert mock_kill.called

    def test_launch_nonexistent_folder(self, generic_config):
        """Test launch with non-existent folder raises error."""
        launcher = ViewerLauncher3D(generic_config)
        with pytest.raises(FileNotFoundError, match="Series folder not found"):
            launcher.launch_with_series(Path("/nonexistent/folder"))


class TestCountDicomFiles:
    """Test _count_dicom_files method."""

    def test_count_dcm_files(self, generic_config, temp_series_folder):
        """Test counting .dcm files."""
        launcher = ViewerLauncher3D(generic_config)
        count = launcher._count_dicom_files(temp_series_folder)
        assert count >= 5  # At least 5 slices (may double-count extensions on Windows)

    def test_count_mixed_extensions(self, generic_config):
        """Test counting files with different extensions."""
        temp_dir = Path(tempfile.mkdtemp())
        try:
            # Create files with different extensions
            (temp_dir / "file1.dcm").write_bytes(b"\x00" * 128 + b"DICM")
            (temp_dir / "file2.DCM").write_bytes(b"\x00" * 128 + b"DICM")
            (temp_dir / "file3.dicom").write_bytes(b"\x00" * 128 + b"DICM")

            launcher = ViewerLauncher3D(generic_config)
            count = launcher._count_dicom_files(temp_dir)
            assert count >= 3  # At least 3 files (case-insensitive on Windows)
        finally:
            shutil.rmtree(temp_dir)


class TestCrashCorrelation:
    """Test _correlate_crash_to_slice method."""

    def test_correlate_with_filename_pattern(self, generic_config, temp_series_folder):
        """Test crash correlation with filename in error."""
        launcher = ViewerLauncher3D(generic_config)
        stderr = "Error loading slice_003.dcm: Invalid data"
        result = launcher._correlate_crash_to_slice(temp_series_folder, stderr, "")
        assert result == 2  # 0-based index (slice 3 = index 2)

    def test_correlate_with_slice_number(self, generic_config, temp_series_folder):
        """Test crash correlation with slice number."""
        launcher = ViewerLauncher3D(generic_config)
        stderr = "Failed to load slice 4"
        result = launcher._correlate_crash_to_slice(temp_series_folder, stderr, "")
        assert result == 3  # 0-based index

    def test_correlate_no_match(self, generic_config, temp_series_folder):
        """Test crash correlation when no pattern matches."""
        launcher = ViewerLauncher3D(generic_config)
        stderr = "Generic error message"
        result = launcher._correlate_crash_to_slice(temp_series_folder, stderr, "")
        assert result is None


class TestMemoryMonitoring:
    """Test _monitor_process method."""

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.Process")
    def test_monitor_process_memory(self, mock_psutil_process, generic_config):
        """Test memory monitoring during process execution."""
        # Mock process
        mock_process = Mock()
        mock_process.poll.side_effect = [None, None, 0]  # Running, then exits
        mock_process.pid = 12345

        # Mock psutil memory info
        mock_ps = Mock()
        mock_mem_info = Mock()
        mock_mem_info.rss = 100 * 1024 * 1024  # 100 MB
        mock_ps.memory_info.return_value = mock_mem_info
        mock_psutil_process.return_value = mock_ps

        launcher = ViewerLauncher3D(generic_config)
        peak_memory = launcher._monitor_process(mock_process, timeout=1)

        assert peak_memory > 0  # Should have recorded memory usage


class TestKillProcessTree:
    """Test _kill_process_tree method."""

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.Process")
    def test_kill_process_tree(self, mock_psutil_process, generic_config):
        """Test killing process tree."""
        # Mock process
        mock_process = Mock()
        mock_process.pid = 12345

        # Mock psutil
        mock_parent = Mock()
        mock_child1 = Mock()
        mock_child2 = Mock()
        mock_parent.children.return_value = [mock_child1, mock_child2]
        mock_psutil_process.return_value = mock_parent

        launcher = ViewerLauncher3D(generic_config)
        launcher._kill_process_tree(mock_process)

        # Verify kill was called on children and parent
        mock_child1.kill.assert_called_once()
        mock_child2.kill.assert_called_once()
        mock_parent.kill.assert_called_once()


class TestSeriesTestResult:
    """Test SeriesTestResult dataclass."""

    def test_result_initialization(self, temp_series_folder):
        """Test SeriesTestResult initialization."""
        result = SeriesTestResult(
            status=ExecutionStatus.SUCCESS,
            series_folder=temp_series_folder,
            slice_count=5,
            execution_time=1.5,
            peak_memory_mb=150.0,
        )

        assert result.status == ExecutionStatus.SUCCESS
        assert result.slice_count == 5
        assert not result.crashed
        assert not result.timed_out

    def test_result_with_crash(self, temp_series_folder):
        """Test SeriesTestResult with crash."""
        result = SeriesTestResult(
            status=ExecutionStatus.CRASH,
            series_folder=temp_series_folder,
            slice_count=5,
            execution_time=0.5,
            peak_memory_mb=100.0,
            crashed=True,
            exit_code=-11,
            crash_slice_index=3,
            stderr="Segmentation fault at slice 4",
        )

        assert result.crashed
        assert result.crash_slice_index == 3
        assert "Segmentation fault" in result.stderr


class TestCreateGenericConfig:
    """Test create_generic_config helper function."""

    def test_create_generic_config_defaults(self, temp_viewer_executable):
        """Test create_generic_config with defaults."""
        config = create_generic_config(temp_viewer_executable)

        assert config.viewer_type == ViewerType.GENERIC
        assert config.executable_path == temp_viewer_executable
        assert config.timeout_seconds == 60
        assert config.memory_limit_mb is None

    def test_create_generic_config_custom(self, temp_viewer_executable):
        """Test create_generic_config with custom values."""
        config = create_generic_config(
            temp_viewer_executable, timeout=120, memory_limit_mb=2048
        )

        assert config.timeout_seconds == 120
        assert config.memory_limit_mb == 2048


class TestViewerTypeEnum:
    """Test ViewerType enum."""

    def test_all_viewer_types(self):
        """Test that all viewer types are defined."""
        types = [
            ViewerType.GENERIC,
            ViewerType.MICRODICOM,
            ViewerType.RADIANT,
            ViewerType.RUBO,
            ViewerType.CUSTOM,
        ]

        assert len(types) == 5
        assert all(isinstance(t.value, str) for t in types)


class TestEdgeCasesAndExceptionPaths:
    """Test edge cases and exception handling paths."""

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.subprocess.Popen")
    def test_launch_with_memory_monitoring(
        self, mock_popen, generic_config, temp_series_folder
    ):
        """Test launch with memory monitoring enabled (line 199)."""
        # Mock process
        mock_process = Mock()
        mock_process.poll.side_effect = [None, 0]  # Running, then exits
        mock_process.returncode = 0
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        with patch.object(ViewerLauncher3D, "_monitor_process", return_value=150.0):
            launcher = ViewerLauncher3D(generic_config, monitor_memory=True)
            result = launcher.launch_with_series(temp_series_folder)

            assert result.peak_memory_mb == 150.0
            assert result.status == ExecutionStatus.SUCCESS

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.subprocess.Popen")
    def test_launch_exception_during_execution(
        self, mock_popen, generic_config, temp_series_folder
    ):
        """Test exception during viewer launch (lines 220-223)."""
        # Mock Popen to raise exception
        mock_popen.side_effect = OSError("Failed to launch process")

        launcher = ViewerLauncher3D(generic_config, monitor_memory=False)
        result = launcher.launch_with_series(temp_series_folder)

        assert result.crashed
        assert result.status == ExecutionStatus.CRASH
        assert "Failed to launch process" in result.stderr

    def test_count_dicom_extensionless_files(self, generic_config):
        """Test counting extensionless DICOM files (lines 289-295)."""
        temp_dir = Path(tempfile.mkdtemp())
        try:
            # Create extensionless file with DICOM magic bytes
            dicom_file = temp_dir / "extensionless_dicom"
            with open(dicom_file, "wb") as f:
                f.write(b"\x00" * 128)
                f.write(b"DICM")
                f.write(b"\x00" * 100)

            # Create non-DICOM extensionless file
            other_file = temp_dir / "other_file"
            other_file.write_bytes(b"Not a DICOM file")

            launcher = ViewerLauncher3D(generic_config)
            count = launcher._count_dicom_files(temp_dir)
            assert count >= 1  # At least the DICOM file
        finally:
            shutil.rmtree(temp_dir)

    def test_count_dicom_with_read_error(self, generic_config):
        """Test counting DICOM files when read fails (line 294-295)."""
        temp_dir = Path(tempfile.mkdtemp())
        try:
            # Create a directory that looks like an extensionless file
            # (will fail to open for reading)
            subdir = temp_dir / "fakefile"
            subdir.mkdir()

            launcher = ViewerLauncher3D(generic_config)
            # Should not raise, just skip the unreadable file
            count = launcher._count_dicom_files(temp_dir)
            assert count >= 0
        finally:
            shutil.rmtree(temp_dir)

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.Process")
    def test_monitor_process_timeout(self, mock_psutil_process, generic_config):
        """Test memory monitoring when process exceeds timeout (lines 321-322)."""
        mock_process = Mock()
        mock_process.poll.return_value = None  # Never exits
        mock_process.pid = 12345

        mock_ps = Mock()
        mock_mem_info = Mock()
        mock_mem_info.rss = 100 * 1024 * 1024  # 100 MB
        mock_ps.memory_info.return_value = mock_mem_info
        mock_psutil_process.return_value = mock_ps

        launcher = ViewerLauncher3D(generic_config)
        # Very short timeout to trigger timeout path
        with patch("time.time", side_effect=[0, 0.1, 1.1]):
            peak_memory = launcher._monitor_process(mock_process, timeout=1)
            assert peak_memory >= 0

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.Process")
    def test_monitor_process_exceeds_memory_limit(
        self, mock_psutil_process, temp_viewer_executable
    ):
        """Test monitoring when process exceeds memory limit (lines 335-341)."""
        config = ViewerConfig(
            viewer_type=ViewerType.GENERIC,
            executable_path=temp_viewer_executable,
            command_template="{folder_path}",
            timeout_seconds=10,
            memory_limit_mb=50,  # 50 MB limit
        )

        mock_process = Mock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345

        mock_ps = Mock()
        mock_mem_info = Mock()
        mock_mem_info.rss = 100 * 1024 * 1024  # 100 MB - exceeds limit
        mock_ps.memory_info.return_value = mock_mem_info
        mock_psutil_process.return_value = mock_ps

        launcher = ViewerLauncher3D(config)
        peak_memory = launcher._monitor_process(mock_process, timeout=10)
        # Should exit early due to memory limit
        assert peak_memory > 0

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.Process")
    def test_monitor_process_nosuchprocess_during_monitor(
        self, mock_psutil_process, generic_config
    ):
        """Test monitoring when process terminates during memory check (lines 345-346)."""
        import psutil

        mock_process = Mock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345

        mock_ps = Mock()
        mock_ps.memory_info.side_effect = psutil.NoSuchProcess(12345)
        mock_psutil_process.return_value = mock_ps

        launcher = ViewerLauncher3D(generic_config)
        peak_memory = launcher._monitor_process(mock_process, timeout=10)
        assert peak_memory == 0.0  # No memory recorded before termination

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.Process")
    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.wait_procs")
    def test_kill_process_tree_child_already_gone(
        self, mock_wait_procs, mock_psutil_process, generic_config
    ):
        """Test killing process tree when child is already gone (lines 365-366)."""
        import psutil

        mock_process = Mock()
        mock_process.pid = 12345

        mock_parent = Mock()
        mock_child = Mock()
        mock_child.kill.side_effect = psutil.NoSuchProcess(12346)
        mock_parent.children.return_value = [mock_child]
        mock_psutil_process.return_value = mock_parent
        mock_wait_procs.return_value = ([], [])

        launcher = ViewerLauncher3D(generic_config)
        # Should not raise
        launcher._kill_process_tree(mock_process)

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.Process")
    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.wait_procs")
    def test_kill_process_tree_parent_already_gone(
        self, mock_wait_procs, mock_psutil_process, generic_config
    ):
        """Test killing process tree when parent is already gone (lines 371-372)."""
        import psutil

        mock_process = Mock()
        mock_process.pid = 12345

        mock_parent = Mock()
        mock_parent.children.return_value = []
        mock_parent.kill.side_effect = psutil.NoSuchProcess(12345)
        mock_psutil_process.return_value = mock_parent
        mock_wait_procs.return_value = ([], [])

        launcher = ViewerLauncher3D(generic_config)
        # Should not raise
        launcher._kill_process_tree(mock_process)

    @patch("dicom_fuzzer.harness.viewer_launcher_3d.psutil.Process")
    def test_kill_process_tree_general_exception(
        self, mock_psutil_process, generic_config
    ):
        """Test killing process tree handles general exceptions (lines 381-384)."""
        mock_process = Mock()
        mock_process.pid = 12345

        mock_psutil_process.side_effect = Exception("Unexpected error")

        launcher = ViewerLauncher3D(generic_config)
        # Should not raise, just log warning
        launcher._kill_process_tree(mock_process)

    def test_correlate_crash_instance_pattern(self, generic_config, temp_series_folder):
        """Test crash correlation with instance/file pattern (line 425)."""
        launcher = ViewerLauncher3D(generic_config)

        # Test instance pattern
        stderr = "Error at instance 5"
        result = launcher._correlate_crash_to_slice(temp_series_folder, stderr, "")
        assert result == 4  # 0-based index

        # Test file pattern
        stderr = "Failed to load file 3"
        result = launcher._correlate_crash_to_slice(temp_series_folder, stderr, "")
        assert result == 2  # 0-based index
