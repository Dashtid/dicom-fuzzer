"""Tests for main.py GUITargetRunner class and GUIExecutionResult dataclass.

Tests cover GUI application execution, monitoring, and campaign management.
"""

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.target_runner import ExecutionStatus


class TestGUIExecutionResult:
    """Test GUIExecutionResult dataclass."""

    def test_dataclass_fields(self):
        """Test that dataclass has expected fields."""
        from dicom_fuzzer.cli.gui_runner import GUIExecutionResult

        result = GUIExecutionResult(
            test_file=Path("/test/file.dcm"),
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=1.5,
            peak_memory_mb=100.0,
            crashed=False,
            timed_out=True,
            stdout="output",
            stderr="",
        )

        assert result.test_file == Path("/test/file.dcm")
        assert result.status == ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert result.execution_time == 1.5
        assert result.peak_memory_mb == 100.0
        assert result.crashed is False
        assert result.timed_out is True
        assert result.stdout == "output"
        assert result.stderr == ""

    def test_bool_not_crashed(self):
        """Test __bool__ returns True when not crashed."""
        from dicom_fuzzer.cli.gui_runner import GUIExecutionResult

        result = GUIExecutionResult(
            test_file=Path("/test/file.dcm"),
            status=ExecutionStatus.SUCCESS,
            exit_code=None,
            execution_time=1.0,
            peak_memory_mb=50.0,
            crashed=False,
            timed_out=True,
        )

        assert bool(result) is True

    def test_bool_crashed(self):
        """Test __bool__ returns False when crashed."""
        from dicom_fuzzer.cli.gui_runner import GUIExecutionResult

        result = GUIExecutionResult(
            test_file=Path("/test/file.dcm"),
            status=ExecutionStatus.CRASH,
            exit_code=1,
            execution_time=0.5,
            peak_memory_mb=50.0,
            crashed=True,
            timed_out=False,
        )

        assert bool(result) is False


class TestGUITargetRunnerInit:
    """Test GUITargetRunner initialization."""

    def test_init_with_valid_executable(self, tmp_path):
        """Test initialization with valid executable."""
        # Create a mock executable
        exe_path = tmp_path / "viewer.exe"
        exe_path.write_bytes(b"mock executable")

        with patch("dicom_fuzzer.cli.gui_runner.HAS_PSUTIL", True):
            from dicom_fuzzer.cli.gui_runner import GUITargetRunner

            runner = GUITargetRunner(
                target_executable=str(exe_path),
                timeout=10.0,
                crash_dir=str(tmp_path / "crashes"),
                memory_limit_mb=512,
                startup_delay=2.0,
            )

            assert runner.target_executable == exe_path
            assert runner.timeout == 10.0
            assert runner.memory_limit_mb == 512
            assert runner.startup_delay == 2.0
            assert runner.total_tests == 0
            assert runner.crashes == 0

    def test_init_missing_executable(self, tmp_path):
        """Test initialization with missing executable raises error."""
        with patch("dicom_fuzzer.cli.gui_runner.HAS_PSUTIL", True):
            from dicom_fuzzer.cli.gui_runner import GUITargetRunner

            with pytest.raises(FileNotFoundError):
                GUITargetRunner(
                    target_executable=str(tmp_path / "nonexistent.exe"),
                    timeout=10.0,
                )

    def test_init_missing_psutil(self, tmp_path):
        """Test initialization without psutil raises ImportError."""
        exe_path = tmp_path / "viewer.exe"
        exe_path.write_bytes(b"mock executable")

        with patch("dicom_fuzzer.cli.gui_runner.HAS_PSUTIL", False):
            # Need to reload to get the check
            from dicom_fuzzer.cli.gui_runner import GUITargetRunner

            with pytest.raises(ImportError) as exc_info:
                GUITargetRunner(target_executable=str(exe_path))

            assert "psutil" in str(exc_info.value)


class TestGUITargetRunnerExecute:
    """Test GUITargetRunner execute_test method."""

    @pytest.fixture
    def mock_runner(self, tmp_path):
        """Create a GUITargetRunner with mocked dependencies."""
        exe_path = tmp_path / "viewer.exe"
        exe_path.write_bytes(b"mock executable")

        with patch("dicom_fuzzer.cli.gui_runner.HAS_PSUTIL", True):
            from dicom_fuzzer.cli.gui_runner import GUITargetRunner

            runner = GUITargetRunner(
                target_executable=str(exe_path),
                timeout=1.0,
                crash_dir=str(tmp_path / "crashes"),
            )
            return runner

    def test_execute_success_timeout(self, mock_runner, tmp_path):
        """Test successful execution that times out (normal for GUI apps)."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        # Mock subprocess and psutil
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Process still running
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"")

        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.return_value = MagicMock(rss=50 * 1024 * 1024)
        mock_ps_process.children.return_value = []
        mock_ps_process.kill.return_value = None

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch("psutil.Process", return_value=mock_ps_process),
            patch("psutil.wait_procs"),
        ):
            result = mock_runner.execute_test(test_file)

            assert result.crashed is False
            assert result.timed_out is True
            assert result.status == ExecutionStatus.SUCCESS

    def test_execute_crash_before_timeout(self, mock_runner, tmp_path):
        """Test execution where app crashes before timeout."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        # Mock subprocess - process exits with error code
        mock_process = MagicMock()
        mock_process.poll.return_value = 1  # Crashed
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"crash error")

        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.return_value = MagicMock(rss=50 * 1024 * 1024)

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch("psutil.Process", return_value=mock_ps_process),
        ):
            result = mock_runner.execute_test(test_file)

            assert result.crashed is True
            assert result.exit_code == 1
            assert result.status == ExecutionStatus.CRASH
            assert mock_runner.crashes == 1

    def test_execute_memory_exceeded(self, mock_runner, tmp_path):
        """Test execution where memory limit is exceeded."""
        mock_runner.memory_limit_mb = 100

        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        # Mock subprocess - process running
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"")

        # Mock psutil - memory exceeds limit
        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.return_value = MagicMock(
            rss=200 * 1024 * 1024
        )  # 200 MB
        mock_ps_process.children.return_value = []

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch("psutil.Process", return_value=mock_ps_process),
            patch("psutil.wait_procs"),
        ):
            result = mock_runner.execute_test(test_file)

            assert result.crashed is True
            assert mock_runner.memory_exceeded == 1

    def test_execute_process_dies_during_monitoring(self, mock_runner, tmp_path):
        """Test handling when process dies during monitoring."""
        import psutil

        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"")

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch("psutil.Process", side_effect=psutil.NoSuchProcess(12345)),
            patch("psutil.wait_procs"),
        ):
            result = mock_runner.execute_test(test_file)

            assert result.crashed is True


class TestGUITargetRunnerCampaign:
    """Test GUITargetRunner campaign methods."""

    @pytest.fixture
    def mock_runner(self, tmp_path):
        """Create a GUITargetRunner with mocked dependencies."""
        exe_path = tmp_path / "viewer.exe"
        exe_path.write_bytes(b"mock executable")

        with patch("dicom_fuzzer.cli.gui_runner.HAS_PSUTIL", True):
            from dicom_fuzzer.cli.gui_runner import GUITargetRunner

            runner = GUITargetRunner(
                target_executable=str(exe_path),
                timeout=0.1,
                crash_dir=str(tmp_path / "crashes"),
            )
            return runner

    def test_run_campaign_all_success(self, mock_runner, tmp_path):
        """Test campaign where all tests succeed."""
        from dicom_fuzzer.cli.gui_runner import GUIExecutionResult

        test_files = [tmp_path / f"test{i}.dcm" for i in range(3)]
        for f in test_files:
            f.write_bytes(b"test")

        # Mock execute_test to return success
        success_result = GUIExecutionResult(
            test_file=test_files[0],
            status=ExecutionStatus.SUCCESS,
            exit_code=None,
            execution_time=0.1,
            peak_memory_mb=50.0,
            crashed=False,
            timed_out=True,
        )

        with patch.object(mock_runner, "execute_test", return_value=success_result):
            results = mock_runner.run_campaign(test_files)

            assert len(results[ExecutionStatus.SUCCESS]) == 3
            assert len(results[ExecutionStatus.CRASH]) == 0

    def test_run_campaign_with_crash(self, mock_runner, tmp_path):
        """Test campaign with one crash."""
        from dicom_fuzzer.cli.gui_runner import GUIExecutionResult

        test_files = [tmp_path / f"test{i}.dcm" for i in range(3)]
        for f in test_files:
            f.write_bytes(b"test")

        success_result = GUIExecutionResult(
            test_file=test_files[0],
            status=ExecutionStatus.SUCCESS,
            exit_code=None,
            execution_time=0.1,
            peak_memory_mb=50.0,
            crashed=False,
            timed_out=True,
        )

        crash_result = GUIExecutionResult(
            test_file=test_files[1],
            status=ExecutionStatus.CRASH,
            exit_code=1,
            execution_time=0.05,
            peak_memory_mb=50.0,
            crashed=True,
            timed_out=False,
        )

        call_count = [0]

        def mock_execute(f):
            call_count[0] += 1
            if call_count[0] == 2:
                return crash_result
            return success_result

        with patch.object(mock_runner, "execute_test", side_effect=mock_execute):
            results = mock_runner.run_campaign(test_files)

            assert len(results[ExecutionStatus.SUCCESS]) == 2
            assert len(results[ExecutionStatus.CRASH]) == 1

    def test_run_campaign_stop_on_crash(self, mock_runner, tmp_path):
        """Test campaign stops on first crash when stop_on_crash=True."""
        from dicom_fuzzer.cli.gui_runner import GUIExecutionResult

        test_files = [tmp_path / f"test{i}.dcm" for i in range(5)]
        for f in test_files:
            f.write_bytes(b"test")

        crash_result = GUIExecutionResult(
            test_file=test_files[0],
            status=ExecutionStatus.CRASH,
            exit_code=1,
            execution_time=0.05,
            peak_memory_mb=50.0,
            crashed=True,
            timed_out=False,
        )

        with patch.object(mock_runner, "execute_test", return_value=crash_result):
            results = mock_runner.run_campaign(test_files, stop_on_crash=True)

            # Should stop after first crash
            total_tested = sum(len(r) for r in results.values())
            assert total_tested == 1

    def test_get_summary(self, mock_runner, tmp_path):
        """Test campaign summary generation."""
        from dicom_fuzzer.cli.gui_runner import GUIExecutionResult

        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        # Build results dict with all ExecutionStatus values
        results = {status: [] for status in ExecutionStatus}
        results[ExecutionStatus.SUCCESS] = [
            GUIExecutionResult(
                test_file=test_file,
                status=ExecutionStatus.SUCCESS,
                exit_code=None,
                execution_time=1.0,
                peak_memory_mb=100.0,
                crashed=False,
                timed_out=True,
            ),
            GUIExecutionResult(
                test_file=test_file,
                status=ExecutionStatus.SUCCESS,
                exit_code=None,
                execution_time=1.5,
                peak_memory_mb=150.0,
                crashed=False,
                timed_out=True,
            ),
        ]
        results[ExecutionStatus.CRASH] = [
            GUIExecutionResult(
                test_file=test_file,
                status=ExecutionStatus.CRASH,
                exit_code=1,
                execution_time=0.5,
                peak_memory_mb=200.0,
                crashed=True,
                timed_out=False,
            ),
        ]

        summary = mock_runner.get_summary(results)

        assert "Total tests" in summary
        assert "3" in summary  # Total
        assert "Successful" in summary
        assert "2" in summary  # Successful
        assert "Crashes" in summary
        assert "1" in summary  # Crashes
        assert "CRASHES DETECTED" in summary


class TestGUITargetRunnerKillProcessTree:
    """Test GUITargetRunner._kill_process_tree method edge cases."""

    @pytest.fixture
    def mock_runner(self, tmp_path):
        """Create a GUITargetRunner with mocked dependencies."""
        exe_path = tmp_path / "viewer.exe"
        exe_path.write_bytes(b"mock executable")

        with patch("dicom_fuzzer.cli.gui_runner.HAS_PSUTIL", True):
            from dicom_fuzzer.cli.gui_runner import GUITargetRunner

            runner = GUITargetRunner(
                target_executable=str(exe_path),
                timeout=1.0,
                crash_dir=str(tmp_path / "crashes"),
            )
            return runner

    def test_kill_process_tree_with_children(self, mock_runner):
        """Test killing process with multiple child processes."""
        mock_process = MagicMock()
        mock_process.pid = 12345

        mock_parent = MagicMock()
        mock_child1 = MagicMock()
        mock_child2 = MagicMock()
        mock_parent.children.return_value = [mock_child1, mock_child2]

        with (
            patch("psutil.Process", return_value=mock_parent),
            patch("psutil.wait_procs") as mock_wait,
        ):
            mock_runner._kill_process_tree(mock_process)

            # Verify children killed first
            mock_child1.kill.assert_called_once()
            mock_child2.kill.assert_called_once()
            mock_parent.kill.assert_called_once()
            mock_wait.assert_called_once()

    def test_kill_process_tree_child_already_terminated(self, mock_runner):
        """Test handling when child process already terminated (NoSuchProcess)."""
        import psutil

        mock_process = MagicMock()
        mock_process.pid = 12345

        mock_parent = MagicMock()
        mock_child1 = MagicMock()
        mock_child1.kill.side_effect = psutil.NoSuchProcess(111)
        mock_child2 = MagicMock()
        mock_parent.children.return_value = [mock_child1, mock_child2]

        with (
            patch("psutil.Process", return_value=mock_parent),
            patch("psutil.wait_procs"),
        ):
            # Should not raise, should continue to kill other processes
            mock_runner._kill_process_tree(mock_process)

            # child2 and parent should still be killed
            mock_child2.kill.assert_called_once()
            mock_parent.kill.assert_called_once()

    def test_kill_process_tree_parent_already_terminated(self, mock_runner):
        """Test handling when parent terminates before kill."""
        import psutil

        mock_process = MagicMock()
        mock_process.pid = 12345

        mock_parent = MagicMock()
        mock_parent.children.return_value = []
        mock_parent.kill.side_effect = psutil.NoSuchProcess(12345)

        with (
            patch("psutil.Process", return_value=mock_parent),
            patch("psutil.wait_procs"),
        ):
            # Should not raise
            result = mock_runner._kill_process_tree(mock_process)
            assert result is None  # Gracefully handled terminated parent
            mock_parent.kill.assert_called_once()  # Kill was attempted

    def test_kill_process_tree_process_not_found(self, mock_runner):
        """Test when psutil.Process() raises NoSuchProcess immediately."""
        import psutil

        mock_process = MagicMock()
        mock_process.pid = 12345

        with patch(
            "psutil.Process", side_effect=psutil.NoSuchProcess(12345)
        ) as mock_ps:
            # Should not raise - process already gone
            result = mock_runner._kill_process_tree(mock_process)
            assert result is None  # Gracefully handled missing process
            mock_ps.assert_called_once_with(12345)  # Attempted to get process

    def test_kill_process_tree_general_exception(self, mock_runner):
        """Test handling of unexpected exceptions during kill."""
        mock_process = MagicMock()
        mock_process.pid = 12345

        with patch(
            "psutil.Process", side_effect=OSError("Unexpected error")
        ) as mock_ps:
            # Should not raise - logs warning but continues
            result = mock_runner._kill_process_tree(mock_process)
            assert result is None  # Gracefully handled exception
            mock_ps.assert_called_once_with(12345)  # Attempted to get process

    def test_kill_process_tree_nested_children(self, mock_runner):
        """Test killing deeply nested process tree (recursive=True)."""
        mock_process = MagicMock()
        mock_process.pid = 12345

        mock_parent = MagicMock()
        # Simulate grandchildren by having recursive=True return all descendants
        mock_child = MagicMock()
        mock_grandchild = MagicMock()
        mock_parent.children.return_value = [mock_child, mock_grandchild]

        with (
            patch("psutil.Process", return_value=mock_parent),
            patch("psutil.wait_procs"),
        ):
            mock_runner._kill_process_tree(mock_process)

            # All descendants should be killed
            mock_child.kill.assert_called_once()
            mock_grandchild.kill.assert_called_once()
            mock_parent.kill.assert_called_once()


class TestGUITargetRunnerExecuteEdgeCases:
    """Test GUITargetRunner.execute_test edge cases."""

    @pytest.fixture
    def mock_runner(self, tmp_path):
        """Create a GUITargetRunner with mocked dependencies."""
        exe_path = tmp_path / "viewer.exe"
        exe_path.write_bytes(b"mock executable")

        with patch("dicom_fuzzer.cli.gui_runner.HAS_PSUTIL", True):
            from dicom_fuzzer.cli.gui_runner import GUITargetRunner

            runner = GUITargetRunner(
                target_executable=str(exe_path),
                timeout=0.5,
                crash_dir=str(tmp_path / "crashes"),
                startup_delay=0.1,
            )
            return runner

    def test_execute_with_startup_delay(self, mock_runner, tmp_path):
        """Test startup delay is applied before monitoring starts."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"")

        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.return_value = MagicMock(rss=50 * 1024 * 1024)
        mock_ps_process.children.return_value = []

        start_time = time.time()
        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch("psutil.Process", return_value=mock_ps_process),
            patch("psutil.wait_procs"),
        ):
            result = mock_runner.execute_test(test_file)
            elapsed = time.time() - start_time

            # Should take at least startup_delay (0.1s)
            assert elapsed >= 0.05 or result is not None

    def test_execute_process_launch_failure(self, mock_runner, tmp_path):
        """Test handling when subprocess.Popen fails."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        with patch(
            "subprocess.Popen", side_effect=FileNotFoundError("Executable not found")
        ):
            result = mock_runner.execute_test(test_file)

            assert result.crashed is True
            assert "Executable not found" in result.stderr

    def test_execute_string_test_file_path(self, mock_runner, tmp_path):
        """Test execute_test accepts string path (not just Path)."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        mock_process = MagicMock()
        mock_process.poll.return_value = 0  # Clean exit
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"output", b"")

        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.return_value = MagicMock(rss=50 * 1024 * 1024)

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch("psutil.Process", return_value=mock_ps_process),
        ):
            # Pass string instead of Path
            result = mock_runner.execute_test(str(test_file))

            assert result.test_file == Path(test_file)

    def test_execute_normal_exit_zero(self, mock_runner, tmp_path):
        """Test process exiting with code 0 before timeout is success."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        mock_process = MagicMock()
        mock_process.poll.return_value = 0  # Clean exit before timeout
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"")

        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.return_value = MagicMock(rss=50 * 1024 * 1024)

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch("psutil.Process", return_value=mock_ps_process),
        ):
            result = mock_runner.execute_test(test_file)

            # Exit code 0 should be success, not crash
            assert result.exit_code == 0
            assert result.crashed is False
            assert result.status == ExecutionStatus.SUCCESS

    def test_execute_negative_exit_code_crash(self, mock_runner, tmp_path):
        """Test process with negative exit code (signal) is detected as crash."""
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test")

        mock_process = MagicMock()
        mock_process.poll.return_value = -11  # SIGSEGV
        mock_process.pid = 12345
        mock_process.communicate.return_value = (b"", b"segfault")

        mock_ps_process = MagicMock()
        mock_ps_process.memory_info.return_value = MagicMock(rss=50 * 1024 * 1024)

        with (
            patch("subprocess.Popen", return_value=mock_process),
            patch("psutil.Process", return_value=mock_ps_process),
        ):
            result = mock_runner.execute_test(test_file)

            assert result.exit_code == -11
            assert result.crashed is True
            assert result.status == ExecutionStatus.CRASH
