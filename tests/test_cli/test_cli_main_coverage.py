"""Coverage-focused tests for CLI main module.

These tests focus on improving coverage for the GUITargetRunner class
and GUIExecutionResult dataclass which are harder to test with mocks.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.main import (
    GUIExecutionResult,
    GUITargetRunner,
    format_duration,
    format_file_size,
    parse_strategies,
    pre_campaign_health_check,
    setup_logging,
    validate_input_file,
    validate_strategy,
)
from dicom_fuzzer.core.target_runner import ExecutionStatus


class TestGUIExecutionResultCoverage:
    """Test GUIExecutionResult dataclass."""

    def test_gui_result_bool_success(self):
        """Test GUIExecutionResult __bool__ returns True when not crashed."""
        result = GUIExecutionResult(
            test_file=Path("/tmp/test.dcm"),
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=1.0,
            peak_memory_mb=100.0,
            crashed=False,
            timed_out=True,
        )
        assert bool(result) is True

    def test_gui_result_bool_crash(self):
        """Test GUIExecutionResult __bool__ returns False when crashed."""
        result = GUIExecutionResult(
            test_file=Path("/tmp/test.dcm"),
            status=ExecutionStatus.CRASH,
            exit_code=-1,
            execution_time=0.5,
            peak_memory_mb=150.0,
            crashed=True,
            timed_out=False,
        )
        assert bool(result) is False

    def test_gui_result_attributes(self):
        """Test GUIExecutionResult stores all attributes correctly."""
        test_path = Path("/tmp/test.dcm")
        result = GUIExecutionResult(
            test_file=test_path,
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=2.5,
            peak_memory_mb=256.0,
            crashed=False,
            timed_out=True,
            stdout="output text",
            stderr="error text",
        )

        assert result.test_file == test_path
        assert result.status == ExecutionStatus.SUCCESS
        assert result.exit_code == 0
        assert result.execution_time == 2.5
        assert result.peak_memory_mb == 256.0
        assert result.crashed is False
        assert result.timed_out is True
        assert result.stdout == "output text"
        assert result.stderr == "error text"

    def test_gui_result_default_stdout_stderr(self):
        """Test GUIExecutionResult default stdout/stderr values."""
        result = GUIExecutionResult(
            test_file=Path("/tmp/test.dcm"),
            status=ExecutionStatus.SUCCESS,
            exit_code=0,
            execution_time=1.0,
            peak_memory_mb=100.0,
            crashed=False,
            timed_out=False,
        )
        assert result.stdout == ""
        assert result.stderr == ""


class TestGUITargetRunnerInit:
    """Test GUITargetRunner initialization."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_init_with_existing_executable(self, temp_dir):
        """Test initialization with existing executable."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            timeout=10.0,
            crash_dir=str(temp_dir / "crashes"),
            memory_limit_mb=2048,
        )

        assert runner.target_executable == target
        assert runner.timeout == 10.0
        assert runner.memory_limit_mb == 2048
        assert runner.total_tests == 0
        assert runner.crashes == 0
        assert runner.timeouts == 0
        assert runner.memory_exceeded == 0

    def test_init_creates_crash_dir(self, temp_dir):
        """Test that initialization creates crash directory."""
        target = temp_dir / "target.exe"
        target.touch()
        crash_dir = temp_dir / "new_crashes"

        assert not crash_dir.exists()

        runner = GUITargetRunner(
            target_executable=str(target),
            crash_dir=str(crash_dir),
        )

        assert crash_dir.exists()

    def test_init_nonexistent_executable(self, temp_dir):
        """Test initialization fails with nonexistent executable."""
        with pytest.raises(FileNotFoundError):
            GUITargetRunner(
                target_executable="/nonexistent/path/to/app",
                crash_dir=str(temp_dir / "crashes"),
            )


class TestGUITargetRunnerExecuteTest:
    """Test GUITargetRunner.execute_test method."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_runner(self, temp_dir):
        """Create a runner with mocked target."""
        target = temp_dir / "target.exe"
        target.touch()
        return GUITargetRunner(
            target_executable=str(target),
            timeout=1.0,
            crash_dir=str(temp_dir / "crashes"),
        )

    def test_execute_test_timeout_success(self, mock_runner, temp_dir):
        """Test execute_test returns success on timeout (expected for GUI)."""
        test_file = temp_dir / "test.dcm"
        test_file.touch()

        # Mock subprocess to not exit
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = None  # Process running
            mock_process.communicate.return_value = (b"", b"")
            mock_popen.return_value = mock_process

            # Mock psutil for memory monitoring
            with patch("psutil.Process") as mock_psutil_process:
                mock_ps = MagicMock()
                mock_ps.memory_info.return_value = MagicMock(rss=100 * 1024 * 1024)
                mock_psutil_process.return_value = mock_ps

                with patch.object(mock_runner, "_kill_process_tree"):
                    result = mock_runner.execute_test(test_file)

        assert result.status == ExecutionStatus.SUCCESS
        assert result.timed_out is True
        assert result.crashed is False

    def test_execute_test_crash_before_timeout(self, mock_runner, temp_dir):
        """Test execute_test detects crash before timeout."""
        test_file = temp_dir / "test.dcm"
        test_file.touch()

        # Mock subprocess to exit with error code
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = -1  # Crashed
            mock_process.communicate.return_value = (b"error", b"crash")
            mock_popen.return_value = mock_process

            # Mock psutil
            with patch("psutil.Process") as mock_psutil_process:
                mock_ps = MagicMock()
                mock_ps.memory_info.return_value = MagicMock(rss=50 * 1024 * 1024)
                mock_psutil_process.return_value = mock_ps

                result = mock_runner.execute_test(test_file)

        assert result.status == ExecutionStatus.CRASH
        assert result.crashed is True
        assert result.exit_code == -1

    def test_execute_test_memory_exceeded(self, temp_dir):
        """Test execute_test detects memory limit exceeded."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            timeout=5.0,
            crash_dir=str(temp_dir / "crashes"),
            memory_limit_mb=100,  # Low limit
        )

        test_file = temp_dir / "test.dcm"
        test_file.touch()

        # Mock subprocess
        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_process.communicate.return_value = (b"", b"")
            mock_popen.return_value = mock_process

            # Mock psutil to return high memory
            with patch("psutil.Process") as mock_psutil_process:
                mock_ps = MagicMock()
                mock_ps.memory_info.return_value = MagicMock(
                    rss=200 * 1024 * 1024
                )  # 200MB
                mock_psutil_process.return_value = mock_ps

                with patch.object(runner, "_kill_process_tree"):
                    result = runner.execute_test(test_file)

        assert result.crashed is True
        assert runner.memory_exceeded == 1

    def test_execute_test_with_string_path(self, mock_runner, temp_dir):
        """Test execute_test accepts string path."""
        test_file = temp_dir / "test.dcm"
        test_file.touch()

        with patch("subprocess.Popen") as mock_popen:
            mock_process = MagicMock()
            mock_process.poll.return_value = None
            mock_process.communicate.return_value = (b"", b"")
            mock_popen.return_value = mock_process

            with patch("psutil.Process") as mock_psutil_process:
                mock_ps = MagicMock()
                mock_ps.memory_info.return_value = MagicMock(rss=50 * 1024 * 1024)
                mock_psutil_process.return_value = mock_ps

                with patch.object(mock_runner, "_kill_process_tree"):
                    result = mock_runner.execute_test(str(test_file))  # String path

        assert result.test_file == test_file


class TestGUITargetRunnerKillProcessTree:
    """Test GUITargetRunner._kill_process_tree method."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_kill_process_tree_success(self, temp_dir):
        """Test kill_process_tree kills process and children."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            crash_dir=str(temp_dir / "crashes"),
        )

        mock_process = MagicMock()
        mock_process.pid = 12345

        with patch("psutil.Process") as mock_psutil:
            mock_parent = MagicMock()
            mock_child = MagicMock()
            mock_parent.children.return_value = [mock_child]
            mock_psutil.return_value = mock_parent

            with patch("psutil.wait_procs"):
                runner._kill_process_tree(mock_process)

            mock_child.kill.assert_called_once()
            mock_parent.kill.assert_called_once()

    def test_kill_process_tree_no_such_process(self, temp_dir):
        """Test kill_process_tree handles NoSuchProcess."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            crash_dir=str(temp_dir / "crashes"),
        )

        mock_process = MagicMock()
        mock_process.pid = 12345

        import psutil

        with patch("psutil.Process", side_effect=psutil.NoSuchProcess(12345)):
            # Should not raise
            runner._kill_process_tree(mock_process)


class TestGUITargetRunnerRunCampaign:
    """Test GUITargetRunner.run_campaign method."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_run_campaign_basic(self, temp_dir):
        """Test run_campaign executes all test files."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            timeout=0.1,
            crash_dir=str(temp_dir / "crashes"),
        )

        # Create test files
        test_files = []
        for i in range(3):
            f = temp_dir / f"test_{i}.dcm"
            f.touch()
            test_files.append(f)

        # Mock execute_test to return success
        with patch.object(runner, "execute_test") as mock_execute:
            mock_execute.return_value = GUIExecutionResult(
                test_file=test_files[0],
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                execution_time=0.1,
                peak_memory_mb=100.0,
                crashed=False,
                timed_out=True,
            )

            results = runner.run_campaign(test_files)

        assert ExecutionStatus.SUCCESS in results
        assert len(results[ExecutionStatus.SUCCESS]) == 3
        assert mock_execute.call_count == 3

    def test_run_campaign_stop_on_crash(self, temp_dir):
        """Test run_campaign stops on first crash when stop_on_crash=True."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            timeout=0.1,
            crash_dir=str(temp_dir / "crashes"),
        )

        test_files = [temp_dir / f"test_{i}.dcm" for i in range(5)]
        for f in test_files:
            f.touch()

        # First call succeeds, second crashes
        results = [
            GUIExecutionResult(
                test_file=test_files[0],
                status=ExecutionStatus.SUCCESS,
                exit_code=0,
                execution_time=0.1,
                peak_memory_mb=100.0,
                crashed=False,
                timed_out=True,
            ),
            GUIExecutionResult(
                test_file=test_files[1],
                status=ExecutionStatus.CRASH,
                exit_code=-1,
                execution_time=0.05,
                peak_memory_mb=150.0,
                crashed=True,
                timed_out=False,
            ),
        ]

        with patch.object(runner, "execute_test", side_effect=results):
            campaign_results = runner.run_campaign(test_files, stop_on_crash=True)

        # Should have stopped after crash
        total = sum(len(r) for r in campaign_results.values())
        assert total == 2


class TestGUITargetRunnerGetSummary:
    """Test GUITargetRunner.get_summary method."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_get_summary_no_crashes(self, temp_dir):
        """Test get_summary with no crashes."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            crash_dir=str(temp_dir / "crashes"),
        )

        results = {
            ExecutionStatus.SUCCESS: [
                GUIExecutionResult(
                    test_file=Path("/tmp/test1.dcm"),
                    status=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    execution_time=1.0,
                    peak_memory_mb=100.0,
                    crashed=False,
                    timed_out=True,
                ),
                GUIExecutionResult(
                    test_file=Path("/tmp/test2.dcm"),
                    status=ExecutionStatus.SUCCESS,
                    exit_code=0,
                    execution_time=1.0,
                    peak_memory_mb=200.0,
                    crashed=False,
                    timed_out=True,
                ),
            ],
            ExecutionStatus.CRASH: [],
            ExecutionStatus.HANG: [],
            ExecutionStatus.ERROR: [],
        }

        summary = runner.get_summary(results)

        assert "Total tests:" in summary
        assert "Successful:" in summary
        assert "Crashes:" in summary
        assert "Avg memory:" in summary
        assert "Peak memory:" in summary

    def test_get_summary_with_crashes(self, temp_dir):
        """Test get_summary with crashes."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            crash_dir=str(temp_dir / "crashes"),
        )

        crash_results = []
        for i in range(15):
            crash_results.append(
                GUIExecutionResult(
                    test_file=Path(f"/tmp/crash_{i}.dcm"),
                    status=ExecutionStatus.CRASH,
                    exit_code=-1,
                    execution_time=0.5,
                    peak_memory_mb=150.0,
                    crashed=True,
                    timed_out=False,
                )
            )

        results = {
            ExecutionStatus.SUCCESS: [],
            ExecutionStatus.CRASH: crash_results,
            ExecutionStatus.HANG: [],
            ExecutionStatus.ERROR: [],
        }

        summary = runner.get_summary(results)

        assert "CRASHES DETECTED" in summary
        assert "and 5 more" in summary  # More than 10 crashes

    def test_get_summary_empty_results(self, temp_dir):
        """Test get_summary with empty results."""
        target = temp_dir / "target.exe"
        target.touch()

        runner = GUITargetRunner(
            target_executable=str(target),
            crash_dir=str(temp_dir / "crashes"),
        )

        results = {
            ExecutionStatus.SUCCESS: [],
            ExecutionStatus.CRASH: [],
            ExecutionStatus.HANG: [],
            ExecutionStatus.ERROR: [],
        }

        summary = runner.get_summary(results)

        assert "Total tests:     0" in summary


class TestPreCampaignHealthCheckCoverage:
    """Additional coverage tests for pre_campaign_health_check."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_health_check_psutil_missing_warning(self, temp_dir):
        """Test warning when psutil is not available."""
        output_dir = temp_dir / "output"

        with patch.dict("sys.modules", {"psutil": None}):
            with patch("builtins.__import__") as mock_import:

                def import_side_effect(name, *args, **kwargs):
                    if name == "psutil":
                        raise ImportError("No module named 'psutil'")
                    return MagicMock()

                mock_import.side_effect = import_side_effect

                passed, issues = pre_campaign_health_check(
                    output_dir=output_dir, verbose=True
                )

        # Should still pass but have warning
        assert passed is True

    def test_health_check_verbose_no_warnings(self, temp_dir, capsys):
        """Test verbose output when there are no warnings."""
        output_dir = temp_dir / "output"

        passed, issues = pre_campaign_health_check(output_dir=output_dir, verbose=True)

        captured = capsys.readouterr()
        assert "Pre-flight checks passed" in captured.out

    def test_health_check_output_not_writable(self, temp_dir):
        """Test failure when output directory is not writable."""
        output_dir = temp_dir / "output"

        with patch("pathlib.Path.mkdir", side_effect=PermissionError("Not writable")):
            passed, issues = pre_campaign_health_check(output_dir=output_dir)

        assert passed is False
        assert any("not writable" in issue.lower() for issue in issues)


class TestFormatFunctions:
    """Test format helper functions."""

    def test_format_file_size_edge_cases(self):
        """Test format_file_size with edge cases."""
        assert format_file_size(0) == "0 B"
        assert format_file_size(1) == "1 B"
        assert format_file_size(1023) == "1023 B"
        assert format_file_size(1024) == "1.0 KB"
        assert format_file_size(1024 * 1024 - 1) == "1024.0 KB"

    def test_format_duration_edge_cases(self):
        """Test format_duration with edge cases."""
        assert format_duration(0) == "0s"
        assert format_duration(59.9) == "59s"
        assert format_duration(60) == "1m 0s"
        assert format_duration(3599) == "59m 59s"
        assert format_duration(3600) == "1h 0m 0s"


class TestValidateFunctions:
    """Test validation helper functions."""

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_validate_strategy_all(self):
        """Test validate_strategy with 'all' keyword."""
        assert validate_strategy("all", []) is True
        assert validate_strategy("all", ["metadata", "header"]) is True

    def test_validate_strategy_invalid(self):
        """Test validate_strategy with invalid strategy."""
        assert validate_strategy("nonexistent", ["metadata", "header"]) is False

    def test_parse_strategies_with_unknown(self, capsys):
        """Test parse_strategies warns about unknown strategies."""
        result = parse_strategies("metadata,unknown_strategy,header")

        assert "metadata" in result
        assert "header" in result
        assert "unknown_strategy" not in result

        captured = capsys.readouterr()
        assert "Unknown strategies" in captured.out

    def test_validate_input_file_directory_error(self, temp_dir, capsys):
        """Test validate_input_file exits for directory."""
        with pytest.raises(SystemExit) as exc_info:
            validate_input_file(str(temp_dir))

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "not a file" in captured.out


class TestSetupLoggingCoverage:
    """Additional coverage for setup_logging."""

    def test_setup_logging_verbose_debug(self):
        """Test setup_logging sets DEBUG level in verbose mode."""
        import logging

        # Clear handlers first
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        root_logger.setLevel(logging.NOTSET)

        setup_logging(verbose=True)

        assert root_logger.level == logging.DEBUG

    def test_setup_logging_normal_info(self):
        """Test setup_logging sets INFO level normally."""
        import logging

        # Clear handlers first
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        root_logger.setLevel(logging.NOTSET)

        setup_logging(verbose=False)

        assert root_logger.level == logging.INFO
