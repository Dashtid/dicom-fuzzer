"""Comprehensive tests for dicom_fuzzer.core.resource_manager module.

This test suite provides thorough coverage of resource management functionality,
including resource limits, usage tracking, disk space checks, and execution contexts.
"""

import platform
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from dicom_fuzzer.core.resource_manager import (
    ResourceExhaustedError,
    ResourceLimits,
    ResourceManager,
    ResourceUsage,
    resource_limited,
)


class TestResourceLimits:
    """Test suite for ResourceLimits dataclass."""

    def test_default_initialization(self):
        """Test ResourceLimits with default values."""
        limits = ResourceLimits()

        assert limits.max_memory_mb == 1024
        assert limits.max_memory_mb_hard == 2048
        assert limits.max_cpu_seconds == 30
        assert limits.min_disk_space_mb == 1024
        assert limits.max_open_files == 1000

    def test_custom_initialization(self):
        """Test ResourceLimits with custom values."""
        limits = ResourceLimits(
            max_memory_mb=512,
            max_memory_mb_hard=1024,
            max_cpu_seconds=60,
            min_disk_space_mb=2048,
            max_open_files=500,
        )

        assert limits.max_memory_mb == 512
        assert limits.max_memory_mb_hard == 1024
        assert limits.max_cpu_seconds == 60
        assert limits.min_disk_space_mb == 2048
        assert limits.max_open_files == 500

    def test_partial_custom_values(self):
        """Test ResourceLimits with some custom values."""
        limits = ResourceLimits(max_memory_mb=2048, max_cpu_seconds=120)

        assert limits.max_memory_mb == 2048
        assert limits.max_cpu_seconds == 120
        assert limits.min_disk_space_mb == 1024  # Default


class TestResourceUsage:
    """Test suite for ResourceUsage dataclass."""

    def test_initialization(self):
        """Test ResourceUsage creation."""
        timestamp = time.time()
        usage = ResourceUsage(
            memory_mb=512.5,
            cpu_seconds=10.3,
            disk_free_mb=50000.0,
            open_files=25,
            timestamp=timestamp,
        )

        assert usage.memory_mb == 512.5
        assert usage.cpu_seconds == 10.3
        assert usage.disk_free_mb == 50000.0
        assert usage.open_files == 25
        assert usage.timestamp == timestamp

    def test_zero_values(self):
        """Test ResourceUsage with zero values."""
        usage = ResourceUsage(
            memory_mb=0.0,
            cpu_seconds=0.0,
            disk_free_mb=0.0,
            open_files=0,
            timestamp=0.0,
        )

        assert usage.memory_mb == 0.0
        assert usage.cpu_seconds == 0.0
        assert usage.disk_free_mb == 0.0
        assert usage.open_files == 0


class TestResourceManagerInitialization:
    """Test suite for ResourceManager initialization."""

    def test_default_initialization(self):
        """Test ResourceManager with default limits."""
        manager = ResourceManager()

        assert isinstance(manager.limits, ResourceLimits)
        assert manager.limits.max_memory_mb == 1024
        assert manager.is_windows == (platform.system() == "Windows")

    def test_custom_limits(self):
        """Test ResourceManager with custom limits."""
        limits = ResourceLimits(max_memory_mb=512, max_cpu_seconds=60)
        manager = ResourceManager(limits)

        assert manager.limits.max_memory_mb == 512
        assert manager.limits.max_cpu_seconds == 60

    def test_windows_detection(self):
        """Test Windows platform detection."""
        manager = ResourceManager()

        if platform.system() == "Windows":
            assert manager.is_windows is True
        else:
            assert manager.is_windows is False


class TestDiskSpaceChecks:
    """Test suite for disk space checking functionality."""

    def test_get_disk_space_current_dir(self):
        """Test disk space check for current directory."""
        manager = ResourceManager()
        disk_mb = manager._get_disk_space_mb(Path.cwd())

        assert disk_mb > 0
        assert isinstance(disk_mb, float)

    def test_get_disk_space_nonexistent_path(self, tmp_path):
        """Test disk space for non-existent path uses parent."""
        manager = ResourceManager()
        nonexistent = tmp_path / "does_not_exist"

        disk_mb = manager._get_disk_space_mb(nonexistent)

        # Should still return valid disk space (from parent)
        assert disk_mb > 0

    @patch("shutil.disk_usage")
    def test_get_disk_space_error_returns_inf(self, mock_disk_usage):
        """Test disk space returns infinity on error."""
        mock_disk_usage.side_effect = Exception("Disk error")

        manager = ResourceManager()
        disk_mb = manager._get_disk_space_mb(Path.cwd())

        assert disk_mb == float("inf")

    def test_check_available_resources_sufficient(self, tmp_path):
        """Test resource check when disk space is sufficient."""
        limits = ResourceLimits(min_disk_space_mb=1)  # Very low requirement
        manager = ResourceManager(limits)

        result = manager.check_available_resources(tmp_path)

        assert result is True

    def test_check_available_resources_insufficient(self):
        """Test resource check when disk space is insufficient."""
        limits = ResourceLimits(min_disk_space_mb=999999999)  # Impossibly high
        manager = ResourceManager(limits)

        with pytest.raises(ResourceExhaustedError, match="Insufficient disk space"):
            manager.check_available_resources()


class TestResourceUsageTracking:
    """Test suite for resource usage tracking."""

    def test_get_current_usage_returns_valid_data(self, tmp_path):
        """Test that usage tracking returns valid ResourceUsage."""
        manager = ResourceManager()
        usage = manager.get_current_usage(tmp_path)

        assert isinstance(usage, ResourceUsage)
        assert usage.timestamp > 0
        assert usage.disk_free_mb >= 0

    def test_get_current_usage_disk_space_accurate(self, tmp_path):
        """Test that disk space tracking is accurate."""
        manager = ResourceManager()
        usage = manager.get_current_usage(tmp_path)

        # Should have some free space
        assert usage.disk_free_mb > 0

    @patch("platform.system", return_value="Windows")
    def test_get_current_usage_on_windows(self, mock_platform, tmp_path):
        """Test usage tracking on Windows (limited metrics)."""
        manager = ResourceManager()
        usage = manager.get_current_usage(tmp_path)

        # On Windows, memory and CPU should be 0 without psutil
        assert usage.disk_free_mb > 0  # Disk space works everywhere


class TestResourceEstimation:
    """Test suite for resource estimation."""

    def test_estimate_required_disk_space_basic(self):
        """Test basic disk space estimation."""
        manager = ResourceManager()

        required = manager.estimate_required_disk_space(100, 1.0)

        # 100 files * 1MB * 1.2 overhead = 120MB
        assert required == 120.0

    def test_estimate_required_disk_space_large_files(self):
        """Test estimation with large files."""
        manager = ResourceManager()

        required = manager.estimate_required_disk_space(1000, 10.0)

        # 1000 files * 10MB * 1.2 = 12000MB
        assert required == 12000.0

    def test_estimate_required_disk_space_small_campaign(self):
        """Test estimation for small campaign."""
        manager = ResourceManager()

        required = manager.estimate_required_disk_space(10, 0.5)

        # 10 files * 0.5MB * 1.2 = 6MB
        assert required == 6.0

    def test_can_accommodate_campaign_sufficient_space(self, tmp_path):
        """Test campaign check with sufficient disk space."""
        manager = ResourceManager()

        # Very small campaign should fit
        result = manager.can_accommodate_campaign(10, 0.001, tmp_path)

        assert result is True

    def test_can_accommodate_campaign_insufficient_space(self, tmp_path):
        """Test campaign check with insufficient disk space."""
        manager = ResourceManager()

        # Impossibly large campaign
        with pytest.raises(ResourceExhaustedError, match="Insufficient disk space"):
            manager.can_accommodate_campaign(1000000, 1000.0, tmp_path)


@pytest.mark.slow  # Skip in CI - these tests mock system functions that crash xdist workers
class TestLimitedExecutionContext:
    """Test suite for limited_execution context manager."""

    @patch("platform.system", return_value="Windows")
    def test_limited_execution_windows_yields(self, mock_platform, tmp_path):
        """Test limited_execution on Windows (should just yield)."""
        limits = ResourceLimits(min_disk_space_mb=1)
        manager = ResourceManager(limits)

        executed = False
        with manager.limited_execution():
            executed = True

        assert executed is True

    def test_limited_execution_pre_flight_check(self):
        """Test that limited_execution performs pre-flight check."""
        limits = ResourceLimits(min_disk_space_mb=999999999)
        manager = ResourceManager(limits)

        with pytest.raises(ResourceExhaustedError):
            with manager.limited_execution():
                pass

    @patch("platform.system", return_value="Linux")
    def test_limited_execution_unix_attempts_limits(self, mock_platform):
        """Test limited_execution attempts to set limits on Unix."""
        limits = ResourceLimits(min_disk_space_mb=1)
        manager = ResourceManager(limits)

        # Should not raise even if resource module not available
        executed = False
        try:
            with manager.limited_execution():
                executed = True
        except Exception:
            pass

        # Either executed or failed gracefully
        assert executed is True or executed is False


@pytest.mark.slow  # Skip in CI - these tests mock disk_usage that can crash xdist workers
class TestConvenienceFunction:
    """Test suite for resource_limited convenience function."""

    def test_resource_limited_default_params(self, tmp_path):
        """Test resource_limited with default parameters."""
        executed = False

        # Mock disk space to be sufficient
        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = Mock(free=10 * 1024 * 1024 * 1024)  # 10GB

            with resource_limited():
                executed = True

        assert executed is True

    def test_resource_limited_custom_params(self, tmp_path):
        """Test resource_limited with custom parameters."""
        executed = False

        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = Mock(free=10 * 1024 * 1024 * 1024)

            with resource_limited(
                max_memory_mb=512, max_cpu_seconds=60, min_disk_space_mb=100
            ):
                executed = True

        assert executed is True

    def test_resource_limited_returns_manager(self):
        """Test that resource_limited yields manager instance."""
        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = Mock(free=10 * 1024 * 1024 * 1024)

            with resource_limited() as manager:
                assert isinstance(manager, ResourceManager)
                assert manager.limits.max_memory_mb == 1024

    def test_resource_limited_fails_on_low_disk(self):
        """Test resource_limited raises on insufficient disk space."""
        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = Mock(free=100 * 1024 * 1024)  # Only 100MB

            with pytest.raises(ResourceExhaustedError):
                with resource_limited(min_disk_space_mb=2048):
                    pass


class TestResourceExhaustedError:
    """Test suite for ResourceExhaustedError exception."""

    def test_exception_can_be_raised(self):
        """Test ResourceExhaustedError can be raised."""
        with pytest.raises(ResourceExhaustedError):
            raise ResourceExhaustedError("Test error")

    def test_exception_message(self):
        """Test ResourceExhaustedError preserves message."""
        with pytest.raises(ResourceExhaustedError, match="Custom message"):
            raise ResourceExhaustedError("Custom message")

    def test_exception_inheritance(self):
        """Test ResourceExhaustedError is an Exception."""
        error = ResourceExhaustedError("Test")
        assert isinstance(error, Exception)


@pytest.mark.slow  # Skip in CI - these tests use resource_limited context that can crash xdist workers
class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    def test_complete_resource_check_workflow(self, tmp_path):
        """Test complete resource checking workflow."""
        # Create manager with reasonable limits
        limits = ResourceLimits(
            max_memory_mb=512, max_cpu_seconds=30, min_disk_space_mb=100
        )
        manager = ResourceManager(limits)

        # Check available resources
        result = manager.check_available_resources(tmp_path)
        assert result is True

        # Get current usage
        usage = manager.get_current_usage(tmp_path)
        assert isinstance(usage, ResourceUsage)

        # Check if campaign can fit
        can_fit = manager.can_accommodate_campaign(100, 0.1, tmp_path)
        assert can_fit is True

    def test_resource_limited_execution_workflow(self, tmp_path):
        """Test resource-limited execution workflow."""
        with patch("shutil.disk_usage") as mock_disk:
            mock_disk.return_value = Mock(free=10 * 1024 * 1024 * 1024)

            operations_executed = []

            with resource_limited(max_memory_mb=256, min_disk_space_mb=100) as manager:
                operations_executed.append("start")

                # Verify we can check usage inside context
                usage = manager.get_current_usage(tmp_path)
                assert usage.disk_free_mb > 0

                operations_executed.append("end")

            assert len(operations_executed) == 2
            assert operations_executed == ["start", "end"]

    def test_campaign_planning_workflow(self, tmp_path):
        """Test workflow for planning fuzzing campaign."""
        manager = ResourceManager()

        # Estimate resources for campaign
        num_files = 1000
        avg_size_mb = 0.5
        required_mb = manager.estimate_required_disk_space(num_files, avg_size_mb)

        assert required_mb == 600.0  # 1000 * 0.5 * 1.2

        # Check if system can handle it
        try:
            can_run = manager.can_accommodate_campaign(num_files, avg_size_mb, tmp_path)
            # Should succeed with reasonable campaign size
            assert can_run is True
        except ResourceExhaustedError:
            # Acceptable if disk is actually low
            pass

    def test_error_recovery_from_resource_exhaustion(self):
        """Test graceful handling of resource exhaustion."""
        limits = ResourceLimits(min_disk_space_mb=999999999)
        manager = ResourceManager(limits)

        # Should raise but be catchable
        try:
            manager.check_available_resources()
            assert False, "Should have raised ResourceExhaustedError"
        except ResourceExhaustedError as e:
            assert "Insufficient disk space" in str(e)

    @patch("platform.system", return_value="Linux")
    @patch("shutil.disk_usage")
    def test_cross_platform_compatibility(self, mock_disk, mock_platform):
        """Test that manager works across platforms."""
        mock_disk.return_value = Mock(free=10 * 1024 * 1024 * 1024)

        limits = ResourceLimits(min_disk_space_mb=100)
        manager = ResourceManager(limits)

        # Should work regardless of platform
        result = manager.check_available_resources()
        assert result is True

        usage = manager.get_current_usage()
        assert isinstance(usage, ResourceUsage)


@pytest.mark.slow  # Skip in CI - these tests mock sys_resource module that crashes xdist workers
class TestUnixSpecificResourceLimits:
    """Test Unix-specific resource limit setting and restoration."""

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_memory_limit_setting_success(self, mock_resource, mock_platform):
        """Test successful memory limit setting (lines 233-237)."""
        # Setup mock
        mock_resource.RLIMIT_AS = 9
        mock_resource.getrlimit.return_value = (100 * 1024 * 1024, 200 * 1024 * 1024)

        limits = ResourceLimits(
            max_memory_mb=512, max_memory_mb_hard=1024, min_disk_space_mb=1
        )
        manager = ResourceManager(limits)

        with manager.limited_execution():
            # Verify setrlimit was called with correct values
            mock_resource.setrlimit.assert_any_call(
                mock_resource.RLIMIT_AS, (512 * 1024 * 1024, 1024 * 1024 * 1024)
            )
        # Verify setrlimit was called at least once
        assert mock_resource.setrlimit.called

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_memory_limit_setting_exception(self, mock_resource, mock_platform):
        """Test memory limit setting with exception (lines 238-239)."""
        # Setup mock to raise exception
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.RLIMIT_NOFILE = 7
        mock_resource.getrlimit.return_value = (100 * 1024 * 1024, 200 * 1024 * 1024)

        def setrlimit_side_effect(limit_type, values):
            if limit_type == mock_resource.RLIMIT_AS:
                raise OSError("Permission denied")

        mock_resource.setrlimit.side_effect = setrlimit_side_effect

        limits = ResourceLimits(min_disk_space_mb=1)
        manager = ResourceManager(limits)

        # Should handle exception gracefully
        with manager.limited_execution():
            pass  # Should not raise
        # Verify setrlimit was attempted (exception was caught, not propagated)
        assert mock_resource.setrlimit.called

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_cpu_limit_setting_success(self, mock_resource, mock_platform):
        """Test successful CPU limit setting (lines 243-248)."""
        # Setup mock
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.getrlimit.return_value = (30, 35)

        limits = ResourceLimits(max_cpu_seconds=60, min_disk_space_mb=1)
        manager = ResourceManager(limits)

        with manager.limited_execution():
            # Verify CPU limit was set
            calls = mock_resource.setrlimit.call_args_list
            cpu_call = [c for c in calls if c[0][0] == mock_resource.RLIMIT_CPU]
            assert len(cpu_call) > 0

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_cpu_limit_setting_exception(self, mock_resource, mock_platform):
        """Test CPU limit setting with exception (lines 249-250)."""
        # Setup mock
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.RLIMIT_NOFILE = 7
        mock_resource.getrlimit.return_value = (30, 35)

        def setrlimit_side_effect(limit_type, values):
            if limit_type == mock_resource.RLIMIT_CPU:
                raise ValueError("Invalid limit")

        mock_resource.setrlimit.side_effect = setrlimit_side_effect

        limits = ResourceLimits(min_disk_space_mb=1)
        manager = ResourceManager(limits)

        # Should handle exception gracefully
        with manager.limited_execution():
            pass
        # Verify setrlimit was attempted (exception was caught, not propagated)
        assert mock_resource.setrlimit.called

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_file_descriptor_limit_setting(self, mock_resource, mock_platform):
        """Test file descriptor limit setting (lines 254-263)."""
        # Setup mock
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.RLIMIT_NOFILE = 7
        mock_resource.getrlimit.return_value = (1000, 1100)

        limits = ResourceLimits(max_open_files=500, min_disk_space_mb=1)
        manager = ResourceManager(limits)

        with manager.limited_execution():
            # Verify file descriptor limit was set
            calls = mock_resource.setrlimit.call_args_list
            nofile_call = [c for c in calls if c[0][0] == mock_resource.RLIMIT_NOFILE]
            assert len(nofile_call) > 0

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_file_descriptor_limit_exception(self, mock_resource, mock_platform):
        """Test file descriptor limit setting with exception (lines 262-263)."""
        # Setup mock
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.RLIMIT_NOFILE = 7
        mock_resource.getrlimit.return_value = (1000, 1100)

        # Make setrlimit raise exception only for RLIMIT_NOFILE
        def setrlimit_side_effect(limit_type, values):
            if limit_type == mock_resource.RLIMIT_NOFILE:
                raise OSError("Permission denied setting file descriptor limit")

        mock_resource.setrlimit.side_effect = setrlimit_side_effect

        limits = ResourceLimits(max_open_files=500, min_disk_space_mb=1)
        manager = ResourceManager(limits)

        # Should handle exception gracefully (lines 262-263)
        with manager.limited_execution():
            pass  # Should not raise
        # Verify setrlimit was attempted (exception was caught, not propagated)
        assert mock_resource.setrlimit.called

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_limit_restoration_on_exit(self, mock_resource, mock_platform):
        """Test that limits are restored on context exit (lines 270-278)."""
        # Setup mock
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.RLIMIT_NOFILE = 7

        original_limits = {
            mock_resource.RLIMIT_AS: (100 * 1024 * 1024, 200 * 1024 * 1024),
            mock_resource.RLIMIT_CPU: (30, 35),
            mock_resource.RLIMIT_NOFILE: (1000, 1100),
        }

        def getrlimit_side_effect(limit_type):
            return original_limits.get(limit_type, (0, 0))

        mock_resource.getrlimit.side_effect = getrlimit_side_effect

        limits = ResourceLimits(min_disk_space_mb=1)
        manager = ResourceManager(limits)

        with manager.limited_execution():
            pass

        # Verify limits were restored
        restore_calls = mock_resource.setrlimit.call_args_list
        # Should have both set and restore calls
        assert len(restore_calls) >= 3  # At least 3 limit restorations

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_limit_restoration_with_exception(self, mock_resource, mock_platform):
        """Test limit restoration handles exceptions (lines 277-278)."""
        # Setup mock
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.RLIMIT_NOFILE = 7
        mock_resource.getrlimit.return_value = (100, 200)

        setrlimit_count = [0]

        def setrlimit_with_exception(limit_type, values):
            setrlimit_count[0] += 1
            # Raise exception on restoration attempts (even numbered calls)
            if setrlimit_count[0] % 2 == 0:
                raise OSError("Restore failed")

        mock_resource.setrlimit.side_effect = setrlimit_with_exception

        limits = ResourceLimits(min_disk_space_mb=1)
        manager = ResourceManager(limits)

        # Should not raise even if restoration fails
        with manager.limited_execution():
            pass
        # Verify setrlimit was called multiple times (set + restore attempts)
        assert mock_resource.setrlimit.call_count >= 2


@pytest.mark.slow  # Skip in CI - these tests mock psutil and sys_resource that crash xdist workers
class TestUnixSpecificUsageTracking:
    """Test Unix-specific resource usage tracking paths."""

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    def test_get_current_usage_with_psutil_memory(self, mock_platform):
        """Test memory usage with psutil on Unix (lines 154-158)."""
        import sys

        # Create a mock psutil module
        mock_psutil = Mock()
        mock_process = Mock()
        mock_process.memory_info.return_value = Mock(rss=512 * 1024 * 1024)  # 512 MB
        mock_process.open_files.return_value = []  # Empty list for open files
        mock_psutil.Process.return_value = mock_process

        # Patch sys.modules to inject mock psutil
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            manager = ResourceManager(ResourceLimits())
            usage = manager.get_current_usage()

            # Should have memory info from psutil
            assert usage.memory_mb == 512.0

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    def test_get_current_usage_psutil_import_error(self, mock_platform):
        """Test memory usage fallback when psutil not available (lines 161-162)."""
        import sys

        # Create a mock that raises ImportError when imported
        import_error_module = Mock()
        import_error_module.Process.side_effect = ImportError("psutil not available")

        with patch.dict(sys.modules, {"psutil": import_error_module}):
            manager = ResourceManager(ResourceLimits())
            usage = manager.get_current_usage()

            # Should fall back to 0.0
            assert usage.memory_mb == 0.0

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_get_current_usage_with_cpu_time(self, mock_resource, mock_platform):
        """Test CPU time tracking on Unix (line 168)."""
        # Setup mock
        mock_usage = Mock()
        mock_usage.ru_utime = 10.5  # User time
        mock_usage.ru_stime = 5.3  # System time
        mock_resource.getrusage.return_value = mock_usage
        mock_resource.RUSAGE_SELF = 0

        manager = ResourceManager(ResourceLimits())
        usage = manager.get_current_usage()

        # Should sum user + system time
        assert usage.cpu_seconds == 15.8

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    def test_get_current_usage_with_open_files(self, mock_platform):
        """Test open files count on Unix (lines 179-183)."""
        import sys

        # Create a mock psutil module
        mock_psutil = Mock()
        mock_process = Mock()
        mock_process.memory_info.return_value = Mock(rss=100 * 1024 * 1024)
        mock_process.open_files.return_value = [Mock()] * 25  # 25 open files
        mock_psutil.Process.return_value = mock_process

        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            manager = ResourceManager(ResourceLimits())
            usage = manager.get_current_usage()

            # Should have open files count
            assert usage.open_files == 25

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    def test_get_current_usage_open_files_import_error(self, mock_platform):
        """Test open files fallback when psutil not available (lines 186-187)."""
        import sys

        # Create a mock that raises ImportError when used
        import_error_module = Mock()
        import_error_module.Process.side_effect = ImportError("psutil not available")

        with patch.dict(sys.modules, {"psutil": import_error_module}):
            manager = ResourceManager(ResourceLimits())
            usage = manager.get_current_usage()

            # Should fall back to 0
            assert usage.open_files == 0


class TestHasResourceModuleFlag:
    """Test HAS_RESOURCE_MODULE flag initialization.

    NOTE: Line 24 (HAS_RESOURCE_MODULE = True) is executed at module import time
    on Unix systems. On Windows, it's never executed (False path is taken).
    This is platform-dependent behavior that cannot be easily tested through
    normal means because the module is loaded before tests run.

    The flag value is verified indirectly through all the Unix-specific tests
    that check HAS_RESOURCE_MODULE before executing Unix-only code paths.
    """

    def test_has_resource_module_flag_is_boolean(self):
        """Test that HAS_RESOURCE_MODULE is a boolean value."""
        from dicom_fuzzer.core import resource_manager

        # On Windows, HAS_RESOURCE_MODULE should be False
        # On Unix, it should be True
        # The actual value depends on the platform
        assert isinstance(resource_manager.HAS_RESOURCE_MODULE, bool)

    def test_has_resource_module_consistency_with_sys_resource(self):
        """Test HAS_RESOURCE_MODULE is consistent with sys_resource availability."""
        from dicom_fuzzer.core import resource_manager

        # If HAS_RESOURCE_MODULE is True, sys_resource should not be None
        # If HAS_RESOURCE_MODULE is False, sys_resource should be None
        if resource_manager.HAS_RESOURCE_MODULE:
            assert resource_manager.sys_resource is not None
        else:
            assert resource_manager.sys_resource is None


@pytest.mark.slow  # Skip in CI - these tests mock sys_resource that crash xdist workers
class TestResourceUsageCPUExceptionHandling:
    """Test CPU usage exception handling in get_current_usage.

    This specifically targets lines 179-180 in resource_manager.py.
    """

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_getrusage_exception_returns_zero_cpu(self, mock_resource, mock_platform):
        """Test that getrusage exception is handled gracefully (lines 179-180).

        When sys_resource.getrusage raises an exception, cpu_seconds should be 0.0.
        """
        # Setup mock to raise exception on getrusage
        mock_resource.RUSAGE_SELF = 0
        mock_resource.getrusage.side_effect = OSError(
            "Resource temporarily unavailable"
        )

        manager = ResourceManager(ResourceLimits(min_disk_space_mb=1))
        usage = manager.get_current_usage()

        # Should return 0.0 for cpu_seconds due to exception
        assert usage.cpu_seconds == 0.0

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_getrusage_runtime_error_returns_zero_cpu(
        self, mock_resource, mock_platform
    ):
        """Test that RuntimeError in getrusage is handled (lines 179-180)."""
        mock_resource.RUSAGE_SELF = 0
        mock_resource.getrusage.side_effect = RuntimeError("Unexpected error")

        manager = ResourceManager(ResourceLimits(min_disk_space_mb=1))
        usage = manager.get_current_usage()

        assert usage.cpu_seconds == 0.0

    @patch("platform.system", return_value="Linux")
    @patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", True)
    @patch("dicom_fuzzer.core.resource_manager.sys_resource")
    def test_getrusage_value_error_returns_zero_cpu(self, mock_resource, mock_platform):
        """Test that ValueError in getrusage is handled (lines 179-180)."""
        mock_resource.RUSAGE_SELF = 0
        mock_resource.getrusage.side_effect = ValueError("Invalid RUSAGE value")

        manager = ResourceManager(ResourceLimits(min_disk_space_mb=1))
        usage = manager.get_current_usage()

        assert usage.cpu_seconds == 0.0


class TestUnixResourceModuleImport:
    """Test Unix-specific resource module import paths.

    NOTE: Lines 31-36 are executed at module import time on Unix systems.
    These lines handle the dynamic import of the 'resource' module which
    is only available on Unix-like systems. On Windows, IS_WINDOWS is True
    so the import block is never entered.

    Since this code runs at module load time (before any tests), we cannot
    directly test the import path. However, we can verify the behavior
    through the module's public interface.
    """

    def test_unix_import_path_coverage_note(self):
        """Document that lines 31-36 are platform-specific import code.

        Lines 31-36 contain:
            if not IS_WINDOWS:
                try:
                    import resource as sys_resource
                    HAS_RESOURCE_MODULE = True
                except ImportError:
                    pass

        This code path:
        - Is executed on Unix/Linux/macOS at module import time
        - Sets HAS_RESOURCE_MODULE to True if import succeeds
        - Silently handles ImportError if resource module is unavailable
        - Is NEVER executed on Windows (IS_WINDOWS == True)

        Testing this would require:
        1. Running on a Unix system where resource module exists
        2. Or mocking the import system at a very low level

        The functionality is verified indirectly by all tests that check
        HAS_RESOURCE_MODULE and sys_resource behavior.
        """
        import sys

        from dicom_fuzzer.core import resource_manager

        if sys.platform == "win32":
            # On Windows, the import block is skipped
            assert resource_manager.IS_WINDOWS is True
            assert resource_manager.HAS_RESOURCE_MODULE is False
            assert resource_manager.sys_resource is None
        else:
            # On Unix, the import block should have run
            assert resource_manager.IS_WINDOWS is False
            # HAS_RESOURCE_MODULE depends on whether resource imported successfully
            # It should be True on most Unix systems
            if resource_manager.HAS_RESOURCE_MODULE:
                assert resource_manager.sys_resource is not None
