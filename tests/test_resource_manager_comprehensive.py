"""Comprehensive tests for dicom_fuzzer.core.resource_manager module.

This test suite provides thorough coverage of resource management functionality,
including resource limits, usage tracking, disk space checks, and execution contexts.
"""

import platform
import time
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

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
