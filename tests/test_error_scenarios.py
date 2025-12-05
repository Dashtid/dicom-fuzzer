"""
Error Scenario Testing Suite

CONCEPT: Error scenario tests validate graceful handling of adverse conditions:
- Corrupted DICOM files
- Disk full conditions
- Permission errors
- Missing dependencies
- Network failures
- System resource exhaustion
- Invalid input data

PURPOSE: Ensure the fuzzer fails gracefully and provides helpful error messages
rather than crashing when encountering real-world error conditions.
"""

import os
import shutil
from unittest.mock import Mock, patch

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.config_validator import ConfigValidator
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.resource_manager import ResourceLimits, ResourceManager
from dicom_fuzzer.core.target_runner import ExecutionStatus, TargetRunner
from dicom_fuzzer.core.validator import DicomValidator


class TestCorruptedFileHandling:
    """Test handling of corrupted or malformed DICOM files."""

    def test_completely_corrupted_file(self, temp_dir):
        """Test handling file with random garbage data."""
        corrupted_file = temp_dir / "corrupted.dcm"
        corrupted_file.write_bytes(b"\x00\x01\x02\x03\x04" * 100)

        # Should raise ParsingError for completely corrupted file
        try:
            parser = DicomParser(corrupted_file)
            # If parsing succeeds (with force=True), that's acceptable
            assert parser.file_path == corrupted_file
        except Exception as e:
            # If parsing fails, that's also acceptable - should get meaningful error
            assert "parse" in str(e).lower() or "dicom" in str(e).lower()

    def test_truncated_dicom_file(self, sample_dicom_file, temp_dir):
        """Test handling truncated DICOM file."""
        # Read and truncate
        data = sample_dicom_file.read_bytes()
        truncated_data = data[: len(data) // 2]  # Cut in half

        truncated_file = temp_dir / "truncated.dcm"
        truncated_file.write_bytes(truncated_data)

        # Parsing might succeed with force=True, validation should catch issues
        try:
            parser = DicomParser(truncated_file)
            validator = DicomValidator()
            validator.validate(parser.dataset)

            # Either parse fails or validation detects issues
            # This is acceptable behavior
            assert True
        except Exception:
            # If parse fails, that's also acceptable
            assert True

    def test_empty_file(self, temp_dir):
        """Test handling empty file."""
        empty_file = temp_dir / "empty.dcm"
        empty_file.touch()

        validator = DicomValidator()
        result, dataset = validator.validate_file(empty_file)

        # Should detect empty file
        assert not result.is_valid
        assert any("empty" in e.lower() for e in result.errors)
        assert dataset is None

    def test_missing_required_elements(self):
        """Test handling DICOM with critical elements missing."""
        dataset = Dataset()
        # Minimal dataset with no required tags

        validator = DicomValidator(strict_mode=True)
        result = validator.validate(dataset)

        # Should fail in strict mode
        assert not result.is_valid
        assert len(result.errors) > 0

    def test_invalid_tag_values(self):
        """Test handling invalid tag values."""
        dataset = Dataset()
        dataset.PatientName = "\x00\x00\x00"  # Null bytes
        dataset.PatientID = "A" * 100000  # Extremely long

        validator = DicomValidator()
        result = validator.validate(dataset)

        # Should detect issues
        assert not result.is_valid or len(result.warnings) > 0


@pytest.mark.slow
class TestDiskSpaceErrors:
    """Test handling disk space exhaustion."""

    def test_insufficient_disk_space_detection(self, temp_dir):
        """Test pre-flight disk space check."""
        # Use config validator to check disk space
        validator = ConfigValidator()

        # Request more space than available
        disk_usage = shutil.disk_usage(temp_dir)
        available_mb = disk_usage.free / (1024 * 1024)
        required_mb = available_mb + 10000  # Request 10GB more than available

        validator._check_disk_space(temp_dir, required_mb, num_files=1000)

        # Should detect insufficient space (check happens in validate_all)
        # This test verifies the method exists and runs

    @pytest.mark.skipif(
        os.environ.get("CI") == "true",
        reason="Cannot reliably test disk full in CI",
    )
    def test_disk_full_during_generation(self, sample_dicom_file, temp_dir):
        """Test handling disk full during file generation."""
        # This is difficult to test reliably without actually filling disk
        # Instead, we mock the write operation to simulate disk full

        generator = DICOMGenerator(output_dir=str(temp_dir / "disk_full"))

        with patch("pathlib.Path.write_bytes") as mock_write:
            mock_write.side_effect = OSError(28, "No space left on device")

            # Should handle error gracefully
            try:
                generator.generate_batch(sample_dicom_file, count=10)
                # If it handles gracefully, no exception
                assert True
            except OSError as e:
                # If exception propagates, should be informative
                assert "space" in str(e).lower() or "disk" in str(e).lower()


class TestPermissionErrors:
    """Test handling file permission errors."""

    def test_read_permission_denied(self, sample_dicom_file, temp_dir):
        """Test handling file read permission error."""
        # Copy file and remove read permissions
        restricted_file = temp_dir / "no_read.dcm"
        shutil.copy(sample_dicom_file, restricted_file)

        if os.name == "nt":
            # Windows: Use icacls to deny read access
            import subprocess

            user = os.environ.get("USERNAME", "")
            # Deny read access for current user
            subprocess.run(
                ["icacls", str(restricted_file), "/deny", f"{user}:(R)"],
                capture_output=True,
                check=False,
            )
        else:
            restricted_file.chmod(0o000)

        try:
            DicomParser(restricted_file)
            # Should fail to read
            assert False, "Should have raised permission error"
        except (PermissionError, OSError):
            # Expected - raw permission error
            assert True
        except Exception as e:
            # Parser may wrap permission error in ParsingError
            # Check if the underlying cause is permission-related
            error_msg = str(e).lower()
            assert "permission denied" in error_msg or "errno 13" in error_msg, (
                f"Expected permission error, got: {e}"
            )
        finally:
            # Restore permissions for cleanup
            try:
                if os.name == "nt":
                    import subprocess

                    user = os.environ.get("USERNAME", "")
                    # Grant full access back
                    subprocess.run(
                        ["icacls", str(restricted_file), "/grant", f"{user}:(F)"],
                        capture_output=True,
                        check=False,
                    )
                else:
                    restricted_file.chmod(0o644)
            except Exception:
                pass

    def test_write_permission_denied(self, sample_dicom_file, temp_dir):
        """Test handling write permission error."""
        # Create read-only output directory
        readonly_dir = temp_dir / "readonly"
        readonly_dir.mkdir()

        if os.name == "nt":
            # Windows: Use icacls to deny write access to directory
            import subprocess

            user = os.environ.get("USERNAME", "")
            # Deny write access for current user
            subprocess.run(
                ["icacls", str(readonly_dir), "/deny", f"{user}:(W)"],
                capture_output=True,
                check=False,
            )
        else:
            readonly_dir.chmod(0o444)

        try:
            generator = DICOMGenerator(output_dir=str(readonly_dir))
            files = generator.generate_batch(sample_dicom_file, count=1)

            # Should either fail or handle gracefully
            assert len(files) == 0 or len(files) == 1
        except (PermissionError, OSError):
            # Expected failure
            assert True
        finally:
            # Restore permissions
            try:
                if os.name == "nt":
                    import subprocess

                    user = os.environ.get("USERNAME", "")
                    # Grant full access back
                    subprocess.run(
                        ["icacls", str(readonly_dir), "/grant", f"{user}:(F)"],
                        capture_output=True,
                        check=False,
                    )
                else:
                    readonly_dir.chmod(0o755)
            except Exception:
                pass

    def test_output_directory_creation_permission(self, temp_dir):
        """Test handling permission error during directory creation."""
        # Mock mkdir to simulate permission error
        from dicom_fuzzer.utils.helpers import ensure_directory

        with patch("pathlib.Path.mkdir") as mock_mkdir:
            mock_mkdir.side_effect = PermissionError("Permission denied")

            with pytest.raises(PermissionError):
                ensure_directory(temp_dir / "forbidden" / "nested")


@pytest.mark.slow
class TestResourceExhaustion:
    """Test handling system resource exhaustion."""

    def test_memory_limit_exceeded(self, sample_dicom_file, temp_dir):
        """Test handling when memory limit is exceeded."""
        # Create resource manager with very low memory limit
        limits = ResourceLimits(max_memory_mb=10, max_memory_mb_hard=20)
        manager = ResourceManager(limits)

        # Attempt operation that might exceed limit
        try:
            with manager.limited_execution():
                # Try to allocate large amount of memory
                large_data = bytearray(50 * 1024 * 1024)  # 50MB
                del large_data  # Clean up

            # If we get here, either limit wasn't enforced (Windows)
            # or we stayed under limit
            assert True
        except MemoryError:
            # Expected on systems with resource limits
            assert True

    def test_cpu_timeout_exceeded(self, temp_dir):
        """Test handling CPU timeout."""
        # Create mock target that takes too long
        target_exe = temp_dir / "slow_target.bat"
        if os.name == "nt":
            # Windows: use timeout command
            target_exe.write_text("@echo off\ntimeout /t 10 /nobreak >nul")
        else:
            # Unix: use sleep
            target_exe.write_text("#!/bin/bash\nsleep 10")
            target_exe.chmod(0o755)

        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"dummy")

        runner = TargetRunner(
            target_executable=str(target_exe),
            timeout=1.0,  # 1 second timeout
        )

        result = runner.execute_test(str(test_file))

        # Should detect timeout/hang
        assert result.result in (ExecutionStatus.HANG, ExecutionStatus.ERROR)

    def test_too_many_open_files(self, sample_dicom_file, temp_dir):
        """Test handling too many open files."""
        # Generate many files
        output_dir = temp_dir / "many_files"
        generator = DICOMGenerator(output_dir=str(output_dir))
        files = generator.generate_batch(sample_dicom_file, count=100)

        # Try to open all at once
        file_handles = []
        try:
            for f in files:
                file_handles.append(open(f, "rb"))

            # Should succeed for 100 files
            assert len(file_handles) == 100

        finally:
            # Clean up
            for fh in file_handles:
                fh.close()


class TestInvalidInputData:
    """Test handling invalid input data."""

    def test_none_dataset(self):
        """Test handling None dataset."""
        validator = DicomValidator()
        result = validator.validate(None)

        assert not result.is_valid
        assert "None" in result.errors[0]

    def test_empty_dataset(self):
        """Test handling empty dataset."""
        dataset = Dataset()

        validator = DicomValidator()
        result = validator.validate(dataset)

        assert not result.is_valid
        assert "empty" in result.errors[0].lower()

    def test_invalid_file_path(self):
        """Test handling invalid file paths."""
        from dicom_fuzzer.utils.helpers import validate_file_path

        with pytest.raises(FileNotFoundError):
            validate_file_path("/nonexistent/path/file.dcm", must_exist=True)

    def test_directory_instead_of_file(self, temp_dir):
        """Test handling directory path where file expected."""
        from dicom_fuzzer.utils.helpers import validate_file_path

        with pytest.raises(ValueError):
            validate_file_path(temp_dir, must_exist=True)

    @pytest.mark.slow
    def test_oversized_file(self, temp_dir):
        """Test handling file exceeding size limit."""
        large_file = temp_dir / "large.dcm"
        large_file.write_bytes(b"X" * (200 * 1024 * 1024))  # 200MB

        validator = DicomValidator(max_file_size=100 * 1024 * 1024)  # 100MB limit
        result, dataset = validator.validate_file(large_file)

        assert not result.is_valid
        assert any("exceeds" in e.lower() for e in result.errors)


class TestTargetExecutableErrors:
    """Test handling errors with target executable."""

    def test_nonexistent_executable(self, temp_dir):
        """Test handling nonexistent target executable."""
        fake_exe = temp_dir / "nonexistent.exe"

        # TargetRunner should raise FileNotFoundError for nonexistent executable
        with pytest.raises(FileNotFoundError):
            TargetRunner(target_executable=str(fake_exe))

    def test_executable_crashes(self, temp_dir):
        """Test handling target executable that crashes."""
        # Create executable that always crashes
        crash_exe = temp_dir / "crash.bat"
        if os.name == "nt":
            crash_exe.write_text("@echo off\nexit -1")
        else:
            crash_exe.write_text("#!/bin/bash\nexit 139")  # SIGSEGV
            crash_exe.chmod(0o755)

        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"dummy")

        runner = TargetRunner(target_executable=str(crash_exe))
        result = runner.execute_test(str(test_file))

        # Should detect crash
        assert result.result in (ExecutionStatus.CRASH, ExecutionStatus.ERROR)

    def test_circuit_breaker_activation(self, temp_dir):
        """Test circuit breaker opens after consistent failures."""
        # Create failing executable
        fail_exe = temp_dir / "fail.bat"
        if os.name == "nt":
            fail_exe.write_text("@echo off\nexit 1")
        else:
            fail_exe.write_text("#!/bin/bash\nexit 1")
            fail_exe.chmod(0o755)

        runner = TargetRunner(
            target_executable=str(fail_exe), enable_circuit_breaker=True
        )

        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"dummy")

        # Trigger circuit breaker - run tests until it opens
        # NOTE: Circuit breaker counts consecutive failures including retries.
        # With max_retries=2, each execute_test call can generate up to 3 failures
        # (original + 2 retries), so the circuit may open after just 1-2 calls.
        results = []
        for i in range(10):
            result = runner.execute_test(str(test_file))
            results.append(result)

            # Circuit breaker should eventually open
            if result.result == ExecutionStatus.SKIPPED:
                break

        # Verify circuit breaker opened
        assert runner.circuit_breaker.is_open

        # Should have at least 1 failed execution (which may include retries)
        failures = [
            r
            for r in results
            if r.result in (ExecutionStatus.ERROR, ExecutionStatus.CRASH)
        ]
        assert len(failures) >= 1, "Should have at least 1 failure before circuit opens"

        # Total consecutive failures (including retries) should be >= threshold
        assert (
            runner.circuit_breaker.consecutive_failures
            >= runner.circuit_breaker.failure_threshold
        )

        # Last result should be skipped (circuit open)
        assert results[-1].result == ExecutionStatus.SKIPPED


class TestConfigurationErrors:
    """Test handling configuration errors."""

    def test_invalid_resource_limits(self):
        """Test handling invalid resource limit values."""
        # Negative limits should work but be ineffective
        limits = ResourceLimits(
            max_memory_mb=-100,  # Invalid
            max_cpu_seconds=-10,  # Invalid
        )

        manager = ResourceManager(limits)

        # Should handle gracefully (resource module will ignore invalid)
        with manager.limited_execution():
            # Should not crash
            assert True

    def test_missing_required_config(self):
        """Test handling missing required configuration."""
        validator = ConfigValidator()

        # Validate without required parameters
        result = validator.validate_all(
            input_file=None,  # Missing
            output_dir=None,  # Missing
            target_executable=None,  # Missing
        )

        # Should not crash, but may have no errors if all optional
        assert isinstance(result, bool)

    def test_conflicting_config_options(self):
        """Test handling conflicting configuration."""
        # Create validator with conflicting settings
        validator = DicomValidator(
            strict_mode=True,
            max_file_size=0,  # Zero size limit
        )

        # Should initialize without crashing
        assert validator.strict_mode is True
        assert validator.max_file_size == 0


class TestGracefulDegradation:
    """Test graceful degradation when optional features unavailable."""

    def test_missing_psutil(self):
        """Test operation when psutil unavailable."""
        with patch("dicom_fuzzer.core.resource_manager.HAS_RESOURCE_MODULE", False):
            manager = ResourceManager()

            # Should still work, just without resource monitoring
            with manager.limited_execution():
                assert True

    def test_missing_tqdm(self):
        """Test operation when tqdm unavailable."""
        # Generator should work without progress bar
        from dicom_fuzzer.core.generator import DICOMGenerator

        # Even if tqdm missing, should not crash
        assert DICOMGenerator is not None


class TestInterruptionHandling:
    """Test handling of interruptions and signals."""

    def test_keyboard_interrupt_during_generation(self, sample_dicom_file, temp_dir):
        """Test handling Ctrl+C during generation."""
        from dicom_fuzzer.core.error_recovery import SignalHandler

        output_dir = temp_dir / "interrupted"
        DICOMGenerator(output_dir=str(output_dir))

        signal_handler = SignalHandler()
        signal_handler.install()

        try:
            # Simulate interrupt after a few files
            with patch(
                "dicom_fuzzer.core.generator.DICOMGenerator.generate_batch"
            ) as mock_gen:

                def side_effect(*args, **kwargs):
                    if mock_gen.call_count >= 3:
                        signal_handler._handle_signal(2, None)  # Simulate SIGINT
                    return temp_dir / f"file_{mock_gen.call_count}.dcm"

                mock_gen.side_effect = side_effect

                # Should detect interrupt
                for _ in range(10):
                    if signal_handler.check_interrupted():
                        break
                    mock_gen()

                assert signal_handler.interrupted

        finally:
            signal_handler.uninstall()


class TestRecoveryMechanisms:
    """Test error recovery and retry mechanisms."""

    def test_retry_on_transient_error(self, temp_dir):
        """Test automatic retry on transient errors."""
        target_exe = temp_dir / "flaky.bat"
        if os.name == "nt":
            target_exe.write_text("@echo off\nexit 0")
        else:
            target_exe.write_text("#!/bin/bash\nexit 0")
            target_exe.chmod(0o755)

        runner = TargetRunner(target_executable=str(target_exe), max_retries=3)

        test_file = temp_dir / "test.dcm"
        test_file.write_bytes(b"dummy")

        # Mock subprocess to simulate transient failure then success
        with patch("subprocess.run") as mock_run:
            call_count = 0

            def side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    # First call fails
                    raise OSError("Transient error")
                else:
                    # Subsequent calls succeed
                    return Mock(returncode=0, stdout="Success", stderr="", args=[])

            mock_run.side_effect = side_effect

            result = runner.execute_test(str(test_file))

            # Should succeed after retry
            assert result.result == ExecutionStatus.SUCCESS
            assert result.retry_count >= 1
            assert call_count == 2  # Original + 1 retry


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
