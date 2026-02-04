"""
Tests for stateless_harness.py - Stateless Harness Validation Utilities.

Tests cover determinism validation, state leak detection, and stateless wrappers.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from dicom_fuzzer.core.harness.stateless_harness import (
    _hash_result,
    create_stateless_test_wrapper,
    detect_state_leaks,
    validate_determinism,
)


class TestValidateDeterminism:
    """Test validate_determinism function."""

    def test_deterministic_function(self):
        """Test validation passes for deterministic function."""

        def deterministic_fn(x):
            return x * 2

        is_deterministic, error = validate_determinism(
            test_input=5,
            test_function=deterministic_fn,
            runs=3,
        )

        assert is_deterministic is True
        assert error is None

    def test_non_deterministic_function(self):
        """Test validation fails for non-deterministic function."""
        counter = [0]  # Use list to allow mutation in closure

        def non_deterministic_fn(x):
            counter[0] += 1
            return x * counter[0]  # Different result each time

        is_deterministic, error = validate_determinism(
            test_input=5,
            test_function=non_deterministic_fn,
            runs=3,
        )

        assert is_deterministic is False
        assert error is not None
        assert "Non-deterministic" in error

    def test_exception_in_function(self):
        """Test validation handles exceptions gracefully."""

        def failing_fn(x):
            raise ValueError("Test error")

        is_deterministic, error = validate_determinism(
            test_input=5,
            test_function=failing_fn,
            runs=3,
        )

        assert is_deterministic is False
        assert error is not None
        assert "exception" in error.lower()
        assert "run 1" in error

    def test_determinism_with_cleanup(self):
        """Test determinism validation triggers garbage collection."""
        gc_called = [0]

        def counting_fn(x):
            return x

        with patch("gc.collect") as mock_gc:
            validate_determinism(
                test_input=10,
                test_function=counting_fn,
                runs=3,
                cleanup=True,
            )

            # Should be called after each run
            assert mock_gc.call_count >= 2

    def test_determinism_without_cleanup(self):
        """Test determinism validation without garbage collection."""

        def simple_fn(x):
            return x

        with patch("gc.collect") as mock_gc:
            validate_determinism(
                test_input=10,
                test_function=simple_fn,
                runs=3,
                cleanup=False,
            )

            # Should not be called when cleanup=False
            assert mock_gc.call_count == 0

    def test_determinism_custom_runs(self):
        """Test determinism with custom number of runs."""
        call_count = [0]

        def counting_fn(x):
            call_count[0] += 1
            return x

        validate_determinism(
            test_input=5,
            test_function=counting_fn,
            runs=5,
            cleanup=False,
        )

        assert call_count[0] == 5


class TestHashResult:
    """Test _hash_result function."""

    def test_hash_string(self):
        """Test hashing string results."""
        hash1 = _hash_result("test string")
        hash2 = _hash_result("test string")
        hash3 = _hash_result("different string")

        assert hash1 == hash2
        assert hash1 != hash3

    def test_hash_dict(self):
        """Test hashing dictionary results."""
        hash1 = _hash_result({"a": 1, "b": 2})
        hash2 = _hash_result({"a": 1, "b": 2})

        assert hash1 == hash2

    def test_hash_list(self):
        """Test hashing list results."""
        hash1 = _hash_result([1, 2, 3])
        hash2 = _hash_result([1, 2, 3])
        hash3 = _hash_result([1, 2, 4])

        assert hash1 == hash2
        assert hash1 != hash3

    def test_hash_none(self):
        """Test hashing None result."""
        hash1 = _hash_result(None)
        hash2 = _hash_result(None)

        assert hash1 == hash2

    def test_hash_complex_object(self):
        """Test hashing complex nested objects."""
        obj = {"list": [1, 2, 3], "nested": {"a": "b"}}
        hash1 = _hash_result(obj)
        hash2 = _hash_result(obj)

        assert hash1 == hash2


class TestCreateStatelessTestWrapper:
    """Test create_stateless_test_wrapper function."""

    def test_wrapper_executes_function(self):
        """Test wrapper correctly executes the wrapped function."""

        def add_one(x):
            return x + 1

        wrapped = create_stateless_test_wrapper(add_one)
        result = wrapped(5)

        assert result == 6

    def test_wrapper_preserves_args(self):
        """Test wrapper preserves positional and keyword arguments."""

        def func_with_args(a, b, c=10):
            return a + b + c

        wrapped = create_stateless_test_wrapper(func_with_args)
        result = wrapped(1, 2, c=3)

        assert result == 6

    def test_wrapper_calls_gc_before_and_after(self):
        """Test wrapper calls garbage collection before and after execution."""

        def simple_fn():
            return "done"

        wrapped = create_stateless_test_wrapper(simple_fn)

        with patch("gc.collect") as mock_gc:
            wrapped()

            # Should be called twice: before and after
            assert mock_gc.call_count == 2

    def test_wrapper_gc_called_on_exception(self):
        """Test wrapper calls GC cleanup even when function raises exception."""

        def failing_fn():
            raise RuntimeError("Test error")

        wrapped = create_stateless_test_wrapper(failing_fn)

        with patch("gc.collect") as mock_gc:
            with pytest.raises(RuntimeError):
                wrapped()

            # Should still call GC after exception (in finally block)
            assert mock_gc.call_count == 2

    def test_wrapper_returns_correct_type(self):
        """Test wrapper returns callable."""

        def original():
            pass

        wrapped = create_stateless_test_wrapper(original)

        assert callable(wrapped)


class TestDetectStateLeaks:
    """Test detect_state_leaks function."""

    def test_no_leaks_detected(self, tmp_path):
        """Test detection when no state leaks exist."""
        # Create test files
        file1 = tmp_path / "test1.dcm"
        file2 = tmp_path / "test2.dcm"
        file1.write_bytes(b"content1")
        file2.write_bytes(b"content2")

        # Stateless function - same input always produces same output
        def stateless_harness(file_path: Path):
            return file_path.read_bytes()

        results = detect_state_leaks(stateless_harness, [file1, file2])

        assert results["leaked"] is False
        assert len(results["evidence"]) == 0
        assert len(results["affected_files"]) == 0

    def test_leak_detected(self, tmp_path):
        """Test detection when state leak exists."""
        file1 = tmp_path / "test1.dcm"
        file2 = tmp_path / "test2.dcm"
        file1.write_bytes(b"content1")
        file2.write_bytes(b"content2")

        # Stateful function - accumulates state between calls
        state = {"counter": 0}

        def stateful_harness(file_path: Path):
            state["counter"] += 1
            return f"{file_path.name}_{state['counter']}"

        results = detect_state_leaks(stateful_harness, [file1, file2])

        assert results["leaked"] is True
        assert len(results["affected_files"]) > 0

    def test_insufficient_files(self, tmp_path):
        """Test detection with insufficient test files."""
        file1 = tmp_path / "only.dcm"
        file1.write_bytes(b"content")

        def harness(file_path: Path):
            return "result"

        results = detect_state_leaks(harness, [file1])

        # Should return without error but no leak detection possible
        assert results["leaked"] is False

    def test_empty_file_list(self):
        """Test detection with empty file list."""

        def harness(file_path: Path):
            return "result"

        results = detect_state_leaks(harness, [])

        assert results["leaked"] is False

    def test_baseline_exception_handled(self, tmp_path):
        """Test handling of exceptions during baseline run."""
        file1 = tmp_path / "test1.dcm"
        file2 = tmp_path / "test2.dcm"
        file1.write_bytes(b"content1")
        file2.write_bytes(b"content2")

        call_count = [0]

        def failing_harness(file_path: Path):
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("Baseline failure")
            return "ok"

        results = detect_state_leaks(failing_harness, [file1, file2])

        # Should handle exception gracefully
        assert isinstance(results, dict)
        assert "leaked" in results

    def test_test_run_exception_handled(self, tmp_path):
        """Test handling of exceptions during test run (after setup)."""
        file1 = tmp_path / "test1.dcm"
        file2 = tmp_path / "test2.dcm"
        file1.write_bytes(b"content1")
        file2.write_bytes(b"content2")

        # Fail on specific conditions
        def conditional_harness(file_path: Path):
            if "test2" in file_path.name:
                raise RuntimeError("Test run failure")
            return "ok"

        results = detect_state_leaks(conditional_harness, [file1, file2])

        # Should handle exception gracefully
        assert isinstance(results, dict)


class TestIntegration:
    """Integration tests for stateless harness utilities."""

    def test_full_validation_workflow(self, tmp_path):
        """Test complete validation workflow."""

        # Create deterministic harness
        def harness(file_path: Path):
            return hash(file_path.read_bytes())

        # Create test files
        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"test content")

        # Validate determinism
        is_deterministic, error = validate_determinism(
            test_input=test_file,
            test_function=harness,
            runs=3,
        )

        assert is_deterministic is True
        assert error is None

    def test_wrapped_harness_with_leak_detection(self, tmp_path):
        """Test stateless wrapper combined with leak detection."""
        file1 = tmp_path / "test1.dcm"
        file2 = tmp_path / "test2.dcm"
        file1.write_bytes(b"content1")
        file2.write_bytes(b"content2")

        # Create wrapped stateless harness
        def original_harness(file_path: Path):
            return file_path.stat().st_size

        wrapped = create_stateless_test_wrapper(original_harness)

        # Run leak detection on wrapped harness
        results = detect_state_leaks(wrapped, [file1, file2])

        assert results["leaked"] is False

    def test_determinism_with_file_input(self, tmp_path):
        """Test determinism validation using file path as input."""
        test_file = tmp_path / "input.dcm"
        test_file.write_bytes(b"consistent content")

        def file_processor(file_path: Path):
            return len(file_path.read_bytes())

        is_deterministic, error = validate_determinism(
            test_input=test_file,
            test_function=file_processor,
            runs=5,
        )

        assert is_deterministic is True


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_validate_determinism_single_run(self):
        """Test determinism with single run (always passes)."""

        def any_fn(x):
            return x

        is_deterministic, error = validate_determinism(
            test_input=5,
            test_function=any_fn,
            runs=1,
        )

        # Single run cannot detect non-determinism
        assert is_deterministic is True

    def test_hash_result_with_bytes(self):
        """Test hashing bytes result."""
        hash1 = _hash_result(b"binary data")
        hash2 = _hash_result(b"binary data")

        assert hash1 == hash2

    def test_wrapper_with_no_return_value(self):
        """Test wrapper with function that returns None."""

        def void_fn():
            pass  # Returns None implicitly

        wrapped = create_stateless_test_wrapper(void_fn)
        result = wrapped()

        assert result is None

    def test_leak_detection_with_three_files(self, tmp_path):
        """Test leak detection with multiple files."""
        files = []
        for i in range(3):
            f = tmp_path / f"test{i}.dcm"
            f.write_bytes(f"content{i}".encode())
            files.append(f)

        def stateless_harness(file_path: Path):
            return file_path.name

        results = detect_state_leaks(stateless_harness, files)

        assert results["leaked"] is False
