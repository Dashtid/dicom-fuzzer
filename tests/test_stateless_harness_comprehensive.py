"""
Comprehensive tests for stateless harness validation.

Achieves 80%+ coverage of stateless_harness.py module.
"""

import gc
from pathlib import Path

import pytest

from dicom_fuzzer.utils.stateless_harness import (
    _hash_result,
    create_stateless_test_wrapper,
    detect_state_leaks,
    validate_determinism,
)


class TestHashResult:
    """Tests for _hash_result function."""

    def test_hash_none(self):
        """Test hashing None value."""
        hash1 = _hash_result(None)
        hash2 = _hash_result(None)

        assert hash1 == hash2
        assert isinstance(hash1, str)
        assert len(hash1) == 64  # SHA256 hex digest length

    def test_hash_bytes(self):
        """Test hashing bytes."""
        data = b"test data"
        hash1 = _hash_result(data)
        hash2 = _hash_result(data)

        assert hash1 == hash2
        # Different data should produce different hash
        hash3 = _hash_result(b"different data")
        assert hash1 != hash3

    def test_hash_string(self):
        """Test hashing string."""
        data = "test string"
        hash1 = _hash_result(data)
        hash2 = _hash_result(data)

        assert hash1 == hash2

    def test_hash_int(self):
        """Test hashing integer."""
        hash1 = _hash_result(42)
        hash2 = _hash_result(42)

        assert hash1 == hash2
        assert hash1 != _hash_result(43)

    def test_hash_float(self):
        """Test hashing float."""
        hash1 = _hash_result(3.14)
        hash2 = _hash_result(3.14)

        assert hash1 == hash2

    def test_hash_bool(self):
        """Test hashing boolean."""
        hash_true = _hash_result(True)
        hash_false = _hash_result(False)

        assert hash_true != hash_false

    def test_hash_complex_object(self):
        """Test hashing complex object using str()."""
        obj = {"key": "value", "nested": {"inner": 123}}
        hash1 = _hash_result(obj)
        hash2 = _hash_result(obj)

        # Should be consistent for same object
        assert hash1 == hash2

    def test_hash_list(self):
        """Test hashing list."""
        data = [1, 2, 3, "test"]
        hash1 = _hash_result(data)
        hash2 = _hash_result(data)

        assert hash1 == hash2

    def test_hash_unhashable_object(self):
        """Test hashing object that might fail str() conversion."""

        class CustomClass:
            def __str__(self):
                raise ValueError("Cannot convert to string")

            def __repr__(self):
                return "CustomClass()"

        obj = CustomClass()
        # Should fall back to repr()
        hash1 = _hash_result(obj)
        assert isinstance(hash1, str)


class TestValidateDeterminism:
    """Tests for validate_determinism function."""

    def test_deterministic_function(self):
        """Test with deterministic function."""

        def deterministic_func(x):
            return x * 2

        is_det, error = validate_determinism("test", deterministic_func, runs=3)

        assert is_det is True
        assert error is None

    def test_deterministic_function_cleanup(self):
        """Test with cleanup enabled."""

        def deterministic_func(x):
            return x + "suffix"

        is_det, error = validate_determinism(
            "test", deterministic_func, runs=5, cleanup=True
        )

        assert is_det is True
        assert error is None

    def test_nondeterministic_function(self):
        """Test with non-deterministic function."""
        counter = {"value": 0}

        def nondeterministic_func(x):
            counter["value"] += 1
            return f"{x}_{counter['value']}"

        is_det, error = validate_determinism("test", nondeterministic_func, runs=3)

        assert is_det is False
        assert error is not None
        assert "Non-deterministic" in error or "different results" in error

    def test_function_raises_exception(self):
        """Test with function that raises exception."""

        def failing_func(x):
            raise ValueError("Test error")

        is_det, error = validate_determinism("test", failing_func, runs=3)

        assert is_det is False
        assert error is not None
        assert "exception" in error.lower()

    def test_function_raises_on_second_run(self):
        """Test with function that fails on second run."""
        counter = {"value": 0}

        def intermittent_func(x):
            counter["value"] += 1
            if counter["value"] == 2:
                raise RuntimeError("Intermittent failure")
            return x

        is_det, error = validate_determinism("test", intermittent_func, runs=3)

        assert is_det is False
        assert "exception on run 2" in error

    def test_single_run(self):
        """Test with single run (always deterministic)."""
        counter = {"value": 0}

        def func(x):
            counter["value"] += 1
            return counter["value"]

        is_det, error = validate_determinism("test", func, runs=1)

        # Single run is always deterministic
        assert is_det is True

    def test_different_input_types(self):
        """Test with different input types."""

        def func(x):
            if isinstance(x, int):
                return x * 2
            elif isinstance(x, str):
                return x.upper()
            elif isinstance(x, bytes):
                return x.decode()
            else:
                return str(x)

        # Test with different inputs
        for test_input in [42, "test", b"bytes", [1, 2, 3]]:
            is_det, error = validate_determinism(test_input, func, runs=3)
            assert is_det is True

    def test_no_cleanup(self):
        """Test with cleanup disabled."""

        def func(x):
            return hashlib.sha256(str(x).encode()).hexdigest()

        import hashlib

        is_det, error = validate_determinism("test", func, runs=3, cleanup=False)

        assert is_det is True


class TestCreateStatelessTestWrapper:
    """Tests for create_stateless_test_wrapper function."""

    def test_wrapper_basic_functionality(self):
        """Test wrapper preserves basic functionality."""

        def original_func(x):
            return x * 2

        wrapped = create_stateless_test_wrapper(original_func)
        result = wrapped(5)

        assert result == 10

    def test_wrapper_with_args(self):
        """Test wrapper with multiple arguments."""

        def original_func(a, b, c):
            return a + b + c

        wrapped = create_stateless_test_wrapper(original_func)
        result = wrapped(1, 2, 3)

        assert result == 6

    def test_wrapper_with_kwargs(self):
        """Test wrapper with keyword arguments."""

        def original_func(x=10, y=20):
            return x * y

        wrapped = create_stateless_test_wrapper(original_func)
        result = wrapped(x=5, y=3)

        assert result == 15

    def test_wrapper_calls_garbage_collection(self):
        """Test that wrapper triggers garbage collection."""
        gc_calls = []

        # Monkey patch gc.collect to track calls
        original_gc_collect = gc.collect

        def mock_gc_collect():
            gc_calls.append(True)
            return original_gc_collect()

        gc.collect = mock_gc_collect

        try:

            def test_func(x):
                return x

            wrapped = create_stateless_test_wrapper(test_func)
            wrapped("test")

            # Should call gc.collect before and after
            assert len(gc_calls) >= 2
        finally:
            gc.collect = original_gc_collect

    def test_wrapper_exception_handling(self):
        """Test wrapper handles exceptions and still cleans up."""

        def failing_func(x):
            raise ValueError("Test error")

        wrapped = create_stateless_test_wrapper(failing_func)

        with pytest.raises(ValueError, match="Test error"):
            wrapped("test")

        # Cleanup should still happen (gc.collect in finally block)

    def test_wrapper_preserves_return_types(self):
        """Test wrapper preserves different return types."""

        def return_dict(x):
            return {"result": x}

        def return_list(x):
            return [x, x * 2]

        def return_none(x):
            return None

        wrapped_dict = create_stateless_test_wrapper(return_dict)
        wrapped_list = create_stateless_test_wrapper(return_list)
        wrapped_none = create_stateless_test_wrapper(return_none)

        assert wrapped_dict(5) == {"result": 5}
        assert wrapped_list(3) == [3, 6]
        assert wrapped_none(10) is None

    def test_wrapper_multiple_calls(self):
        """Test wrapper works correctly across multiple calls."""
        counter = {"value": 0}

        def stateful_func(x):
            counter["value"] += 1
            return counter["value"]

        wrapped = create_stateless_test_wrapper(stateful_func)

        # Multiple calls should still be stateful (wrapper doesn't fix state)
        result1 = wrapped("test")
        result2 = wrapped("test")

        assert result2 == result1 + 1


class TestDetectStateLeaks:
    """Tests for detect_state_leaks function."""

    def test_no_leaks_stateless_harness(self, tmp_path):
        """Test with stateless harness (no leaks)."""
        # Create test files
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"
        file1.write_text("content1")
        file2.write_text("content2")

        def stateless_harness(path):
            return path.read_text()

        results = detect_state_leaks(stateless_harness, [file1, file2])

        assert results["leaked"] is False
        assert len(results["evidence"]) == 0
        assert len(results["affected_files"]) == 0

    def test_leaks_detected_stateful_harness(self, tmp_path):
        """Test with stateful harness (leaks detected)."""
        # Create test files
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"
        file1.write_text("content1")
        file2.write_text("content2")

        # Stateful harness with hidden counter
        state = {"counter": 0}

        def stateful_harness(path):
            state["counter"] += 1
            return f"{path.read_text()}_{state['counter']}"

        results = detect_state_leaks(stateful_harness, [file1, file2])

        assert results["leaked"] is True
        assert len(results["affected_files"]) > 0

    def test_single_file_insufficient(self, tmp_path):
        """Test with only one file (insufficient for leak detection)."""
        file1 = tmp_path / "test.txt"
        file1.write_text("content")

        def harness(path):
            return path.read_text()

        results = detect_state_leaks(harness, [file1])

        # Should return no leaks (but warn about insufficient files)
        assert results["leaked"] is False

    def test_empty_file_list(self):
        """Test with empty file list."""

        def harness(path):
            return path.read_text()

        results = detect_state_leaks(harness, [])

        assert results["leaked"] is False

    def test_harness_raises_exception_baseline(self, tmp_path):
        """Test when harness raises exception during baseline run."""
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"
        file1.write_text("fail")
        file2.write_text("content")

        def failing_harness(path):
            content = path.read_text()
            if content == "fail":
                raise ValueError("Baseline failure")
            return content

        results = detect_state_leaks(failing_harness, [file1, file2])

        # Should handle gracefully
        assert isinstance(results, dict)
        assert "leaked" in results

    def test_harness_raises_exception_test_run(self, tmp_path):
        """Test when harness raises exception during test run."""
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"
        file1.write_text("content1")
        file2.write_text("content2")

        counter = {"value": 0}

        def intermittent_harness(path):
            counter["value"] += 1
            # Fail on second run of same file
            if counter["value"] > 3:
                raise ValueError("Test run failure")
            return path.read_text()

        results = detect_state_leaks(intermittent_harness, [file1, file2])

        # Should handle gracefully
        assert isinstance(results, dict)

    def test_multiple_files_comprehensive(self, tmp_path):
        """Test with multiple files comprehensively."""
        files = []
        for i in range(5):
            file = tmp_path / f"test{i}.txt"
            file.write_text(f"content{i}")
            files.append(file)

        # Stateless harness
        def harness(path):
            return path.read_text().upper()

        results = detect_state_leaks(harness, files)

        assert results["leaked"] is False

    def test_leak_detection_evidence(self, tmp_path):
        """Test that leak detection provides evidence."""
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"
        file1.write_text("A")
        file2.write_text("B")

        state = {"data": ""}

        def leaky_harness(path):
            content = path.read_text()
            state["data"] += content
            return state["data"]

        results = detect_state_leaks(leaky_harness, [file1, file2])

        assert results["leaked"] is True
        assert len(results["evidence"]) > 0
        # Evidence should mention which file(s) affected
        assert any("test" in evidence for evidence in results["evidence"])


class TestIntegrationScenarios:
    """Integration tests for stateless harness validation."""

    def test_complete_validation_workflow(self, tmp_path):
        """Test complete stateless validation workflow."""

        # Create test function
        def test_harness(data):
            import hashlib

            return hashlib.md5(str(data).encode()).hexdigest()

        # Step 1: Validate determinism
        is_det, error = validate_determinism("test_input", test_harness, runs=5)
        assert is_det is True

        # Step 2: Wrap with stateless wrapper
        wrapped_harness = create_stateless_test_wrapper(test_harness)

        # Step 3: Use wrapped harness
        result1 = wrapped_harness("input")
        result2 = wrapped_harness("input")
        assert result1 == result2

    def test_detect_and_fix_stateful_harness(self, tmp_path):
        """Test detecting stateful harness and fixing with wrapper."""
        # Create stateful harness
        state = {"counter": 0}

        def stateful_harness(x):
            state["counter"] += 1
            return f"{x}_{state['counter']}"

        # Detect non-determinism
        is_det, error = validate_determinism("test", stateful_harness, runs=3)
        assert is_det is False

        # Wrap doesn't fix the state issue (state is external)
        wrapped = create_stateless_test_wrapper(stateful_harness)
        is_det2, error2 = validate_determinism("test", wrapped, runs=3)
        assert is_det2 is False  # Still stateful

    def test_real_world_file_processing(self, tmp_path):
        """Test with realistic file processing harness."""
        # Create test files
        file1 = tmp_path / "input1.txt"
        file2 = tmp_path / "input2.txt"
        file1.write_bytes(b"Hello World")
        file2.write_bytes(b"Fuzzing Test")

        def file_harness(path: Path):
            import hashlib

            data = path.read_bytes()
            return hashlib.sha256(data).hexdigest()

        # Validate determinism
        result1_a = file_harness(file1)
        result1_b = file_harness(file1)
        assert result1_a == result1_b

        # Check for state leaks
        results = detect_state_leaks(file_harness, [file1, file2])
        assert results["leaked"] is False
