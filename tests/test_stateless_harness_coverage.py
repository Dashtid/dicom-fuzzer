"""Stateless Harness Coverage Tests

Tests for dicom_fuzzer.utils.stateless_harness module to improve coverage from 12% to 80%+.
This module tests determinism validation and state leak detection.
"""

import gc
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from dicom_fuzzer.utils.stateless_harness import (
    _hash_result,
    create_stateless_test_wrapper,
    detect_state_leaks,
    validate_determinism,
)


class TestHashResult:
    """Tests for _hash_result helper function."""

    def test_hash_result_string(self) -> None:
        """Test hashing a string result."""
        result = _hash_result("test string")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_result_integer(self) -> None:
        """Test hashing an integer result."""
        result = _hash_result(42)
        assert isinstance(result, str)

    def test_hash_result_dict(self) -> None:
        """Test hashing a dictionary result."""
        result = _hash_result({"key": "value", "num": 123})
        assert isinstance(result, str)

    def test_hash_result_list(self) -> None:
        """Test hashing a list result."""
        result = _hash_result([1, 2, 3, "test"])
        assert isinstance(result, str)

    def test_hash_result_bytes(self) -> None:
        """Test hashing bytes result."""
        result = _hash_result(b"binary data")
        assert isinstance(result, str)

    def test_hash_result_none(self) -> None:
        """Test hashing None result."""
        result = _hash_result(None)
        assert isinstance(result, str)

    def test_hash_result_consistent(self) -> None:
        """Test that same input produces same hash."""
        input_data = {"test": [1, 2, 3], "value": "abc"}
        hash1 = _hash_result(input_data)
        hash2 = _hash_result(input_data)
        assert hash1 == hash2

    def test_hash_result_different_for_different_inputs(self) -> None:
        """Test that different inputs produce different hashes."""
        hash1 = _hash_result("input1")
        hash2 = _hash_result("input2")
        assert hash1 != hash2


class TestValidateDeterminism:
    """Tests for validate_determinism function."""

    def test_validate_determinism_deterministic_function(self) -> None:
        """Test validation with a deterministic function."""

        def deterministic_func(x: Any) -> int:
            return x * 2

        is_deterministic, error = validate_determinism(
            test_input=5, test_function=deterministic_func, runs=3
        )

        assert is_deterministic is True
        assert error is None

    def test_validate_determinism_non_deterministic_function(self) -> None:
        """Test validation with a non-deterministic function."""
        counter = [0]  # Use list to allow modification in closure

        def non_deterministic_func(x: Any) -> int:
            counter[0] += 1
            return counter[0]

        is_deterministic, error = validate_determinism(
            test_input=5, test_function=non_deterministic_func, runs=3
        )

        assert is_deterministic is False
        assert error is not None
        assert "Non-deterministic behavior detected" in error

    def test_validate_determinism_with_exception(self) -> None:
        """Test validation when function raises exception."""

        def failing_func(x: Any) -> None:
            raise ValueError("Test error")

        is_deterministic, error = validate_determinism(
            test_input=5, test_function=failing_func, runs=3
        )

        assert is_deterministic is False
        assert error is not None
        assert "exception" in error.lower()

    def test_validate_determinism_custom_runs(self) -> None:
        """Test validation with custom number of runs."""
        call_count = [0]

        def counting_func(x: Any) -> int:
            call_count[0] += 1
            return x

        is_deterministic, _ = validate_determinism(
            test_input=10, test_function=counting_func, runs=5
        )

        assert is_deterministic is True
        assert call_count[0] == 5

    def test_validate_determinism_with_cleanup(self) -> None:
        """Test validation with cleanup enabled."""
        gc_collected = [False]
        original_gc_collect = gc.collect

        def mock_gc_collect(*args: Any, **kwargs: Any) -> int:
            gc_collected[0] = True
            return original_gc_collect(*args, **kwargs)

        def simple_func(x: Any) -> int:
            return x

        with patch("gc.collect", mock_gc_collect):
            is_deterministic, _ = validate_determinism(
                test_input=5, test_function=simple_func, runs=2, cleanup=True
            )

        assert is_deterministic is True
        assert gc_collected[0] is True

    def test_validate_determinism_without_cleanup(self) -> None:
        """Test validation with cleanup disabled."""
        gc_collected = [False]
        original_gc_collect = gc.collect

        def mock_gc_collect(*args: Any, **kwargs: Any) -> int:
            gc_collected[0] = True
            return original_gc_collect(*args, **kwargs)

        def simple_func(x: Any) -> int:
            return x

        with patch("gc.collect", mock_gc_collect):
            is_deterministic, _ = validate_determinism(
                test_input=5, test_function=simple_func, runs=2, cleanup=False
            )

        assert is_deterministic is True
        # gc.collect should not be called when cleanup=False
        assert gc_collected[0] is False

    def test_validate_determinism_complex_return_types(self) -> None:
        """Test validation with complex return types."""

        def complex_func(x: Any) -> dict:
            return {"input": x, "list": [1, 2, 3], "nested": {"a": "b"}}

        is_deterministic, error = validate_determinism(
            test_input="test", test_function=complex_func, runs=3
        )

        assert is_deterministic is True
        assert error is None

    def test_validate_determinism_single_run(self) -> None:
        """Test validation with single run."""

        def func(x: Any) -> int:
            return x

        is_deterministic, error = validate_determinism(
            test_input=1, test_function=func, runs=1
        )

        assert is_deterministic is True
        assert error is None


class TestCreateStatelessTestWrapper:
    """Tests for create_stateless_test_wrapper function."""

    def test_wrapper_calls_original_function(self) -> None:
        """Test that wrapper calls the original function."""
        called = [False]

        def original_func(x: int, y: int) -> int:
            called[0] = True
            return x + y

        wrapped = create_stateless_test_wrapper(original_func)
        result = wrapped(2, 3)

        assert called[0] is True
        assert result == 5

    def test_wrapper_returns_correct_result(self) -> None:
        """Test that wrapper returns the correct result."""

        def func(x: str) -> str:
            return x.upper()

        wrapped = create_stateless_test_wrapper(func)
        result = wrapped("hello")

        assert result == "HELLO"

    def test_wrapper_handles_exceptions(self) -> None:
        """Test that wrapper propagates exceptions."""

        def failing_func() -> None:
            raise RuntimeError("Test error")

        wrapped = create_stateless_test_wrapper(failing_func)

        with pytest.raises(RuntimeError, match="Test error"):
            wrapped()

    def test_wrapper_accepts_kwargs(self) -> None:
        """Test that wrapper handles keyword arguments."""

        def func(a: int, b: int = 10) -> int:
            return a + b

        wrapped = create_stateless_test_wrapper(func)
        result = wrapped(5, b=20)

        assert result == 25

    def test_wrapper_calls_gc_collect(self) -> None:
        """Test that wrapper calls gc.collect before and after."""
        gc_calls = [0]
        original_gc_collect = gc.collect

        def mock_gc_collect(*args: Any, **kwargs: Any) -> int:
            gc_calls[0] += 1
            return original_gc_collect(*args, **kwargs)

        def simple_func() -> str:
            return "result"

        with patch("gc.collect", mock_gc_collect):
            wrapped = create_stateless_test_wrapper(simple_func)
            wrapped()

        # Should call gc.collect before and after (in finally block)
        assert gc_calls[0] >= 2


class TestDetectStateLeaks:
    """Tests for detect_state_leaks function."""

    def test_detect_state_leaks_no_leaks(self, tmp_path: Path) -> None:
        """Test detection with stateless harness (no leaks)."""
        # Create test files
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"
        file3 = tmp_path / "test3.txt"

        file1.write_text("content1")
        file2.write_text("content2")
        file3.write_text("content3")

        def stateless_harness(path: Path) -> str:
            return path.read_text()

        result = detect_state_leaks(
            harness_function=stateless_harness, test_files=[file1, file2, file3]
        )

        assert result["leaked"] is False
        assert len(result["evidence"]) == 0
        assert len(result["affected_files"]) == 0

    def test_detect_state_leaks_with_leaks(self, tmp_path: Path) -> None:
        """Test detection with stateful harness (leaks detected)."""
        # Create test files
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"
        file3 = tmp_path / "test3.txt"

        file1.write_text("content1")
        file2.write_text("content2")
        file3.write_text("content3")

        # Stateful harness that maintains state
        state = {"counter": 0}

        def stateful_harness(path: Path) -> dict:
            state["counter"] += 1
            return {"content": path.read_text(), "count": state["counter"]}

        result = detect_state_leaks(
            harness_function=stateful_harness, test_files=[file1, file2, file3]
        )

        # State leaks should be detected for files 2 and 3
        assert result["leaked"] is True
        assert len(result["affected_files"]) > 0
        assert len(result["evidence"]) > 0

    def test_detect_state_leaks_insufficient_files(self, tmp_path: Path) -> None:
        """Test detection with insufficient test files."""
        file1 = tmp_path / "test1.txt"
        file1.write_text("content")

        def harness(path: Path) -> str:
            return path.read_text()

        result = detect_state_leaks(
            harness_function=harness,
            test_files=[file1],  # Only 1 file
        )

        # Should return empty results when < 2 files
        assert result["leaked"] is False
        assert len(result["evidence"]) == 0

    def test_detect_state_leaks_empty_file_list(self) -> None:
        """Test detection with empty file list."""

        def harness(path: Path) -> str:
            return "result"

        result = detect_state_leaks(harness_function=harness, test_files=[])

        assert result["leaked"] is False

    def test_detect_state_leaks_harness_raises_exception(self, tmp_path: Path) -> None:
        """Test detection when harness raises exception."""
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"

        file1.write_text("content1")
        file2.write_text("content2")

        def failing_harness(path: Path) -> str:
            if "test2" in str(path):
                raise ValueError("Test error")
            return path.read_text()

        # Should not raise, but skip problematic files
        result = detect_state_leaks(
            harness_function=failing_harness, test_files=[file1, file2]
        )

        # Result should be valid even with exceptions
        assert isinstance(result, dict)
        assert "leaked" in result

    def test_detect_state_leaks_result_structure(self, tmp_path: Path) -> None:
        """Test that result has correct structure."""
        file1 = tmp_path / "test1.txt"
        file2 = tmp_path / "test2.txt"

        file1.write_text("a")
        file2.write_text("b")

        def harness(path: Path) -> str:
            return path.read_text()

        result = detect_state_leaks(harness_function=harness, test_files=[file1, file2])

        assert "leaked" in result
        assert "evidence" in result
        assert "affected_files" in result
        assert isinstance(result["leaked"], bool)
        assert isinstance(result["evidence"], list)
        assert isinstance(result["affected_files"], list)


class TestIntegration:
    """Integration tests for stateless harness utilities."""

    def test_combined_validation_and_leak_detection(self, tmp_path: Path) -> None:
        """Test using both validation and leak detection together."""
        # Create test files
        files = []
        for i in range(3):
            f = tmp_path / f"test{i}.bin"
            f.write_bytes(f"data{i}".encode())
            files.append(f)

        # Create a deterministic, stateless harness
        def harness(path: Path) -> bytes:
            return path.read_bytes()

        # First, validate determinism
        is_deterministic, error = validate_determinism(
            test_input=files[0], test_function=harness, runs=3
        )

        assert is_deterministic is True
        assert error is None

        # Then, detect state leaks
        leak_result = detect_state_leaks(harness_function=harness, test_files=files)

        assert leak_result["leaked"] is False

    def test_wrapped_function_in_determinism_check(self) -> None:
        """Test wrapped function with determinism validation."""
        counter = [0]

        def non_deterministic_impl(x: int) -> int:
            counter[0] += 1
            return x * counter[0]

        # Wrap it (but wrapper doesn't fix non-determinism)
        wrapped = create_stateless_test_wrapper(non_deterministic_impl)

        # Validate wrapped function
        is_deterministic, error = validate_determinism(
            test_input=5, test_function=wrapped, runs=3
        )

        # Should still detect non-determinism
        assert is_deterministic is False
        assert error is not None
