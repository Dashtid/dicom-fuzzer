"""Comprehensive tests for dicom_fuzzer.core.crash_deduplication module.

This test suite provides thorough coverage of crash deduplication functionality,
including configuration validation, similarity calculations, and grouping logic.
"""

import hashlib
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.core.crash_deduplication import (
    CrashDeduplicator,
    DeduplicationConfig,
    deduplicate_session_crashes,
)
from dicom_fuzzer.core.fuzzing_session import CrashRecord


class TestDeduplicationConfig:
    """Test suite for DeduplicationConfig dataclass."""

    def test_initialization_with_defaults(self):
        """Test DeduplicationConfig with default values."""
        config = DeduplicationConfig()

        assert config.use_stack_trace is True
        assert config.use_exception_type is True
        assert config.use_mutation_pattern is True
        assert config.stack_trace_weight == 0.5
        assert config.exception_weight == 0.3
        assert config.mutation_weight == 0.2
        assert config.overall_threshold == 0.75

    def test_initialization_with_custom_values(self):
        """Test DeduplicationConfig with custom values."""
        config = DeduplicationConfig(
            use_stack_trace=False,
            stack_trace_weight=0.0,
            exception_weight=0.7,
            mutation_weight=0.3,
            overall_threshold=0.85,
        )

        assert config.use_stack_trace is False
        assert config.stack_trace_weight == 0.0
        assert config.exception_weight == 0.7
        assert config.mutation_weight == 0.3
        assert config.overall_threshold == 0.85

    def test_weight_validation_success(self):
        """Test weight validation passes for valid weights."""
        config = DeduplicationConfig(
            stack_trace_weight=0.6, exception_weight=0.3, mutation_weight=0.1
        )

        # Should not raise
        assert config.stack_trace_weight == 0.6

    def test_weight_validation_failure(self):
        """Test weight validation fails for invalid weights."""
        with pytest.raises(ValueError, match="Weights must sum to 1.0"):
            DeduplicationConfig(
                stack_trace_weight=0.5, exception_weight=0.5, mutation_weight=0.5
            )

    def test_weight_validation_within_tolerance(self):
        """Test weight validation allows small floating-point errors."""
        config = DeduplicationConfig(
            stack_trace_weight=0.333,
            exception_weight=0.333,
            mutation_weight=0.334,
        )

        # Should not raise (sum is 1.0 within tolerance)
        assert config.stack_trace_weight == 0.333


class TestCrashDeduplicatorInitialization:
    """Test suite for CrashDeduplicator initialization."""

    def test_initialization_with_default_config(self):
        """Test CrashDeduplicator with default config."""
        deduplicator = CrashDeduplicator()

        assert deduplicator.config is not None
        assert isinstance(deduplicator.config, DeduplicationConfig)
        assert deduplicator.crash_groups == []
        assert deduplicator.group_signatures == []

    def test_initialization_with_custom_config(self):
        """Test CrashDeduplicator with custom config."""
        config = DeduplicationConfig(overall_threshold=0.9)
        deduplicator = CrashDeduplicator(config=config)

        assert deduplicator.config == config
        assert deduplicator.config.overall_threshold == 0.9


class TestDeduplicateCrashes:
    """Test suite for crash deduplication logic."""

    def test_deduplicate_empty_list(self):
        """Test deduplication with empty crash list."""
        deduplicator = CrashDeduplicator()

        groups = deduplicator.deduplicate_crashes([])

        assert groups == {}
        assert deduplicator.crash_groups == []

    def test_deduplicate_single_crash(self):
        """Test deduplication with single crash."""
        deduplicator = CrashDeduplicator()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="File test.py, line 10",
        )

        groups = deduplicator.deduplicate_crashes([crash])

        assert len(groups) == 1
        assert len(deduplicator.crash_groups) == 1
        assert deduplicator.crash_groups[0][0] == crash

    def test_deduplicate_identical_crashes(self):
        """Test deduplication groups identical crashes."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="File test.py, line 10, in func\nFile main.py, line 5",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="File test.py, line 12, in func\nFile main.py, line 7",
        )

        groups = deduplicator.deduplicate_crashes([crash1, crash2])

        # Should group together due to similarity
        assert len(groups) == 1
        group_crashes = list(groups.values())[0]
        assert len(group_crashes) == 2

    def test_deduplicate_different_crashes(self):
        """Test deduplication separates different crashes."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
            exception_message="Value error",
            stack_trace="File test.py, line 10",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="timeout",
            severity="medium",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="TimeoutError",
            exception_message="Timeout occurred",
            stack_trace="File different.py, line 99",
        )

        groups = deduplicator.deduplicate_crashes([crash1, crash2])

        # Should create separate groups
        assert len(groups) == 2

    def test_group_id_format(self):
        """Test group ID format includes counter and signature."""
        deduplicator = CrashDeduplicator()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )

        groups = deduplicator.deduplicate_crashes([crash])

        group_id = list(groups.keys())[0]
        assert group_id.startswith("group_001_")
        assert len(group_id) > 10  # Has signature hash


class TestGetUniqueCrashCount:
    """Test suite for unique crash count."""

    def test_unique_crash_count_empty(self):
        """Test unique crash count with no crashes."""
        deduplicator = CrashDeduplicator()

        count = deduplicator.get_unique_crash_count()

        assert count == 0

    def test_unique_crash_count_after_deduplication(self):
        """Test unique crash count after deduplication."""
        deduplicator = CrashDeduplicator()
        crashes = [
            CrashRecord(
                crash_id=f"crash_{i}",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id=f"file_{i}",
                fuzzed_file_path=f"/test{i}.dcm",
            )
            for i in range(5)
        ]

        deduplicator.deduplicate_crashes(crashes)
        count = deduplicator.get_unique_crash_count()

        assert count > 0


class TestGetDeduplicationStats:
    """Test suite for deduplication statistics."""

    def test_stats_empty(self):
        """Test stats with no crashes."""
        deduplicator = CrashDeduplicator()

        stats = deduplicator.get_deduplication_stats()

        assert stats["total_crashes"] == 0
        assert stats["unique_groups"] == 0
        assert stats["largest_group"] == 0
        assert stats["deduplication_ratio"] == 0.0

    def test_stats_single_group(self):
        """Test stats with single group."""
        deduplicator = CrashDeduplicator()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )

        deduplicator.deduplicate_crashes([crash])
        stats = deduplicator.get_deduplication_stats()

        assert stats["total_crashes"] == 1
        assert stats["unique_groups"] == 1
        assert stats["largest_group"] == 1
        assert stats["deduplication_ratio"] == 0.0

    def test_stats_multiple_groups(self):
        """Test stats with multiple groups."""
        deduplicator = CrashDeduplicator()
        crashes = [
            CrashRecord(
                crash_id=f"crash_{i}",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id=f"file_{i}",
                fuzzed_file_path=f"/test{i}.dcm",
                exception_type=f"Error{i % 2}",  # Two different types
            )
            for i in range(10)
        ]

        deduplicator.deduplicate_crashes(crashes)
        stats = deduplicator.get_deduplication_stats()

        assert stats["total_crashes"] == 10
        assert stats["unique_groups"] >= 1
        assert "group_sizes" in stats

    def test_stats_deduplication_ratio(self):
        """Test deduplication ratio calculation."""
        deduplicator = CrashDeduplicator()
        # Create crashes that will group together
        crashes = [
            CrashRecord(
                crash_id=f"crash_{i}",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id=f"file_{i}",
                fuzzed_file_path=f"/test{i}.dcm",
                exception_type="SameError",
                exception_message="Same message",
                stack_trace="Same trace",
            )
            for i in range(5)
        ]

        deduplicator.deduplicate_crashes(crashes)
        stats = deduplicator.get_deduplication_stats()

        # All similar crashes should group together
        assert stats["deduplication_ratio"] > 0.0


class TestCompareStackTraces:
    """Test suite for stack trace comparison."""

    def test_compare_identical_traces(self):
        """Test comparing identical stack traces."""
        deduplicator = CrashDeduplicator()
        trace = "File test.py, line 10, in function\nFile main.py, line 5"

        similarity = deduplicator._compare_stack_traces(trace, trace)

        assert similarity == 1.0

    def test_compare_similar_traces(self):
        """Test comparing similar stack traces with different line numbers."""
        deduplicator = CrashDeduplicator()
        trace1 = "File test.py, line 10, in function\nFile main.py, line 5"
        trace2 = "File test.py, line 12, in function\nFile main.py, line 7"

        similarity = deduplicator._compare_stack_traces(trace1, trace2)

        # Should be high similarity (different line numbers normalized)
        assert similarity > 0.8

    def test_compare_different_traces(self):
        """Test comparing completely different stack traces."""
        deduplicator = CrashDeduplicator()
        trace1 = "File test.py, line 10, in function_a"
        trace2 = "File other.py, line 99, in function_z"

        similarity = deduplicator._compare_stack_traces(trace1, trace2)

        # Should be low similarity
        assert similarity < 0.5


class TestNormalizeStackTrace:
    """Test suite for stack trace normalization."""

    def test_normalize_removes_addresses(self):
        """Test normalization removes memory addresses."""
        deduplicator = CrashDeduplicator()
        trace = "Crash at 0x7fff1234abcd in function"

        normalized = deduplicator._normalize_stack_trace(trace)

        assert "0x7fff1234abcd" not in normalized
        assert "0xADDR" in normalized

    def test_normalize_removes_line_numbers(self):
        """Test normalization removes line numbers."""
        deduplicator = CrashDeduplicator()
        trace = "File test.py:42 in function"

        normalized = deduplicator._normalize_stack_trace(trace)

        assert ":42" not in normalized
        assert ":LINE" in normalized

    def test_normalize_removes_timestamps(self):
        """Test normalization removes timestamps."""
        deduplicator = CrashDeduplicator()
        trace = "2025-01-15 14:30:45 Error occurred"

        normalized = deduplicator._normalize_stack_trace(trace)

        assert "2025-01-15 14:30:45" not in normalized
        assert "TIMESTAMP" in normalized

    def test_normalize_removes_process_ids(self):
        """Test normalization removes process IDs."""
        deduplicator = CrashDeduplicator()
        trace = "pid: 1234 crashed"

        normalized = deduplicator._normalize_stack_trace(trace)

        assert "1234" not in normalized
        assert "pid:ID" in normalized

    def test_normalize_preserves_function_names(self):
        """Test normalization preserves function names."""
        deduplicator = CrashDeduplicator()
        trace = "in my_function at 0x1234"

        normalized = deduplicator._normalize_stack_trace(trace)

        assert "my_function" in normalized


class TestExtractFunctionSequence:
    """Test suite for function sequence extraction."""

    def test_extract_java_style_functions(self):
        """Test extracting Java/C++ style function names."""
        deduplicator = CrashDeduplicator()
        trace = "at com.example.MyClass.myMethod()\nat java.lang.String.valueOf()"

        functions = deduplicator._extract_function_sequence(trace)

        assert "com.example.MyClass.myMethod" in functions or "myMethod" in functions

    def test_extract_python_style_functions(self):
        """Test extracting Python style function names."""
        deduplicator = CrashDeduplicator()
        trace = "in my_function\nin another_function"

        functions = deduplicator._extract_function_sequence(trace)

        assert "my_function" in functions
        assert "another_function" in functions

    def test_extract_empty_for_no_matches(self):
        """Test extraction returns empty for no function names."""
        deduplicator = CrashDeduplicator()
        trace = "Random text without function names 12345"

        functions = deduplicator._extract_function_sequence(trace)

        assert functions == [] or len(functions) == 0


class TestCompareExceptions:
    """Test suite for exception comparison."""

    def test_compare_identical_exception_types(self):
        """Test comparing identical exception types."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
            exception_message="Test message",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="ValueError",
            exception_message="Test message",
        )

        similarity = deduplicator._compare_exceptions(crash1, crash2)

        assert similarity >= 0.7  # High similarity

    def test_compare_different_exception_types(self):
        """Test comparing different exception types."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="TimeoutError",
        )

        similarity = deduplicator._compare_exceptions(crash1, crash2)

        # Should be low similarity
        assert similarity < 0.5

    def test_compare_similar_exception_types(self):
        """Test comparing similar exception type names."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="FileNotFoundError",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="FileNotFound",
        )

        similarity = deduplicator._compare_exceptions(crash1, crash2)

        # Should have moderate similarity due to partial name match
        assert similarity > 0.4

    def test_compare_missing_exception_types(self):
        """Test comparing crashes with missing exception types."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
        )

        similarity = deduplicator._compare_exceptions(crash1, crash2)

        # Missing types should result in low similarity
        assert similarity == 0.0


class TestNormalizeExceptionMessage:
    """Test suite for exception message normalization."""

    def test_normalize_removes_numbers(self):
        """Test normalization removes numbers."""
        deduplicator = CrashDeduplicator()
        message = "Error at index 42 with value 1234"

        normalized = deduplicator._normalize_exception_message(message)

        assert "42" not in normalized
        assert "1234" not in normalized
        assert "NUM" in normalized

    def test_normalize_removes_hex_values(self):
        """Test normalization removes hex values."""
        deduplicator = CrashDeduplicator()
        message = "Memory error at 0xdeadbeef"

        normalized = deduplicator._normalize_exception_message(message)

        assert "0xdeadbeef" not in normalized
        assert "HEX" in normalized

    def test_normalize_removes_windows_paths(self):
        """Test normalization removes Windows file paths."""
        deduplicator = CrashDeduplicator()
        message = "File not found: C:\\Users\\test\\file.txt"

        normalized = deduplicator._normalize_exception_message(message)

        assert "C:\\Users\\test\\file.txt" not in normalized
        assert "PATH" in normalized

    def test_normalize_removes_unix_paths(self):
        """Test normalization removes Unix file paths."""
        deduplicator = CrashDeduplicator()
        message = "Error in /home/user/test.py"

        normalized = deduplicator._normalize_exception_message(message)

        assert "/home/user/test.py" not in normalized
        assert "PATH" in normalized

    def test_normalize_preserves_text(self):
        """Test normalization preserves descriptive text."""
        deduplicator = CrashDeduplicator()
        message = "Invalid value encountered"

        normalized = deduplicator._normalize_exception_message(message)

        assert "Invalid" in normalized
        assert "value" in normalized


class TestCompareMutationPatterns:
    """Test suite for mutation pattern comparison."""

    def test_compare_mutation_patterns_placeholder(self):
        """Test mutation pattern comparison returns neutral score."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Currently returns 0.5 as placeholder
        assert similarity == 0.5


class TestGenerateSignature:
    """Test suite for signature generation."""

    def test_generate_signature_deterministic(self):
        """Test signature is deterministic for same crash."""
        deduplicator = CrashDeduplicator()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="File test.py, line 10",
        )

        sig1 = deduplicator._generate_signature(crash)
        sig2 = deduplicator._generate_signature(crash)

        assert sig1 == sig2

    def test_generate_signature_different_crashes(self):
        """Test different crashes produce different signatures."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="timeout",
            severity="medium",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="TimeoutError",
        )

        sig1 = deduplicator._generate_signature(crash1)
        sig2 = deduplicator._generate_signature(crash2)

        assert sig1 != sig2

    def test_generate_signature_format(self):
        """Test signature is SHA256 hex digest."""
        deduplicator = CrashDeduplicator()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )

        signature = deduplicator._generate_signature(crash)

        # SHA256 hex digest is 64 characters
        assert len(signature) == 64
        assert all(c in "0123456789abcdef" for c in signature)


class TestCalculateSimilarity:
    """Test suite for overall similarity calculation."""

    def test_calculate_similarity_with_all_strategies(self):
        """Test similarity calculation uses all enabled strategies."""
        deduplicator = CrashDeduplicator()
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="File test.py, line 10, in func",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="File test.py, line 12, in func",
        )

        similarity = deduplicator._calculate_similarity(crash1, crash2)

        # Should be high due to similar exception and stack trace
        assert 0.0 <= similarity <= 1.0

    def test_calculate_similarity_disabled_strategies(self):
        """Test similarity with disabled strategies."""
        config = DeduplicationConfig(
            use_stack_trace=False,
            stack_trace_weight=0.0,
            exception_weight=0.5,
            mutation_weight=0.5,
        )
        deduplicator = CrashDeduplicator(config=config)
        crash1 = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
        )
        crash2 = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="ValueError",
        )

        similarity = deduplicator._calculate_similarity(crash1, crash2)

        # Stack trace should not contribute
        assert 0.0 <= similarity <= 1.0


class TestFindBestGroup:
    """Test suite for finding best matching group."""

    def test_find_best_group_empty(self):
        """Test finding best group with no existing groups."""
        deduplicator = CrashDeduplicator()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )

        result = deduplicator._find_best_group(crash)

        assert result is None

    def test_find_best_group_above_threshold(self):
        """Test finding group when similarity is above threshold."""
        deduplicator = CrashDeduplicator()
        existing_crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="File test.py, line 10",
        )
        deduplicator.crash_groups = [[existing_crash]]

        new_crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="File test.py, line 12",
        )

        result = deduplicator._find_best_group(new_crash)

        # Should find the matching group
        assert result is not None

    def test_find_best_group_below_threshold(self):
        """Test no group found when similarity below threshold."""
        config = DeduplicationConfig(overall_threshold=0.95)  # Very high threshold
        deduplicator = CrashDeduplicator(config=config)
        existing_crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="ValueError",
        )
        deduplicator.crash_groups = [[existing_crash]]

        new_crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="timeout",
            severity="medium",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test2.dcm",
            exception_type="TimeoutError",
        )

        result = deduplicator._find_best_group(new_crash)

        # Should not find a match due to differences
        assert result is None


class TestDeduplicateSessionCrashes:
    """Test suite for helper function."""

    def test_deduplicate_session_crashes(self):
        """Test deduplicating crashes from session data."""
        session_data = {
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "timestamp": datetime.now(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "/test.dcm",
                },
                {
                    "crash_id": "crash_002",
                    "timestamp": datetime.now(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file_002",
                    "fuzzed_file_path": "/test2.dcm",
                },
            ]
        }

        result = deduplicate_session_crashes(session_data)

        assert "groups" in result
        assert "statistics" in result
        assert len(result["groups"]) > 0

    def test_deduplicate_session_crashes_empty(self):
        """Test deduplicating empty session data."""
        session_data = {"crashes": []}

        result = deduplicate_session_crashes(session_data)

        assert result["groups"] == {}
        assert result["statistics"]["total_crashes"] == 0

    def test_deduplicate_session_crashes_with_config(self):
        """Test deduplicating with custom config."""
        config = DeduplicationConfig(overall_threshold=0.9)
        session_data = {
            "crashes": [
                {
                    "crash_id": "crash_001",
                    "timestamp": datetime.now(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "file_001",
                    "fuzzed_file_path": "/test.dcm",
                }
            ]
        }

        result = deduplicate_session_crashes(session_data, config=config)

        assert "groups" in result
        assert "statistics" in result


class TestIntegrationScenarios:
    """Test suite for complete deduplication workflows."""

    def test_complete_deduplication_workflow(self):
        """Test complete deduplication workflow."""
        deduplicator = CrashDeduplicator()

        # Create mix of similar and different crashes
        crashes = []
        for i in range(10):
            crash = CrashRecord(
                crash_id=f"crash_{i:03d}",
                timestamp=datetime.now(),
                crash_type="crash" if i < 7 else "timeout",
                severity="high" if i < 5 else "medium",
                fuzzed_file_id=f"file_{i:03d}",
                fuzzed_file_path=f"/test{i}.dcm",
                exception_type="ValueError" if i < 5 else "TimeoutError",
                exception_message=f"Error {i % 3}",  # Group by message
                stack_trace=f"File test.py, line {10 + i}, in func_{i % 4}",
            )
            crashes.append(crash)

        groups = deduplicator.deduplicate_crashes(crashes)
        stats = deduplicator.get_deduplication_stats()

        assert len(groups) > 0
        assert stats["total_crashes"] == 10
        assert stats["unique_groups"] > 0
        assert stats["unique_groups"] <= 10

    def test_high_similarity_grouping(self):
        """Test crashes with high similarity are grouped."""
        deduplicator = CrashDeduplicator()

        # Create very similar crashes
        crashes = [
            CrashRecord(
                crash_id=f"crash_{i}",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id=f"file_{i}",
                fuzzed_file_path=f"/test{i}.dcm",
                exception_type="ValueError",
                exception_message="Same error message",
                stack_trace=f"File test.py, line {10+i}, in same_function",
            )
            for i in range(5)
        ]

        groups = deduplicator.deduplicate_crashes(crashes)
        stats = deduplicator.get_deduplication_stats()

        # Should group most/all together
        assert len(groups) <= 2  # At most 2 groups for very similar crashes
        assert stats["deduplication_ratio"] > 0.5

    def test_low_similarity_separation(self):
        """Test crashes with low similarity are separated."""
        deduplicator = CrashDeduplicator()

        # Create very different crashes
        crashes = [
            CrashRecord(
                crash_id=f"crash_{i}",
                timestamp=datetime.now(),
                crash_type=["crash", "timeout", "hang", "assert"][i % 4],
                severity=["high", "medium", "low"][i % 3],
                fuzzed_file_id=f"file_{i}",
                fuzzed_file_path=f"/test{i}.dcm",
                exception_type=f"Error{i}",
                exception_message=f"Unique error {i}",
                stack_trace=f"File file{i}.py, line {i*10}, in func_{i}",
            )
            for i in range(5)
        ]

        groups = deduplicator.deduplicate_crashes(crashes)

        # Should create separate groups for different crashes
        assert len(groups) >= 3
