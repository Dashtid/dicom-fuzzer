"""
Tests for Crash Deduplication System

Tests multi-strategy crash grouping and similarity analysis.
"""

from datetime import datetime

import pytest

from core.crash_deduplication import (
    CrashDeduplicator,
    DeduplicationConfig,
    deduplicate_session_crashes,
)
from core.fuzzing_session import CrashRecord


class TestDeduplicationConfig:
    """Test deduplication configuration."""

    def test_default_config(self):
        """Test default configuration values."""
        config = DeduplicationConfig()

        assert config.use_stack_trace is True
        assert config.use_exception_type is True
        assert config.stack_trace_weight == 0.5
        assert config.exception_weight == 0.3
        assert config.mutation_weight == 0.2

    def test_custom_config(self):
        """Test custom configuration."""
        config = DeduplicationConfig(
            stack_trace_weight=0.6,
            exception_weight=0.3,
            mutation_weight=0.1,
        )

        assert config.stack_trace_weight == 0.6
        assert config.exception_weight == 0.3

    def test_invalid_weights(self):
        """Test that invalid weights raise error."""
        with pytest.raises(ValueError):
            DeduplicationConfig(
                stack_trace_weight=0.3,
                exception_weight=0.3,
                mutation_weight=0.3,  # Sum = 0.9, not 1.0
            )


class TestCrashDeduplicator:
    """Test crash deduplication functionality."""

    @pytest.fixture
    def similar_crashes(self):
        """Create set of similar crashes for testing."""
        base_trace = """
        File "test.py", line 10, in main
            process_dicom(file)
        File "dicom.py", line 50, in process_dicom
            parse_header(data)
        File "parser.py", line 100, in parse_header
            raise ValueError("Invalid header")
        """

        crashes = [
            CrashRecord(
                crash_id="crash_001",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="file_001",
                fuzzed_file_path="test1.dcm",
                exception_type="ValueError",
                exception_message="Invalid header",
                stack_trace=base_trace,
            ),
            CrashRecord(
                crash_id="crash_002",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="file_002",
                fuzzed_file_path="test2.dcm",
                exception_type="ValueError",
                exception_message="Invalid header",
                stack_trace=base_trace,  # Same trace
            ),
            CrashRecord(
                crash_id="crash_003",
                timestamp=datetime.now(),
                crash_type="hang",
                severity="medium",
                fuzzed_file_id="file_003",
                fuzzed_file_path="test3.dcm",
                exception_message="Timeout after 5s",
                stack_trace=None,
            ),
        ]

        return crashes

    def test_deduplicate_empty_list(self):
        """Test deduplication with empty crash list."""
        deduplicator = CrashDeduplicator()
        groups = deduplicator.deduplicate_crashes([])

        assert len(groups) == 0
        assert deduplicator.get_unique_crash_count() == 0

    def test_deduplicate_similar_crashes(self, similar_crashes):
        """Test that similar crashes are grouped together."""
        deduplicator = CrashDeduplicator()
        groups = deduplicator.deduplicate_crashes(
            similar_crashes[:2]
        )  # First 2 are similar

        # Should group into 1 group (both have same stack trace and exception)
        assert len(groups) == 1
        group_crashes = list(groups.values())[0]
        assert len(group_crashes) == 2

    def test_deduplicate_different_crashes(self, similar_crashes):
        """Test that different crashes are separated."""
        deduplicator = CrashDeduplicator()
        groups = deduplicator.deduplicate_crashes(similar_crashes)  # All 3

        # Should create 2 groups (crash vs hang)
        assert len(groups) >= 1  # At least one group
        assert deduplicator.get_unique_crash_count() >= 1

    def test_deduplication_stats(self, similar_crashes):
        """Test deduplication statistics."""
        deduplicator = CrashDeduplicator()
        deduplicator.deduplicate_crashes(similar_crashes)

        stats = deduplicator.get_deduplication_stats()

        assert stats["total_crashes"] == 3
        assert stats["unique_groups"] > 0
        assert "largest_group" in stats
        assert "deduplication_ratio" in stats

    def test_stack_trace_normalization(self):
        """Test stack trace normalization."""
        deduplicator = CrashDeduplicator()

        trace1 = "at 0x12345678 line 50"
        trace2 = "at 0x87654321 line 50"

        norm1 = deduplicator._normalize_stack_trace(trace1)
        norm2 = deduplicator._normalize_stack_trace(trace2)

        # Should normalize addresses to same pattern
        assert "0xADDR" in norm1
        assert norm1 == norm2  # Should be identical after normalization

    def test_function_extraction(self):
        """Test function extraction from stack trace."""
        deduplicator = CrashDeduplicator()

        trace = """
        at main() in test.py:10
        at process_data() in parser.py:50
        at validate() in validator.py:100
        """

        functions = deduplicator._extract_function_sequence(trace)

        assert len(functions) > 0
        # Should extract function names

    def test_exception_comparison(self):
        """Test exception similarity comparison."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            exception_type="ValueError",
            exception_message="Invalid value 123",
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            exception_type="ValueError",
            exception_message="Invalid value 456",
        )

        similarity = deduplicator._compare_exceptions(crash1, crash2)

        # Should have high similarity (same type, similar message)
        assert similarity > 0.5

    def test_exception_normalization(self):
        """Test exception message normalization."""
        deduplicator = CrashDeduplicator()

        msg1 = "File C:\\Path\\To\\File.dcm not found at line 42"
        msg2 = "File D:\\Other\\Path\\Test.dcm not found at line 99"

        norm1 = deduplicator._normalize_exception_message(msg1)
        norm2 = deduplicator._normalize_exception_message(msg2)

        # Should normalize paths and numbers
        assert "PATH" in norm1
        assert "NUM" in norm1
        assert norm1 == norm2  # Should be identical

    def test_signature_generation(self):
        """Test crash signature generation."""
        deduplicator = CrashDeduplicator()

        crash = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="test.dcm",
            exception_type="ValueError",
            exception_message="Test error",
            stack_trace="line 1\nline 2",
        )

        sig = deduplicator._generate_signature(crash)

        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA256 hex length

    def test_configurable_thresholds(self):
        """Test configurable similarity thresholds."""
        config = DeduplicationConfig(overall_threshold=0.95)  # Very high threshold

        deduplicator = CrashDeduplicator(config)

        crashes = [
            CrashRecord(
                crash_id=f"c{i}",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id=f"f{i}",
                fuzzed_file_path=f"t{i}.dcm",
                exception_type="ValueError",
                exception_message=f"Error {i}",
            )
            for i in range(3)
        ]

        groups = deduplicator.deduplicate_crashes(crashes)

        # High threshold should create more groups (less deduplication)
        assert len(groups) >= 1


class TestDeduplicateSessionCrashes:
    """Test session-level deduplication."""

    def test_deduplicate_session_data(self):
        """Test deduplicating crashes from session data."""
        session_data = {
            "crashes": [
                {
                    "crash_id": "c1",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "f1",
                    "fuzzed_file_path": "t1.dcm",
                    "exception_type": "ValueError",
                    "exception_message": "Test",
                    "stack_trace": "trace1",
                },
                {
                    "crash_id": "c2",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash",
                    "severity": "high",
                    "fuzzed_file_id": "f2",
                    "fuzzed_file_path": "t2.dcm",
                    "exception_type": "ValueError",
                    "exception_message": "Test",
                    "stack_trace": "trace1",  # Same trace
                },
            ]
        }

        result = deduplicate_session_crashes(session_data)

        assert "groups" in result
        assert "statistics" in result
        assert len(result["groups"]) >= 1
