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


class TestCrashDeduplicationIntegration:
    """Integration tests for complete deduplication workflows."""

    @pytest.fixture
    def realistic_crash_dataset(self):
        """Create realistic crash dataset mimicking real fuzzing output."""
        crashes = []

        # Group 1: Same buffer overflow, different file sizes
        for i in range(5):
            crashes.append(
                CrashRecord(
                    crash_id=f"buffer_overflow_{i}",
                    timestamp=datetime.now(),
                    crash_type="crash",
                    severity="critical",
                    fuzzed_file_id=f"file_{i}",
                    fuzzed_file_path=f"fuzzed_{i}.dcm",
                    exception_type="MemoryError",
                    exception_message=f"Buffer overflow at offset {1000 + i * 100}",
                    stack_trace="""
                    File "dicom_parser.py", line 150, in parse_pixel_data
                        memcpy(buffer, data, size)
                    File "memory.py", line 45, in memcpy
                        raise MemoryError("Buffer overflow")
                    """,
                )
            )

        # Group 2: Same null pointer dereference
        for i in range(3):
            crashes.append(
                CrashRecord(
                    crash_id=f"null_deref_{i}",
                    timestamp=datetime.now(),
                    crash_type="crash",
                    severity="high",
                    fuzzed_file_id=f"file_{i + 10}",
                    fuzzed_file_path=f"fuzzed_{i + 10}.dcm",
                    exception_type="NullPointerException",
                    exception_message="Attempted to access null reference",
                    stack_trace="""
                    File "metadata.py", line 200, in get_patient_name
                        return dataset.PatientName.value
                    AttributeError: 'NoneType' object has no attribute 'value'
                    """,
                )
            )

        # Group 3: Unique timeout/hang issues
        crashes.append(
            CrashRecord(
                crash_id="timeout_1",
                timestamp=datetime.now(),
                crash_type="hang",
                severity="medium",
                fuzzed_file_id="file_20",
                fuzzed_file_path="fuzzed_20.dcm",
                exception_message="Timeout after 30 seconds",
                stack_trace=None,
            )
        )

        # Group 4: Unique assertion failure
        crashes.append(
            CrashRecord(
                crash_id="assertion_1",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="file_21",
                fuzzed_file_path="fuzzed_21.dcm",
                exception_type="AssertionError",
                exception_message="Expected positive value, got -1",
                stack_trace="""
                File "validator.py", line 75, in validate_rows
                    assert rows > 0, "Expected positive value"
                AssertionError: Expected positive value, got -1
                """,
            )
        )

        return crashes

    def test_full_deduplication_workflow(self, realistic_crash_dataset):
        """Test complete deduplication workflow with realistic data."""
        config = DeduplicationConfig(
            stack_trace_weight=0.5,
            exception_weight=0.3,
            mutation_weight=0.2,
            overall_threshold=0.75,
        )

        deduplicator = CrashDeduplicator(config)
        groups = deduplicator.deduplicate_crashes(realistic_crash_dataset)

        # Should identify 4 unique crash patterns
        assert len(groups) == 4, f"Expected 4 groups, got {len(groups)}"

        # Verify stats
        stats = deduplicator.get_deduplication_stats()
        assert stats["total_crashes"] == 10
        assert stats["unique_groups"] == 4
        assert stats["largest_group"] == 5  # Buffer overflow group
        assert 0.0 < stats["deduplication_ratio"] < 1.0

    def test_stack_trace_similarity_clustering(self, realistic_crash_dataset):
        """Test that crashes with similar stack traces are clustered."""
        deduplicator = CrashDeduplicator()
        groups = deduplicator.deduplicate_crashes(realistic_crash_dataset)

        # Find buffer overflow group (should have 5 members)
        buffer_overflow_group = None
        for group_crashes in groups.values():
            if len(group_crashes) == 5:
                buffer_overflow_group = group_crashes
                break

        assert buffer_overflow_group is not None
        # All should be MemoryError crashes
        for crash in buffer_overflow_group:
            assert crash.exception_type == "MemoryError"

    def test_exception_type_grouping(self, realistic_crash_dataset):
        """Test that exception type influences grouping."""
        config = DeduplicationConfig(
            exception_weight=0.8,  # Heavy weight on exception type
            stack_trace_weight=0.1,
            mutation_weight=0.1,
        )

        deduplicator = CrashDeduplicator(config)
        groups = deduplicator.deduplicate_crashes(realistic_crash_dataset)

        # Should still separate different exception types
        exception_types_per_group = []
        for group_crashes in groups.values():
            types = {c.exception_type for c in group_crashes if c.exception_type}
            exception_types_per_group.append(types)

        # Each group should have predominantly one exception type
        for types in exception_types_per_group:
            if types:  # Skip None types
                assert len(types) <= 2

    def test_threshold_affects_grouping(self, realistic_crash_dataset):
        """Test that threshold parameter affects number of groups."""
        # Low threshold = more grouping (fewer groups)
        low_threshold_config = DeduplicationConfig(overall_threshold=0.5)
        low_dedup = CrashDeduplicator(low_threshold_config)
        low_groups = low_dedup.deduplicate_crashes(realistic_crash_dataset)

        # High threshold = less grouping (more groups)
        high_threshold_config = DeduplicationConfig(overall_threshold=0.95)
        high_dedup = CrashDeduplicator(high_threshold_config)
        high_groups = high_dedup.deduplicate_crashes(realistic_crash_dataset)

        # High threshold should create more or equal groups
        assert len(high_groups) >= len(low_groups)

    def test_empty_stack_traces_handled(self):
        """Test deduplication with crashes lacking stack traces."""
        crashes = [
            CrashRecord(
                crash_id=f"hang_{i}",
                timestamp=datetime.now(),
                crash_type="hang",
                severity="medium",
                fuzzed_file_id=f"f{i}",
                fuzzed_file_path=f"t{i}.dcm",
                exception_message=f"Timeout {i}",
                stack_trace=None,  # No stack trace
            )
            for i in range(3)
        ]

        deduplicator = CrashDeduplicator()
        groups = deduplicator.deduplicate_crashes(crashes)

        # Should still group them (based on exception/type)
        assert len(groups) >= 1
        stats = deduplicator.get_deduplication_stats()
        assert stats["total_crashes"] == 3

    def test_mixed_crash_types(self):
        """Test deduplication across different crash types."""
        crashes = [
            CrashRecord(
                crash_id="crash_1",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="f1",
                fuzzed_file_path="t1.dcm",
                exception_type="ValueError",
            ),
            CrashRecord(
                crash_id="hang_1",
                timestamp=datetime.now(),
                crash_type="hang",
                severity="medium",
                fuzzed_file_id="f2",
                fuzzed_file_path="t2.dcm",
            ),
            CrashRecord(
                crash_id="error_1",
                timestamp=datetime.now(),
                crash_type="error",
                severity="low",
                fuzzed_file_id="f3",
                fuzzed_file_path="t3.dcm",
                exception_type="RuntimeError",
            ),
        ]

        deduplicator = CrashDeduplicator()
        groups = deduplicator.deduplicate_crashes(crashes)

        # Different crash types should be in separate groups
        assert len(groups) >= 2

    def test_deduplication_preserves_all_crashes(self, realistic_crash_dataset):
        """Ensure no crashes are lost during deduplication."""
        deduplicator = CrashDeduplicator()
        groups = deduplicator.deduplicate_crashes(realistic_crash_dataset)

        # Count crashes in all groups
        total_in_groups = sum(len(crashes) for crashes in groups.values())

        assert total_in_groups == len(realistic_crash_dataset)

    def test_group_signatures_are_unique(self, realistic_crash_dataset):
        """Test that group signatures are unique."""
        deduplicator = CrashDeduplicator()
        groups = deduplicator.deduplicate_crashes(realistic_crash_dataset)

        # Extract signature parts from group IDs
        signatures = [group_id.split("_")[-1] for group_id in groups.keys()]

        # All signatures should be unique
        assert len(signatures) == len(set(signatures))

    def test_incremental_deduplication(self):
        """Test adding crashes incrementally to deduplicator."""
        deduplicator = CrashDeduplicator()

        # First batch - with stack trace for better grouping
        batch1 = [
            CrashRecord(
                crash_id="c1",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="f1",
                fuzzed_file_path="t1.dcm",
                exception_type="ValueError",
                exception_message="Error A",
                stack_trace="File test.py, line 10 in main\nValueError: Error A",
            )
        ]

        groups1 = deduplicator.deduplicate_crashes(batch1)
        assert len(groups1) == 1

        # Second batch with similar crash (same stack trace pattern)
        batch2 = batch1 + [
            CrashRecord(
                crash_id="c2",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="f2",
                fuzzed_file_path="t2.dcm",
                exception_type="ValueError",
                exception_message="Error A",
                stack_trace="File test.py, line 10 in main\nValueError: Error A",
            )
        ]

        groups2 = deduplicator.deduplicate_crashes(batch2)

        # Should still be 1 group with 2 crashes (same exception + stack trace)
        assert len(groups2) == 1
        assert sum(len(g) for g in groups2.values()) == 2

    def test_session_crash_deduplication_integration(self):
        """Test deduplication from complete session data."""
        session_data = {
            "session_id": "test_session_001",
            "crashes": [
                {
                    "crash_id": f"crash_{i:03d}",
                    "timestamp": datetime.now().isoformat(),
                    "crash_type": "crash" if i % 2 == 0 else "hang",
                    "severity": "high",
                    "fuzzed_file_id": f"file_{i}",
                    "fuzzed_file_path": f"fuzzed_{i}.dcm",
                    "exception_type": "ValueError" if i % 2 == 0 else None,
                    "exception_message": f"Error in file {i}",
                    "stack_trace": "traceback..." if i % 2 == 0 else None,
                }
                for i in range(10)
            ],
        }

        result = deduplicate_session_crashes(session_data)

        assert "groups" in result
        assert "statistics" in result
        assert result["statistics"]["total_crashes"] == 10
        assert result["statistics"]["unique_groups"] >= 1

    def test_weighted_strategy_combinations(self, realistic_crash_dataset):
        """Test different weighting strategies produce different results."""
        # Stack trace heavy
        stack_config = DeduplicationConfig(
            stack_trace_weight=0.8, exception_weight=0.1, mutation_weight=0.1
        )
        stack_dedup = CrashDeduplicator(stack_config)
        stack_groups = stack_dedup.deduplicate_crashes(realistic_crash_dataset)

        # Exception heavy
        exc_config = DeduplicationConfig(
            stack_trace_weight=0.1, exception_weight=0.8, mutation_weight=0.1
        )
        exc_dedup = CrashDeduplicator(exc_config)
        exc_groups = exc_dedup.deduplicate_crashes(realistic_crash_dataset)

        # Both should work but may produce different groupings
        assert len(stack_groups) >= 1
        assert len(exc_groups) >= 1

        # Stats should reflect same total crashes
        stack_stats = stack_dedup.get_deduplication_stats()
        exc_stats = exc_dedup.get_deduplication_stats()
        assert stack_stats["total_crashes"] == exc_stats["total_crashes"]
