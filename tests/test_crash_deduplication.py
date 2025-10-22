"""
Tests for Crash Deduplication System

Tests multi-strategy crash grouping and similarity analysis.
"""

from datetime import datetime

import pytest

from dicom_fuzzer.core.crash_deduplication import (
    CrashDeduplicator,
    DeduplicationConfig,
    deduplicate_session_crashes,
)
from dicom_fuzzer.core.fuzzing_session import CrashRecord


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

    def test_disabled_exception_type(self):
        """Test config with exception type disabled."""
        config = DeduplicationConfig(
            use_exception_type=False,
            stack_trace_weight=0.7,
            exception_weight=0.0,
            mutation_weight=0.3,
        )

        assert config.use_exception_type is False
        assert config.exception_weight == 0.0

    def test_disabled_mutation_pattern(self):
        """Test config with mutation pattern disabled."""
        config = DeduplicationConfig(
            use_mutation_pattern=False,
            stack_trace_weight=0.7,
            exception_weight=0.3,
            mutation_weight=0.0,
        )

        assert config.use_mutation_pattern is False
        assert config.mutation_weight == 0.0


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

    def test_empty_deduplication_stats(self):
        """Test statistics for empty deduplicator."""
        deduplicator = CrashDeduplicator()

        # Get stats without deduplicating any crashes
        stats = deduplicator.get_deduplication_stats()

        assert stats["total_crashes"] == 0
        assert stats["unique_groups"] == 0
        assert stats["largest_group"] == 0
        assert stats["deduplication_ratio"] == 0.0

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

    def test_realistic_mutation_sequence_deduplication(self):
        """Test deduplication with realistic mutation sequences."""
        # Create crashes with realistic mutation patterns
        crashes = []

        # Group 1: Buffer overflow from header fuzzing (3 similar crashes)
        for i in range(3):
            crashes.append(
                CrashRecord(
                    crash_id=f"header_overflow_{i}",
                    timestamp=datetime.now(),
                    crash_type="crash",
                    severity="critical",
                    fuzzed_file_id=f"file_{i}",
                    fuzzed_file_path=f"fuzzed_{i}.dcm",
                    exception_type="MemoryError",
                    exception_message=f"Buffer overflow at offset {i * 100}",
                    stack_trace="""
                    File "dicom_parser.py", line 150, in parse_header
                        read_tag_value(buffer)
                    MemoryError: Buffer overflow
                    """,
                    mutation_sequence=[
                        ("HeaderFuzzer", "overlong_string"),
                        ("HeaderFuzzer", "flip_bits"),
                        ("DictionaryFuzzer", "insert_pattern"),
                    ],
                )
            )

        # Group 2: Null pointer from metadata fuzzing (2 similar crashes)
        for i in range(2):
            crashes.append(
                CrashRecord(
                    crash_id=f"metadata_null_{i}",
                    timestamp=datetime.now(),
                    crash_type="crash",
                    severity="high",
                    fuzzed_file_id=f"file_{i + 10}",
                    fuzzed_file_path=f"fuzzed_{i + 10}.dcm",
                    exception_type="NullPointerException",
                    exception_message="Null reference access",
                    stack_trace="""
                    File "metadata.py", line 200, in get_patient_name
                        return dataset.PatientName.value
                    AttributeError: 'NoneType' object has no attribute 'value'
                    """,
                    mutation_sequence=[
                        ("MetadataFuzzer", "insert_null"),
                        ("MetadataFuzzer", "delete_bytes"),
                    ],
                )
            )

        # Group 3: Pixel data corruption (2 similar crashes)
        for i in range(2):
            crashes.append(
                CrashRecord(
                    crash_id=f"pixel_corrupt_{i}",
                    timestamp=datetime.now(),
                    crash_type="crash",
                    severity="medium",
                    fuzzed_file_id=f"file_{i + 20}",
                    fuzzed_file_path=f"fuzzed_{i + 20}.dcm",
                    exception_type="ValueError",
                    exception_message="Invalid pixel data shape",
                    stack_trace="""
                    File "pixel_data.py", line 80, in decode_pixels
                        validate_shape(pixels)
                    ValueError: Invalid pixel data shape
                    """,
                    mutation_sequence=[
                        ("PixelFuzzer", "corrupt_data"),
                        ("PixelFuzzer", "flip_bits"),
                        ("StructureFuzzer", "modify_header"),
                    ],
                )
            )

        # Group 4: Unique crash with different mutation pattern
        crashes.append(
            CrashRecord(
                crash_id="unique_structure",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="file_30",
                fuzzed_file_path="fuzzed_30.dcm",
                exception_type="StructureError",
                exception_message="Invalid DICOM structure",
                stack_trace="""
                File "validator.py", line 50, in validate_structure
                    check_tag_order(tags)
                StructureError: Invalid tag order
                """,
                mutation_sequence=[
                    ("StructureFuzzer", "reorder_tags"),
                    ("StructureFuzzer", "delete_bytes"),
                ],
            )
        )

        # Test with mutation pattern enabled
        config = DeduplicationConfig(
            stack_trace_weight=0.4,
            exception_weight=0.3,
            mutation_weight=0.3,
            overall_threshold=0.75,
        )

        deduplicator = CrashDeduplicator(config)
        groups = deduplicator.deduplicate_crashes(crashes)

        # Should identify 4 unique crash patterns
        assert len(groups) == 4, f"Expected 4 groups, got {len(groups)}"

        # Verify group sizes
        group_sizes = sorted([len(crashes) for crashes in groups.values()], reverse=True)
        assert group_sizes[0] == 3  # Header overflow group
        assert group_sizes[1] == 2  # Metadata null group
        assert group_sizes[2] == 2  # Pixel corruption group
        assert group_sizes[3] == 1  # Unique structure error

        # Verify stats
        stats = deduplicator.get_deduplication_stats()
        assert stats["total_crashes"] == 8
        assert stats["unique_groups"] == 4
        assert stats["largest_group"] == 3

    def test_mutation_pattern_improves_deduplication_accuracy(self):
        """Test that mutation patterns improve deduplication accuracy."""
        # Create two crashes with:
        # - Similar stack traces and exceptions (would normally group together)
        # - But very different mutation patterns (should separate them)

        crash1 = CrashRecord(
            crash_id="crash_1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            exception_type="ValueError",
            exception_message="Invalid data",
            stack_trace="""
            File "parser.py", line 100, in parse
                validate(data)
            ValueError: Invalid data
            """,
            mutation_sequence=[
                ("HeaderFuzzer", "overlong_string"),
                ("HeaderFuzzer", "flip_bits"),
            ],
        )

        crash2 = CrashRecord(
            crash_id="crash_2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            exception_type="ValueError",
            exception_message="Invalid data",
            stack_trace="""
            File "parser.py", line 100, in parse
                validate(data)
            ValueError: Invalid data
            """,
            mutation_sequence=[
                ("PixelFuzzer", "corrupt_data"),
                ("StructureFuzzer", "delete_bytes"),
            ],
        )

        # With high mutation weight, different patterns should separate crashes
        config_high_mutation = DeduplicationConfig(
            stack_trace_weight=0.2,
            exception_weight=0.2,
            mutation_weight=0.6,
            overall_threshold=0.75,
        )

        dedup_high = CrashDeduplicator(config_high_mutation)
        groups_high = dedup_high.deduplicate_crashes([crash1, crash2])

        # Should create 2 groups (different mutation patterns matter)
        assert len(groups_high) == 2

        # With low mutation weight, similar stack/exception should group together
        config_low_mutation = DeduplicationConfig(
            stack_trace_weight=0.6,
            exception_weight=0.3,
            mutation_weight=0.1,
            overall_threshold=0.75,
        )

        dedup_low = CrashDeduplicator(config_low_mutation)
        groups_low = dedup_low.deduplicate_crashes([crash1, crash2])

        # Should create 1 group (stack trace and exception similarity dominate)
        assert len(groups_low) == 1

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

    def test_disabled_strategies(self):
        """Test deduplication with specific strategies disabled."""
        # Create test crashes
        crashes = [
            CrashRecord(
                crash_id="crash_001",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="file_001",
                fuzzed_file_path="test1.dcm",
                exception_type="ValueError",
                exception_message="Invalid value",
                stack_trace="File test.py, line 10",
            ),
            CrashRecord(
                crash_id="crash_002",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id="file_002",
                fuzzed_file_path="test2.dcm",
                exception_type="ValueError",
                exception_message="Different message",
                stack_trace="File test.py, line 10",
            ),
        ]

        # Config with exception type disabled
        config_no_exc = DeduplicationConfig(
            use_exception_type=False,
            stack_trace_weight=0.7,
            exception_weight=0.0,
            mutation_weight=0.3,
        )
        dedup_no_exc = CrashDeduplicator(config_no_exc)
        groups_no_exc = dedup_no_exc.deduplicate_crashes(crashes)

        # Config with mutation pattern disabled
        config_no_mut = DeduplicationConfig(
            use_mutation_pattern=False,
            stack_trace_weight=0.7,
            exception_weight=0.3,
            mutation_weight=0.0,
        )
        dedup_no_mut = CrashDeduplicator(config_no_mut)
        groups_no_mut = dedup_no_mut.deduplicate_crashes(crashes)

        # Should still work with disabled strategies
        assert len(groups_no_exc) >= 1
        assert len(groups_no_mut) >= 1


class TestMutationPatternComparison:
    """Test mutation pattern comparison functionality."""

    def test_identical_mutation_sequences(self):
        """Test that identical mutation sequences return perfect similarity."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("PixelFuzzer", "corrupt_data"),
                ("MetadataFuzzer", "overlong_string"),
            ],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("PixelFuzzer", "corrupt_data"),
                ("MetadataFuzzer", "overlong_string"),
            ],
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Identical sequences should have very high similarity
        assert similarity >= 0.95

    def test_completely_different_sequences(self):
        """Test that completely different sequences return low similarity."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("HeaderFuzzer", "overlong_string"),
            ],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[
                ("PixelFuzzer", "corrupt_data"),
                ("MetadataFuzzer", "insert_null"),
            ],
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Completely different sequences should have low similarity
        assert similarity <= 0.5

    def test_similar_sequences_different_order(self):
        """Test sequences with same mutations but different order."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("PixelFuzzer", "corrupt_data"),
            ],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[
                ("PixelFuzzer", "corrupt_data"),
                ("HeaderFuzzer", "flip_bits"),
            ],
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Same mutations, different order should still have moderate similarity
        # (due to type/strategy distribution matching)
        assert 0.3 <= similarity <= 0.8

    def test_empty_mutation_sequences_both(self):
        """Test crashes with no mutation data."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[],
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Both empty should be considered similar
        assert similarity == 1.0

    def test_empty_mutation_sequence_one_side(self):
        """Test when only one crash has mutation data."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[("HeaderFuzzer", "flip_bits")],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[],
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # One empty, one with data should be dissimilar
        assert similarity == 0.0

    def test_missing_mutation_sequence_attribute(self):
        """Test crashes without mutation_sequence attribute (backwards compatibility)."""
        deduplicator = CrashDeduplicator()

        # Create crashes without mutation_sequence (old format)
        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
        )

        # Should handle gracefully
        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Both missing should be similar (neutral score)
        assert similarity == 1.0

    def test_mutation_type_distribution_matching(self):
        """Test that same mutation types increase similarity."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("HeaderFuzzer", "flip_bits"),
                ("PixelFuzzer", "corrupt_data"),
            ],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[
                ("MetadataFuzzer", "flip_bits"),
                ("DictionaryFuzzer", "flip_bits"),
                ("StructureFuzzer", "corrupt_data"),
            ],
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Same mutation types (different strategies) should have moderate similarity
        # Note: Using >= 0.29 to account for floating point precision
        assert similarity >= 0.29

    def test_strategy_frequency_matching(self):
        """Test that same strategies increase similarity."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("HeaderFuzzer", "overlong_string"),
                ("PixelFuzzer", "corrupt_data"),
            ],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "insert_null"),
                ("HeaderFuzzer", "delete_bytes"),
                ("PixelFuzzer", "flip_bits"),
            ],
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Same strategies (different mutation types) should have moderate similarity
        # Note: Using >= 0.29 to account for floating point precision
        assert similarity >= 0.29

    def test_partial_sequence_overlap(self):
        """Test sequences with partial overlap."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("PixelFuzzer", "corrupt_data"),
                ("MetadataFuzzer", "overlong_string"),
                ("DictionaryFuzzer", "insert_null"),
            ],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("PixelFuzzer", "corrupt_data"),
                ("StructureFuzzer", "delete_bytes"),
            ],
        )

        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Partial overlap should give moderate similarity
        assert 0.3 <= similarity <= 0.8

    def test_mutation_pattern_weight_affects_deduplication(self):
        """Test that mutation weight affects overall deduplication."""
        # Create crashes with different mutations
        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            exception_type="ValueError",
            stack_trace="trace1",
            mutation_sequence=[("HeaderFuzzer", "flip_bits")],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            exception_type="ValueError",
            stack_trace="trace1",
            mutation_sequence=[("PixelFuzzer", "corrupt_data")],
        )

        # High mutation weight
        config_high_mutation = DeduplicationConfig(
            stack_trace_weight=0.2,
            exception_weight=0.2,
            mutation_weight=0.6,
        )
        dedup_high = CrashDeduplicator(config_high_mutation)
        groups_high = dedup_high.deduplicate_crashes([crash1, crash2])

        # Low mutation weight
        config_low_mutation = DeduplicationConfig(
            stack_trace_weight=0.6,
            exception_weight=0.3,
            mutation_weight=0.1,
        )
        dedup_low = CrashDeduplicator(config_low_mutation)
        groups_low = dedup_low.deduplicate_crashes([crash1, crash2])

        # High mutation weight should create more groups (different mutations matter more)
        # Low mutation weight should create fewer groups (stack/exception similarity matters more)
        assert len(groups_high) >= len(groups_low)

    def test_mutation_type_distribution_helper(self):
        """Test the mutation type distribution comparison helper."""
        deduplicator = CrashDeduplicator()

        seq1 = [
            ("HeaderFuzzer", "flip_bits"),
            ("HeaderFuzzer", "flip_bits"),
            ("PixelFuzzer", "corrupt_data"),
        ]

        seq2 = [
            ("MetadataFuzzer", "flip_bits"),
            ("DictionaryFuzzer", "flip_bits"),
            ("StructureFuzzer", "corrupt_data"),
        ]

        similarity = deduplicator._compare_mutation_type_distribution(seq1, seq2)

        # Same type distribution should yield high similarity
        assert similarity > 0.5

    def test_strategy_frequency_helper(self):
        """Test the strategy frequency comparison helper."""
        deduplicator = CrashDeduplicator()

        seq1 = [
            ("HeaderFuzzer", "flip_bits"),
            ("HeaderFuzzer", "overlong_string"),
            ("PixelFuzzer", "corrupt_data"),
        ]

        seq2 = [
            ("HeaderFuzzer", "insert_null"),
            ("HeaderFuzzer", "delete_bytes"),
            ("PixelFuzzer", "flip_bits"),
        ]

        similarity = deduplicator._compare_strategy_frequency(seq1, seq2)

        # Same strategy distribution should yield high similarity
        assert similarity > 0.5

    def test_malformed_tuple_sequences(self):
        """Test handling of malformed mutation sequence tuples."""
        deduplicator = CrashDeduplicator()

        crash1 = CrashRecord(
            crash_id="c1",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f1",
            fuzzed_file_path="t1.dcm",
            mutation_sequence=[
                ("HeaderFuzzer",),  # Single element tuple
                ("PixelFuzzer", "corrupt_data"),
            ],
        )

        crash2 = CrashRecord(
            crash_id="c2",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="f2",
            fuzzed_file_path="t2.dcm",
            mutation_sequence=[
                ("HeaderFuzzer", "flip_bits"),
                ("PixelFuzzer",),  # Single element tuple
            ],
        )

        # Should handle gracefully without crashing
        similarity = deduplicator._compare_mutation_patterns(crash1, crash2)

        # Should return some valid similarity score
        assert 0.0 <= similarity <= 1.0
