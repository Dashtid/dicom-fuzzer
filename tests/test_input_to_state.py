"""Comprehensive tests for input-to-state correspondence.

Tests the Redqueen/CMPLOG-style input-to-state analysis
for targeted mutation generation.
"""

import pytest

from dicom_fuzzer.core.input_to_state import (
    ComparisonLog,
    ComparisonRecord,
    ComparisonTracker,
    ComparisonType,
    InputColorizer,
    InputToStateConfig,
    InputToStateManager,
    InputToStateResolver,
)


class TestComparisonType:
    """Tests for ComparisonType enum."""

    def test_all_types_exist(self):
        """Test all comparison types exist."""
        assert ComparisonType.EQUAL
        assert ComparisonType.NOT_EQUAL
        assert ComparisonType.LESS_THAN
        assert ComparisonType.GREATER_THAN
        assert ComparisonType.MEMCMP
        assert ComparisonType.STRCMP


class TestComparisonRecord:
    """Tests for ComparisonRecord class."""

    def test_basic_creation(self):
        """Test basic record creation."""
        record = ComparisonRecord(
            comp_type=ComparisonType.EQUAL,
            operand1=b"\x01\x02",
            operand2=b"\x03\x04",
            size=2,
        )

        assert record.comp_type == ComparisonType.EQUAL
        assert record.operand1 == b"\x01\x02"
        assert record.operand2 == b"\x03\x04"
        assert record.size == 2

    def test_as_integers_valid(self):
        """Test conversion to integers."""
        record = ComparisonRecord(
            comp_type=ComparisonType.EQUAL,
            operand1=b"\x01\x00\x00\x00",
            operand2=b"\x02\x00\x00\x00",
            size=4,
        )

        ints = record.as_integers()
        assert ints is not None
        assert ints == (1, 2)

    def test_as_integers_too_large(self):
        """Test conversion fails for large values."""
        record = ComparisonRecord(
            comp_type=ComparisonType.MEMCMP,
            operand1=b"x" * 16,
            operand2=b"y" * 16,
            size=16,
        )

        assert record.as_integers() is None

    def test_get_solving_values_equal(self):
        """Test solving values for equality."""
        record = ComparisonRecord(
            comp_type=ComparisonType.EQUAL,
            operand1=b"test",
            operand2=b"goal",
            size=4,
        )

        values = record.get_solving_values()
        assert b"goal" in values

    def test_get_solving_values_less_than(self):
        """Test solving values for less-than."""
        record = ComparisonRecord(
            comp_type=ComparisonType.LESS_THAN,
            operand1=b"\x10\x00",
            operand2=b"\x20\x00",
            size=2,
        )

        values = record.get_solving_values()
        assert len(values) > 0
        # Should have a value less than 0x20
        for val in values:
            int_val = int.from_bytes(val, "little")
            assert int_val < 0x20

    def test_get_solving_values_greater_than(self):
        """Test solving values for greater-than."""
        record = ComparisonRecord(
            comp_type=ComparisonType.GREATER_THAN,
            operand1=b"\x10\x00",
            operand2=b"\x05\x00",
            size=2,
        )

        values = record.get_solving_values()
        assert len(values) > 0
        # Should have a value greater than 0x05
        for val in values:
            int_val = int.from_bytes(val, "little")
            assert int_val > 0x05

    def test_get_solving_values_strcmp(self):
        """Test solving values for string comparison."""
        record = ComparisonRecord(
            comp_type=ComparisonType.STRCMP,
            operand1=b"input",
            operand2=b"expected",
            size=8,
        )

        values = record.get_solving_values()
        assert b"expected" in values


class TestComparisonLog:
    """Tests for ComparisonLog class."""

    def test_basic_creation(self):
        """Test basic log creation."""
        log = ComparisonLog(input_hash="abc123")
        assert log.input_hash == "abc123"
        assert len(log.comparisons) == 0

    def test_add_record(self):
        """Test adding records to log."""
        log = ComparisonLog()
        record = ComparisonRecord(
            comp_type=ComparisonType.EQUAL,
            operand1=b"a",
            operand2=b"b",
            size=1,
        )

        log.add(record)

        assert len(log.comparisons) == 1
        assert b"a" in log.unique_values
        assert b"b" in log.unique_values

    def test_get_magic_values(self):
        """Test magic value extraction."""
        log = ComparisonLog()

        # Add some comparisons
        log.add(
            ComparisonRecord(
                comp_type=ComparisonType.EQUAL,
                operand1=b"\x00\x00",  # Should be filtered
                operand2=b"DICM",  # Magic value
                size=4,
            )
        )
        log.add(
            ComparisonRecord(
                comp_type=ComparisonType.EQUAL,
                operand1=b"\xff\xff",  # Should be filtered
                operand2=b"PNG",  # Magic value
                size=3,
            )
        )

        magic = log.get_magic_values(min_size=2)

        assert b"DICM" in magic
        assert b"PNG" in magic
        # All-zero and all-0xFF should be filtered
        assert b"\x00\x00" not in magic


class TestInputToStateConfig:
    """Tests for InputToStateConfig class."""

    def test_default_values(self):
        """Test default configuration."""
        config = InputToStateConfig()

        assert config.max_comparisons == 256
        assert config.colorize_chunk_size == 4
        assert config.enable_arithmetic is True
        assert config.enable_string_solving is True

    def test_custom_values(self):
        """Test custom configuration."""
        config = InputToStateConfig(
            max_comparisons=100,
            colorize_chunk_size=8,
            enable_arithmetic=False,
        )

        assert config.max_comparisons == 100
        assert config.colorize_chunk_size == 8
        assert config.enable_arithmetic is False


class TestComparisonTracker:
    """Tests for ComparisonTracker class."""

    @pytest.fixture
    def tracker(self):
        """Create a tracker instance."""
        return ComparisonTracker()

    def test_start_stop_tracking(self, tracker):
        """Test starting and stopping tracking."""
        tracker.start_tracking("input_hash_1")
        log = tracker.stop_tracking()

        assert log is not None
        assert log.input_hash == "input_hash_1"

    def test_record_comparison(self, tracker):
        """Test recording comparisons."""
        tracker.start_tracking("input_1")
        tracker.record_comparison(
            ComparisonType.EQUAL,
            b"abc",
            b"xyz",
            3,
            "test.py:42",
        )
        log = tracker.stop_tracking()

        assert len(log.comparisons) == 1
        assert log.comparisons[0].comp_type == ComparisonType.EQUAL

    def test_record_int_comparison(self, tracker):
        """Test recording integer comparisons."""
        tracker.start_tracking("input_1")
        tracker.record_int_comparison(
            ComparisonType.LESS_THAN,
            100,
            200,
            size=4,
        )
        log = tracker.stop_tracking()

        assert len(log.comparisons) == 1
        ints = log.comparisons[0].as_integers()
        assert ints == (100, 200)

    def test_record_string_comparison(self, tracker):
        """Test recording string comparisons."""
        tracker.start_tracking("input_1")
        tracker.record_string_comparison(
            "hello",
            "world",
        )
        log = tracker.stop_tracking()

        assert len(log.comparisons) == 1
        assert log.comparisons[0].comp_type == ComparisonType.STRCMP

    def test_max_comparisons_limit(self, tracker):
        """Test max comparisons limit."""
        config = InputToStateConfig(max_comparisons=5)
        tracker = ComparisonTracker(config)

        tracker.start_tracking("input_1")
        for i in range(10):
            tracker.record_comparison(
                ComparisonType.EQUAL,
                bytes([i]),
                bytes([i + 1]),
                1,
            )
        log = tracker.stop_tracking()

        assert len(log.comparisons) == 5

    def test_get_all_magic_values(self, tracker):
        """Test getting all magic values across logs."""
        tracker.start_tracking("input_1")
        tracker.record_comparison(
            ComparisonType.EQUAL,
            b"test",
            b"DICM",
            4,
        )
        tracker.stop_tracking()

        tracker.start_tracking("input_2")
        tracker.record_comparison(
            ComparisonType.EQUAL,
            b"other",
            b"PNG",
            3,
        )
        tracker.stop_tracking()

        magic = tracker.get_all_magic_values()

        assert len(magic) > 0


class TestInputToStateResolver:
    """Tests for InputToStateResolver class."""

    @pytest.fixture
    def resolver(self):
        """Create a resolver instance."""
        return InputToStateResolver()

    def test_analyze_input(self, resolver):
        """Test input analysis."""
        input_data = b"hello world test"
        log = ComparisonLog()
        log.add(
            ComparisonRecord(
                comp_type=ComparisonType.EQUAL,
                operand1=b"hello",
                operand2=b"MAGIC",
                size=5,
            )
        )

        mutations = resolver.analyze_input(input_data, log)

        # Should suggest placing "MAGIC" where "hello" was found
        assert len(mutations) > 0
        assert any(val == b"MAGIC" for _, val in mutations)

    def test_generate_solving_mutations(self, resolver):
        """Test mutation generation."""
        input_data = b"AAAA test BBBB"
        log = ComparisonLog()
        log.add(
            ComparisonRecord(
                comp_type=ComparisonType.EQUAL,
                operand1=b"AAAA",
                operand2=b"PASS",
                size=4,
            )
        )

        mutations = resolver.generate_solving_mutations(input_data, log)

        assert len(mutations) > 0
        # At least one mutation should contain "PASS"
        assert any(b"PASS" in m for m in mutations)

    def test_extract_dictionary(self, resolver):
        """Test dictionary extraction."""
        logs = [
            ComparisonLog(),
            ComparisonLog(),
        ]
        logs[0].add(
            ComparisonRecord(
                comp_type=ComparisonType.STRCMP,
                operand1=b"input",
                operand2=b"password",
                size=8,
            )
        )
        logs[1].add(
            ComparisonRecord(
                comp_type=ComparisonType.EQUAL,
                operand1=b"\x00",
                operand2=b"DICM",
                size=4,
            )
        )

        dictionary = resolver.extract_dictionary(logs)

        assert len(dictionary) > 0
        assert b"DICM" in dictionary

    def test_find_value_positions(self, resolver):
        """Test finding value positions in data."""
        data = b"AABBAABBAA"

        positions = resolver._find_value_positions(data, b"AA")

        assert 0 in positions
        assert 4 in positions
        assert 8 in positions

    def test_apply_mutation(self, resolver):
        """Test applying a mutation."""
        data = b"hello world"

        result = resolver._apply_mutation(data, 0, b"XXXXX")

        assert result == b"XXXXX world"

    def test_apply_mutation_out_of_bounds(self, resolver):
        """Test mutation at invalid offset."""
        data = b"hello"

        result = resolver._apply_mutation(data, 10, b"X")

        assert result is None


class TestInputColorizer:
    """Tests for InputColorizer class."""

    @pytest.fixture
    def colorizer(self):
        """Create a colorizer instance."""
        return InputColorizer()

    def test_initialization(self, colorizer):
        """Test colorizer initialization."""
        assert colorizer.config is not None
        assert colorizer.config.colorize_chunk_size == 4


class TestInputToStateManager:
    """Tests for InputToStateManager class."""

    @pytest.fixture
    def manager(self):
        """Create a manager instance."""
        return InputToStateManager()

    def test_process_execution(self, manager):
        """Test processing an execution."""
        log = manager.process_execution(b"test input", "hash_123")

        assert log is not None
        assert log.input_hash == "hash_123"

    def test_finish_execution(self, manager):
        """Test finishing execution tracking."""
        manager.process_execution(b"test", "hash_1")
        log = manager.finish_execution()

        assert log is not None

    def test_update_dictionary(self, manager):
        """Test dictionary update."""
        logs = [ComparisonLog()]
        logs[0].add(
            ComparisonRecord(
                comp_type=ComparisonType.EQUAL,
                operand1=b"x",
                operand2=b"MAGIC",
                size=5,
            )
        )

        manager.update_dictionary(logs)
        dictionary = manager.get_dictionary()

        assert len(dictionary) > 0

    def test_get_stats(self, manager):
        """Test getting statistics."""
        stats = manager.get_stats()

        assert "total_comparisons" in stats
        assert "unique_values" in stats
        assert "dictionary_size" in stats

    def test_generate_mutations(self, manager):
        """Test mutation generation."""
        input_data = b"test data here"
        log = ComparisonLog()
        log.add(
            ComparisonRecord(
                comp_type=ComparisonType.EQUAL,
                operand1=b"test",
                operand2=b"PASS",
                size=4,
            )
        )

        mutations = manager.generate_mutations(input_data, log)

        assert isinstance(mutations, list)
