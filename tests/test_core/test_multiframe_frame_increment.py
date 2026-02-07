"""Tests for Frame Increment Strategy.

Tests the frame increment mutation strategy in
dicom_fuzzer.core.multiframe_strategies.frame_increment module.
"""

from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.attacks.multiframe.frame_increment import (
    FrameIncrementStrategy,
)


class TestStrategyName:
    """Tests for strategy_name property."""

    def test_strategy_name_returns_correct_value(self) -> None:
        """Test strategy_name returns 'frame_increment_invalid'."""
        strategy = FrameIncrementStrategy()
        assert strategy.strategy_name == "frame_increment_invalid"

    def test_strategy_name_with_custom_severity(self) -> None:
        """Test strategy_name works with custom severity."""
        strategy = FrameIncrementStrategy(severity="aggressive")
        assert strategy.strategy_name == "frame_increment_invalid"
        assert strategy.severity == "aggressive"


class TestMutateNonexistentTag:
    """Tests for nonexistent_tag attack type."""

    @pytest.fixture
    def strategy(self) -> FrameIncrementStrategy:
        """Create a strategy instance."""
        return FrameIncrementStrategy()

    def test_nonexistent_tag_attack(self, strategy: FrameIncrementStrategy) -> None:
        """Test nonexistent_tag attack sets (0x9999, 0x9999)."""
        dataset = MagicMock()
        dataset.FrameIncrementPointer = (0x0018, 0x1063)

        with patch("random.choice", return_value="nonexistent_tag"):
            _, records = strategy.mutate(dataset, mutation_count=1)

        assert len(records) == 1
        assert records[0].strategy == "frame_increment_invalid"
        assert records[0].tag == "FrameIncrementPointer"
        assert records[0].mutated_value == "(9999,9999)"
        assert records[0].details["attack_type"] == "nonexistent_tag"
        assert dataset.FrameIncrementPointer == (0x9999, 0x9999)

    def test_nonexistent_tag_preserves_original(
        self, strategy: FrameIncrementStrategy
    ) -> None:
        """Test original value is captured in record."""
        dataset = MagicMock()
        dataset.FrameIncrementPointer = (0x0018, 0x1063)

        with patch("random.choice", return_value="nonexistent_tag"):
            _, records = strategy.mutate(dataset, mutation_count=1)

        assert (
            "(24, 4195)" in records[0].original_value
            or "0x" in records[0].original_value
            or "18" in records[0].original_value
        )


class TestMutateInvalidFormat:
    """Tests for invalid_format attack type."""

    @pytest.fixture
    def strategy(self) -> FrameIncrementStrategy:
        """Create a strategy instance."""
        return FrameIncrementStrategy()

    def test_invalid_format_attack(self, strategy: FrameIncrementStrategy) -> None:
        """Test invalid_format attack sets (0xFFFF, 0xFFFF)."""
        dataset = MagicMock()
        dataset.FrameIncrementPointer = None

        with patch("random.choice", return_value="invalid_format"):
            _, records = strategy.mutate(dataset, mutation_count=1)

        assert len(records) == 1
        assert records[0].mutated_value == "(FFFF,FFFF)"
        assert records[0].details["attack_type"] == "invalid_format"
        assert dataset.FrameIncrementPointer == (0xFFFF, 0xFFFF)


class TestMutatePointToPixelData:
    """Tests for point_to_pixel_data attack type."""

    @pytest.fixture
    def strategy(self) -> FrameIncrementStrategy:
        """Create a strategy instance."""
        return FrameIncrementStrategy()

    def test_point_to_pixel_data_attack(self, strategy: FrameIncrementStrategy) -> None:
        """Test point_to_pixel_data attack sets (0x7FE0, 0x0010)."""
        dataset = MagicMock()
        dataset.FrameIncrementPointer = None

        with patch("random.choice", return_value="point_to_pixel_data"):
            _, records = strategy.mutate(dataset, mutation_count=1)

        assert len(records) == 1
        assert records[0].mutated_value == "(7FE0,0010) [PixelData]"
        assert records[0].details["attack_type"] == "point_to_pixel_data"
        assert dataset.FrameIncrementPointer == (0x7FE0, 0x0010)


class TestMutateMultipleInvalid:
    """Tests for multiple_invalid attack type."""

    @pytest.fixture
    def strategy(self) -> FrameIncrementStrategy:
        """Create a strategy instance."""
        return FrameIncrementStrategy()

    def test_multiple_invalid_attack(self, strategy: FrameIncrementStrategy) -> None:
        """Test multiple_invalid attack sets list of invalid pointers."""
        dataset = MagicMock()
        dataset.FrameIncrementPointer = None

        with patch("random.choice", return_value="multiple_invalid"):
            _, records = strategy.mutate(dataset, mutation_count=1)

        assert len(records) == 1
        assert "[(0,0), (FFFF,FFFF), (7FE0,0010)]" in records[0].mutated_value
        assert records[0].details["attack_type"] == "multiple_invalid"
        assert dataset.FrameIncrementPointer == [
            (0x0000, 0x0000),
            (0xFFFF, 0xFFFF),
            (0x7FE0, 0x0010),
        ]


class TestMutateGeneral:
    """General tests for mutate method."""

    @pytest.fixture
    def strategy(self) -> FrameIncrementStrategy:
        """Create a strategy instance."""
        return FrameIncrementStrategy()

    def test_mutate_returns_dataset_and_records(
        self, strategy: FrameIncrementStrategy
    ) -> None:
        """Test mutate returns tuple of dataset and records."""
        dataset = MagicMock()

        result = strategy.mutate(dataset, mutation_count=1)

        assert isinstance(result, tuple)
        assert len(result) == 2
        returned_dataset, records = result
        assert returned_dataset is dataset
        assert isinstance(records, list)

    def test_mutate_multiple_mutations(self, strategy: FrameIncrementStrategy) -> None:
        """Test mutate with multiple mutations."""
        dataset = MagicMock()

        _, records = strategy.mutate(dataset, mutation_count=5)

        assert len(records) == 5

    def test_mutate_zero_mutations(self, strategy: FrameIncrementStrategy) -> None:
        """Test mutate with zero mutations."""
        dataset = MagicMock()

        _, records = strategy.mutate(dataset, mutation_count=0)

        assert records == []

    def test_mutate_no_original_value(self, strategy: FrameIncrementStrategy) -> None:
        """Test mutate when no original FrameIncrementPointer exists."""
        dataset = MagicMock(spec=[])  # No FrameIncrementPointer

        with patch("random.choice", return_value="nonexistent_tag"):
            _, records = strategy.mutate(dataset, mutation_count=1)

        assert records[0].original_value == "<none>"

    def test_all_attack_types_covered(self, strategy: FrameIncrementStrategy) -> None:
        """Test all attack types can be generated."""
        dataset = MagicMock()
        attack_types = [
            "nonexistent_tag",
            "invalid_format",
            "point_to_pixel_data",
            "multiple_invalid",
        ]

        for attack_type in attack_types:
            with patch("random.choice", return_value=attack_type):
                _, records = strategy.mutate(dataset, mutation_count=1)
                assert records[0].details["attack_type"] == attack_type


class TestSeverity:
    """Tests for severity configuration."""

    def test_default_severity(self) -> None:
        """Test default severity is 'moderate'."""
        strategy = FrameIncrementStrategy()
        assert strategy.severity == "moderate"

    def test_custom_severity(self) -> None:
        """Test custom severity is preserved."""
        strategy = FrameIncrementStrategy(severity="extreme")
        assert strategy.severity == "extreme"

    def test_severity_in_records(self) -> None:
        """Test severity appears in mutation records."""
        strategy = FrameIncrementStrategy(severity="aggressive")
        dataset = MagicMock()

        with patch("random.choice", return_value="nonexistent_tag"):
            _, records = strategy.mutate(dataset, mutation_count=1)

        assert records[0].severity == "aggressive"
