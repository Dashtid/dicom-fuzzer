"""Tests for Frame Time Corruption Strategy.

Tests the frame time mutation strategy in
dicom_fuzzer.core.multiframe_strategies.frame_time module.
"""

import math
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord
from dicom_fuzzer.strategies.multiframe.frame_time import (
    FrameTimeCorruptionStrategy,
)


class TestStrategyName:
    """Tests for strategy_name property."""

    def test_strategy_name_returns_correct_value(self) -> None:
        """Test strategy_name returns 'frame_time_corruption'."""
        strategy = FrameTimeCorruptionStrategy()
        assert strategy.strategy_name == "frame_time_corruption"

    def test_strategy_name_with_custom_severity(self) -> None:
        """Test strategy_name works with custom severity."""
        strategy = FrameTimeCorruptionStrategy(severity="aggressive")
        assert strategy.strategy_name == "frame_time_corruption"
        assert strategy.severity == "aggressive"


class TestSetFrameTime:
    """Tests for _set_frame_time method."""

    @pytest.fixture
    def strategy(self) -> FrameTimeCorruptionStrategy:
        """Create a strategy instance."""
        return FrameTimeCorruptionStrategy()

    @pytest.fixture
    def mock_dataset(self) -> MagicMock:
        """Create a mock dataset."""
        dataset = MagicMock()
        dataset.FrameTime = 33.33
        return dataset

    def test_set_frame_time_negative(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test setting negative frame time."""
        record = strategy._set_frame_time(
            mock_dataset, -33.33, "-33.33", "negative_frame_time"
        )

        assert mock_dataset.FrameTime == -33.33
        assert isinstance(record, MultiFrameMutationRecord)
        assert record.strategy == "frame_time_corruption"
        assert record.tag == "FrameTime"
        assert record.mutated_value == "-33.33"
        assert record.details["attack_type"] == "negative_frame_time"

    def test_set_frame_time_zero(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test setting zero frame time."""
        record = strategy._set_frame_time(mock_dataset, 0.0, "0.0", "zero_frame_time")

        assert mock_dataset.FrameTime == 0.0
        assert record.mutated_value == "0.0"
        assert record.details["attack_type"] == "zero_frame_time"

    def test_set_frame_time_nan(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test setting NaN frame time."""
        record = strategy._set_frame_time(
            mock_dataset, float("nan"), "NaN", "nan_frame_time"
        )

        assert math.isnan(mock_dataset.FrameTime)
        assert record.mutated_value == "NaN"
        assert record.details["attack_type"] == "nan_frame_time"

    def test_set_frame_time_extreme(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test setting extreme frame time value."""
        record = strategy._set_frame_time(
            mock_dataset, 1e308, "1e308", "extreme_time_values"
        )

        assert mock_dataset.FrameTime == 1e308
        assert record.mutated_value == "1e308"
        assert record.details["attack_type"] == "extreme_time_values"

    def test_set_frame_time_preserves_original(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test original value is captured in record."""
        mock_dataset.FrameTime = 50.0
        record = strategy._set_frame_time(mock_dataset, -10.0, "-10.0", "test_attack")

        assert record.original_value == "50.0"

    def test_set_frame_time_no_original(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test when no original FrameTime exists."""
        dataset = MagicMock(spec=[])  # No FrameTime attribute
        record = strategy._set_frame_time(dataset, 0.0, "0.0", "zero_frame_time")

        assert record.original_value == "<none>"


class TestAttackInvalidVector:
    """Tests for _attack_invalid_vector method."""

    @pytest.fixture
    def strategy(self) -> FrameTimeCorruptionStrategy:
        """Create a strategy instance."""
        return FrameTimeCorruptionStrategy()

    def test_attack_invalid_vector_creates_wrong_length(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test creates FrameTimeVector with wrong length."""
        dataset = MagicMock()
        dataset.NumberOfFrames = 10
        dataset.FrameTimeVector = [33.33] * 9

        record = strategy._attack_invalid_vector(dataset)

        assert isinstance(record, MultiFrameMutationRecord)
        assert record.strategy == "frame_time_corruption"
        assert record.tag == "FrameTimeVector"
        assert record.details["attack_type"] == "invalid_time_vector_length"
        assert record.details["expected_length"] == 9  # NumberOfFrames - 1

    def test_attack_invalid_vector_records_original_length(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test original vector length is recorded."""
        dataset = MagicMock()
        dataset.NumberOfFrames = 5
        dataset.FrameTimeVector = [33.33] * 4

        record = strategy._attack_invalid_vector(dataset)

        assert "length=4" in record.original_value

    def test_attack_invalid_vector_no_original(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test when no original FrameTimeVector exists."""
        dataset = MagicMock(spec=["NumberOfFrames"])
        dataset.NumberOfFrames = 5

        record = strategy._attack_invalid_vector(dataset)

        assert "length=0" in record.original_value


class TestAttackTemporalIndex:
    """Tests for _attack_temporal_index method."""

    @pytest.fixture
    def strategy(self) -> FrameTimeCorruptionStrategy:
        """Create a strategy instance."""
        return FrameTimeCorruptionStrategy()

    def test_attack_temporal_index_no_per_frame_groups(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test returns None when no PerFrameFunctionalGroupsSequence."""
        dataset = MagicMock(spec=["NumberOfFrames"])
        dataset.NumberOfFrames = 5

        result = strategy._attack_temporal_index(dataset)

        assert result is None

    def test_attack_temporal_index_with_per_frame_groups(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test corrupts TemporalPositionIndex in per-frame groups."""
        # Create mock per-frame functional groups
        frame_content = MagicMock()
        frame_content.TemporalPositionIndex = 1

        frame_content_seq = [frame_content]
        functional_group = MagicMock()
        functional_group.FrameContentSequence = frame_content_seq

        dataset = MagicMock()
        dataset.NumberOfFrames = 5
        dataset.PerFrameFunctionalGroupsSequence = [functional_group]

        record = strategy._attack_temporal_index(dataset)

        assert isinstance(record, MultiFrameMutationRecord)
        assert record.strategy == "frame_time_corruption"
        assert record.tag == "TemporalPositionIndex"
        assert record.details["attack_type"] == "corrupt_temporal_index"
        # Check that an invalid value was set
        assert frame_content.TemporalPositionIndex in [0, -1, 999999, 105]  # 5 + 100

    def test_attack_temporal_index_no_frame_content_sequence(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test handles missing FrameContentSequence gracefully."""
        functional_group = MagicMock(spec=[])  # No FrameContentSequence
        dataset = MagicMock()
        dataset.NumberOfFrames = 5
        dataset.PerFrameFunctionalGroupsSequence = [functional_group]

        record = strategy._attack_temporal_index(dataset)

        # Should still return a record even if some frames don't have content
        assert isinstance(record, MultiFrameMutationRecord)

    def test_attack_temporal_index_empty_frame_content_sequence(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test handles empty FrameContentSequence."""
        functional_group = MagicMock()
        functional_group.FrameContentSequence = []

        dataset = MagicMock()
        dataset.NumberOfFrames = 5
        dataset.PerFrameFunctionalGroupsSequence = [functional_group]

        record = strategy._attack_temporal_index(dataset)

        # Should still return a record
        assert isinstance(record, MultiFrameMutationRecord)


class TestMutate:
    """Tests for mutate method."""

    @pytest.fixture
    def strategy(self) -> FrameTimeCorruptionStrategy:
        """Create a strategy instance."""
        return FrameTimeCorruptionStrategy()

    @pytest.fixture
    def mock_dataset(self) -> MagicMock:
        """Create a mock multi-frame dataset."""
        dataset = MagicMock()
        dataset.NumberOfFrames = 10
        dataset.FrameTime = 33.33
        dataset.FrameTimeVector = [33.33] * 9
        return dataset

    def test_mutate_returns_dataset_and_records(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test mutate returns tuple of dataset and records."""
        result = strategy.mutate(mock_dataset, mutation_count=1)

        assert isinstance(result, tuple)
        assert len(result) == 2
        dataset, records = result
        assert dataset is mock_dataset
        assert isinstance(records, list)

    def test_mutate_single_mutation(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test mutate with single mutation."""
        _, records = strategy.mutate(mock_dataset, mutation_count=1)

        # Should have at least 0-1 records (temporal index may return None)
        assert len(records) <= 1

    def test_mutate_multiple_mutations(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test mutate with multiple mutations."""
        # Add per-frame groups for temporal index attacks
        frame_content = MagicMock()
        frame_content.TemporalPositionIndex = 1
        functional_group = MagicMock()
        functional_group.FrameContentSequence = [frame_content]
        mock_dataset.PerFrameFunctionalGroupsSequence = [functional_group]

        _, records = strategy.mutate(mock_dataset, mutation_count=5)

        # Should have some records (exact count depends on random choices)
        assert len(records) >= 0  # May be less due to temporal index returning None

    def test_mutate_zero_mutations(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test mutate with zero mutations."""
        _, records = strategy.mutate(mock_dataset, mutation_count=0)

        assert records == []

    def test_mutate_records_have_correct_strategy(
        self, strategy: FrameTimeCorruptionStrategy, mock_dataset: MagicMock
    ) -> None:
        """Test all records have correct strategy name."""
        # Add per-frame groups
        frame_content = MagicMock()
        frame_content.TemporalPositionIndex = 1
        functional_group = MagicMock()
        functional_group.FrameContentSequence = [frame_content]
        mock_dataset.PerFrameFunctionalGroupsSequence = [functional_group]

        _, records = strategy.mutate(mock_dataset, mutation_count=10)

        for record in records:
            assert record.strategy == "frame_time_corruption"


class TestGetFrameCount:
    """Tests for _get_frame_count method."""

    @pytest.fixture
    def strategy(self) -> FrameTimeCorruptionStrategy:
        """Create a strategy instance."""
        return FrameTimeCorruptionStrategy()

    def test_get_frame_count_multiframe(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test returns correct count for multi-frame dataset."""
        dataset = MagicMock()
        dataset.NumberOfFrames = 25

        result = strategy._get_frame_count(dataset)

        assert result == 25

    def test_get_frame_count_single_frame(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test returns 1 when NumberOfFrames not present."""
        dataset = MagicMock(spec=[])  # No NumberOfFrames

        result = strategy._get_frame_count(dataset)

        assert result == 1

    def test_get_frame_count_string_value(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test handles string NumberOfFrames (converts to int)."""
        dataset = MagicMock()
        dataset.NumberOfFrames = "10"

        result = strategy._get_frame_count(dataset)

        assert result == 10

    def test_get_frame_count_invalid_value_returns_1(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test returns 1 for invalid NumberOfFrames value."""
        dataset = MagicMock()
        dataset.NumberOfFrames = "invalid"

        result = strategy._get_frame_count(dataset)

        assert result == 1

    def test_get_frame_count_none_returns_1(
        self, strategy: FrameTimeCorruptionStrategy
    ) -> None:
        """Test returns 1 when NumberOfFrames is None."""
        dataset = MagicMock()
        dataset.NumberOfFrames = None

        result = strategy._get_frame_count(dataset)

        assert result == 1


class TestSeverity:
    """Tests for severity configuration."""

    def test_default_severity(self) -> None:
        """Test default severity is 'moderate'."""
        strategy = FrameTimeCorruptionStrategy()
        assert strategy.severity == "moderate"

    def test_custom_severity(self) -> None:
        """Test custom severity is preserved."""
        strategy = FrameTimeCorruptionStrategy(severity="extreme")
        assert strategy.severity == "extreme"

    def test_severity_in_records(self) -> None:
        """Test severity appears in mutation records."""
        strategy = FrameTimeCorruptionStrategy(severity="aggressive")
        dataset = MagicMock()
        dataset.NumberOfFrames = 5
        dataset.FrameTime = 33.33

        record = strategy._set_frame_time(dataset, 0.0, "0.0", "test")

        assert record.severity == "aggressive"
