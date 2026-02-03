"""Tests for multiframe mutation strategies."""

from __future__ import annotations

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord
from dicom_fuzzer.strategies.multiframe import (
    DimensionOverflowStrategy,
    FrameCountMismatchStrategy,
    FrameIncrementStrategy,
    FrameTimeCorruptionStrategy,
    FunctionalGroupStrategy,
    MutationStrategyBase,
    PerFrameDimensionStrategy,
    PixelDataTruncationStrategy,
    SharedGroupStrategy,
)


class TestMutationStrategyBase:
    """Tests for MutationStrategyBase abstract class."""

    def test_base_is_abstract(self) -> None:
        """Verify MutationStrategyBase cannot be instantiated directly."""
        with pytest.raises(TypeError):
            MutationStrategyBase()  # type: ignore

    def test_all_strategies_inherit_from_base(self) -> None:
        """Verify all strategies inherit from MutationStrategyBase."""
        strategies = [
            FrameCountMismatchStrategy,
            FrameTimeCorruptionStrategy,
            PerFrameDimensionStrategy,
            SharedGroupStrategy,
            FrameIncrementStrategy,
            DimensionOverflowStrategy,
            FunctionalGroupStrategy,
            PixelDataTruncationStrategy,
        ]
        for strategy_cls in strategies:
            assert issubclass(strategy_cls, MutationStrategyBase)


class TestFrameCountMismatchStrategy:
    """Tests for FrameCountMismatchStrategy."""

    def test_strategy_name(self) -> None:
        """Test strategy name property."""
        strategy = FrameCountMismatchStrategy()
        assert strategy.strategy_name == "frame_count_mismatch"

    def test_mutate_returns_records(self) -> None:
        """Test mutate returns mutation records."""
        dataset = Dataset()
        dataset.NumberOfFrames = 10
        dataset.Rows = 64
        dataset.Columns = 64
        dataset.BitsAllocated = 16
        dataset.SamplesPerPixel = 1
        dataset.PixelData = b"\x00" * (64 * 64 * 2 * 10)

        strategy = FrameCountMismatchStrategy(severity="moderate")
        mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert isinstance(records, list)
        assert len(records) >= 1
        assert all(isinstance(r, MultiFrameMutationRecord) for r in records)
        assert records[0].strategy == "frame_count_mismatch"


class TestFrameTimeCorruptionStrategy:
    """Tests for FrameTimeCorruptionStrategy."""

    def test_strategy_name(self) -> None:
        """Test strategy name property."""
        strategy = FrameTimeCorruptionStrategy()
        assert strategy.strategy_name == "frame_time_corruption"

    def test_mutate_returns_records(self) -> None:
        """Test mutate returns mutation records."""
        from unittest.mock import patch

        dataset = Dataset()
        dataset.NumberOfFrames = 5
        dataset.FrameTime = 33.33

        strategy = FrameTimeCorruptionStrategy(severity="moderate")
        # Force a mutation type that always creates a record (not corrupt_temporal_index
        # which requires PerFrameFunctionalGroupsSequence to create records)
        with patch("random.choice", return_value="negative_frame_time"):
            mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert isinstance(records, list)
        assert len(records) >= 1


class TestPerFrameDimensionStrategy:
    """Tests for PerFrameDimensionStrategy."""

    def test_strategy_name(self) -> None:
        """Test strategy name property."""
        strategy = PerFrameDimensionStrategy()
        assert strategy.strategy_name == "per_frame_dimension_mismatch"

    def test_creates_per_frame_groups_if_missing(self) -> None:
        """Test strategy creates per-frame groups if missing."""
        dataset = Dataset()
        dataset.NumberOfFrames = 3

        strategy = PerFrameDimensionStrategy(severity="moderate")
        mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert hasattr(mutated, "PerFrameFunctionalGroupsSequence")


class TestSharedGroupStrategy:
    """Tests for SharedGroupStrategy."""

    def test_strategy_name(self) -> None:
        """Test strategy name property."""
        strategy = SharedGroupStrategy()
        assert strategy.strategy_name == "shared_group_corruption"

    def test_mutate_returns_records(self) -> None:
        """Test mutate returns mutation records."""
        dataset = Dataset()
        dataset.SharedFunctionalGroupsSequence = Sequence([Dataset()])

        strategy = SharedGroupStrategy(severity="moderate")
        mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert isinstance(records, list)
        assert len(records) >= 1


class TestFrameIncrementStrategy:
    """Tests for FrameIncrementStrategy."""

    def test_strategy_name(self) -> None:
        """Test strategy name property."""
        strategy = FrameIncrementStrategy()
        assert strategy.strategy_name == "frame_increment_invalid"

    def test_mutate_returns_records(self) -> None:
        """Test mutate returns mutation records."""
        dataset = Dataset()

        strategy = FrameIncrementStrategy(severity="moderate")
        mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert isinstance(records, list)
        assert len(records) >= 1


class TestDimensionOverflowStrategy:
    """Tests for DimensionOverflowStrategy."""

    def test_strategy_name(self) -> None:
        """Test strategy name property."""
        strategy = DimensionOverflowStrategy()
        assert strategy.strategy_name == "dimension_overflow"

    def test_mutate_returns_records(self) -> None:
        """Test mutate returns mutation records."""
        dataset = Dataset()
        dataset.NumberOfFrames = 10
        dataset.Rows = 256
        dataset.Columns = 256

        strategy = DimensionOverflowStrategy(severity="extreme")
        mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert isinstance(records, list)
        assert len(records) >= 1


class TestFunctionalGroupStrategy:
    """Tests for FunctionalGroupStrategy."""

    def test_strategy_name(self) -> None:
        """Test strategy name property."""
        strategy = FunctionalGroupStrategy()
        assert strategy.strategy_name == "functional_group_attack"

    def test_mutate_returns_records(self) -> None:
        """Test mutate returns mutation records."""
        dataset = Dataset()
        dataset.NumberOfFrames = 5
        dataset.PerFrameFunctionalGroupsSequence = Sequence(
            [Dataset() for _ in range(5)]
        )

        strategy = FunctionalGroupStrategy(severity="aggressive")
        mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert isinstance(records, list)
        assert len(records) >= 1


class TestPixelDataTruncationStrategy:
    """Tests for PixelDataTruncationStrategy."""

    def test_strategy_name(self) -> None:
        """Test strategy name property."""
        strategy = PixelDataTruncationStrategy()
        assert strategy.strategy_name == "pixel_data_truncation"

    def test_mutate_with_pixel_data(self) -> None:
        """Test mutate with pixel data present."""
        dataset = Dataset()
        dataset.Rows = 64
        dataset.Columns = 64
        dataset.BitsAllocated = 16
        dataset.SamplesPerPixel = 1
        dataset.NumberOfFrames = 5
        dataset.PixelData = b"\x00" * (64 * 64 * 2 * 5)

        strategy = PixelDataTruncationStrategy(severity="moderate")
        mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert isinstance(records, list)
        assert len(records) >= 1

    def test_mutate_without_pixel_data(self) -> None:
        """Test mutate without pixel data returns empty records."""
        dataset = Dataset()
        dataset.NumberOfFrames = 5

        strategy = PixelDataTruncationStrategy(severity="moderate")
        mutated, records = strategy.mutate(dataset, mutation_count=1)

        assert records == []


class TestStrategySeverityLevels:
    """Tests for strategy severity level handling."""

    @pytest.mark.parametrize(
        "strategy_cls",
        [
            pytest.param(FrameCountMismatchStrategy, id="frame_count_mismatch"),
            pytest.param(FrameTimeCorruptionStrategy, id="frame_time_corruption"),
            pytest.param(PerFrameDimensionStrategy, id="per_frame_dimension"),
            pytest.param(SharedGroupStrategy, id="shared_group"),
            pytest.param(FrameIncrementStrategy, id="frame_increment"),
            pytest.param(DimensionOverflowStrategy, id="dimension_overflow"),
            pytest.param(FunctionalGroupStrategy, id="functional_group"),
            pytest.param(PixelDataTruncationStrategy, id="pixel_truncation"),
        ],
    )
    def test_strategy_accepts_severity(self, strategy_cls: type) -> None:
        """Test all strategies accept severity parameter."""
        for severity in ["minimal", "moderate", "aggressive", "extreme"]:
            strategy = strategy_cls(severity=severity)
            assert strategy.severity == severity

    @pytest.mark.parametrize(
        "strategy_cls",
        [
            pytest.param(FrameCountMismatchStrategy, id="frame_count_mismatch"),
            pytest.param(FrameTimeCorruptionStrategy, id="frame_time_corruption"),
            pytest.param(PerFrameDimensionStrategy, id="per_frame_dimension"),
            pytest.param(SharedGroupStrategy, id="shared_group"),
            pytest.param(FrameIncrementStrategy, id="frame_increment"),
            pytest.param(DimensionOverflowStrategy, id="dimension_overflow"),
            pytest.param(FunctionalGroupStrategy, id="functional_group"),
            pytest.param(PixelDataTruncationStrategy, id="pixel_truncation"),
        ],
    )
    def test_strategy_default_severity(self, strategy_cls: type) -> None:
        """Test all strategies default to moderate severity."""
        strategy = strategy_cls()
        assert strategy.severity == "moderate"


class TestStrategyImports:
    """Test strategy imports from different locations."""

    def test_import_from_strategies_package(self) -> None:
        """Verify imports from multiframe_strategies package."""
        from dicom_fuzzer.strategies.multiframe import (
            DimensionOverflowStrategy,
            FrameCountMismatchStrategy,
            FrameIncrementStrategy,
            FrameTimeCorruptionStrategy,
            FunctionalGroupStrategy,
            MutationStrategyBase,
            PerFrameDimensionStrategy,
            PixelDataTruncationStrategy,
            SharedGroupStrategy,
        )

        assert MutationStrategyBase is not None
        assert FrameCountMismatchStrategy is not None
        assert FrameTimeCorruptionStrategy is not None
        assert PerFrameDimensionStrategy is not None
        assert SharedGroupStrategy is not None
        assert FrameIncrementStrategy is not None
        assert DimensionOverflowStrategy is not None
        assert FunctionalGroupStrategy is not None
        assert PixelDataTruncationStrategy is not None
