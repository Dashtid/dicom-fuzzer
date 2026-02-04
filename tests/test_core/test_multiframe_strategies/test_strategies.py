"""Tests for multiframe mutation strategies."""

from __future__ import annotations

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.multiframe import (
    DimensionIndexStrategy,
    DimensionOverflowStrategy,
    EncapsulatedPixelStrategy,
    FrameCountMismatchStrategy,
    FrameIncrementStrategy,
    FrameTimeCorruptionStrategy,
    FunctionalGroupStrategy,
    MutationStrategyBase,
    PerFrameDimensionStrategy,
    PixelDataTruncationStrategy,
    SharedGroupStrategy,
)
from dicom_fuzzer.core.mutation.multiframe_types import MultiFrameMutationRecord


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
        from dicom_fuzzer.attacks.multiframe import (
            DimensionIndexStrategy,
            DimensionOverflowStrategy,
            EncapsulatedPixelStrategy,
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
        assert EncapsulatedPixelStrategy is not None
        assert DimensionIndexStrategy is not None


# --- Base class helper tests ---


class TestBaseClassHelpers:
    """Tests for shared helpers in MutationStrategyBase."""

    def test_get_frame_count_with_frames(self) -> None:
        """Test _get_frame_count returns correct count."""
        strategy = FrameCountMismatchStrategy()
        ds = Dataset()
        ds.NumberOfFrames = 10
        assert strategy._get_frame_count(ds) == 10

    def test_get_frame_count_no_attribute(self) -> None:
        """Test _get_frame_count returns 1 when attribute missing."""
        strategy = FrameCountMismatchStrategy()
        ds = Dataset()
        assert strategy._get_frame_count(ds) == 1

    def test_calculate_frame_size(self) -> None:
        """Test _calculate_frame_size calculation."""
        strategy = PixelDataTruncationStrategy()
        ds = Dataset()
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        assert strategy._calculate_frame_size(ds) == 64 * 64 * 2

    def test_calculate_frame_size_rgb(self) -> None:
        """Test _calculate_frame_size with RGB (3 samples per pixel)."""
        strategy = PixelDataTruncationStrategy()
        ds = Dataset()
        ds.Rows = 128
        ds.Columns = 128
        ds.BitsAllocated = 8
        ds.SamplesPerPixel = 3
        assert strategy._calculate_frame_size(ds) == 128 * 128 * 1 * 3

    def test_calculate_frame_size_no_dims(self) -> None:
        """Test _calculate_frame_size returns 0 when dimensions missing."""
        strategy = PixelDataTruncationStrategy()
        ds = Dataset()
        assert strategy._calculate_frame_size(ds) == 0


# --- Record-loss bug fix tests ---


class TestRecordLossFixes:
    """Tests verifying the record-loss bugs are fixed."""

    def test_pixel_truncation_fallback_on_zero_frame_size(self) -> None:
        """Test truncate_mid_frame fallback when frame_size is 0."""
        from unittest.mock import patch

        strategy = PixelDataTruncationStrategy()
        ds = Dataset()
        ds.PixelData = b"\x00" * 100  # No Rows/Cols -> frame_size=0

        with patch("random.choice", return_value="truncate_mid_frame"):
            _, records = strategy.mutate(ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "truncate_mid_frame_fallback"

    def test_pixel_truncation_fallback_on_small_data(self) -> None:
        """Test truncate_mid_frame fallback when data <= frame_size."""
        from unittest.mock import patch

        strategy = PixelDataTruncationStrategy()
        ds = Dataset()
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        # PixelData exactly one frame -- can't cut mid-frame
        ds.PixelData = b"\x00" * (64 * 64 * 2)

        with patch("random.choice", return_value="truncate_mid_frame"):
            _, records = strategy.mutate(ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "truncate_mid_frame_fallback"

    def test_frame_time_fallback_no_per_frame_groups(self) -> None:
        """Test corrupt_temporal_index fallback when no per-frame groups."""
        from unittest.mock import patch

        strategy = FrameTimeCorruptionStrategy()
        ds = Dataset()
        ds.NumberOfFrames = 5
        ds.FrameTime = 33.33
        # No PerFrameFunctionalGroupsSequence

        with patch("random.choice", return_value="corrupt_temporal_index"):
            _, records = strategy.mutate(ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "negative_frame_time"

    def test_pixel_truncation_always_produces_records(self) -> None:
        """Test that every mutation_count produces a record."""
        strategy = PixelDataTruncationStrategy()
        ds = Dataset()
        ds.PixelData = b"\x00" * 50  # Small data, no dims

        _, records = strategy.mutate(ds, mutation_count=5)
        assert len(records) == 5

    def test_frame_time_always_produces_records(self) -> None:
        """Test that every mutation_count produces a record."""
        strategy = FrameTimeCorruptionStrategy()
        ds = Dataset()
        ds.NumberOfFrames = 3
        # No PerFrameFunctionalGroupsSequence

        _, records = strategy.mutate(ds, mutation_count=10)
        assert len(records) == 10


# --- Per-attack-type tests for under-tested strategies ---


class TestPixelDataTruncationAttackTypes:
    """Individual attack type tests for PixelDataTruncationStrategy."""

    @pytest.fixture
    def multiframe_ds(self) -> Dataset:
        ds = Dataset()
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        ds.NumberOfFrames = 5
        ds.PixelData = b"\x00" * (64 * 64 * 2 * 5)
        return ds

    def test_truncate_mid_frame(self, multiframe_ds: Dataset) -> None:
        """Test truncate_mid_frame cuts data mid-frame."""
        from unittest.mock import patch

        original_size = len(multiframe_ds.PixelData)
        strategy = PixelDataTruncationStrategy()

        with patch("random.choice", return_value="truncate_mid_frame"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "truncate_mid_frame"
        assert len(multiframe_ds.PixelData) < original_size

    def test_truncate_partial(self, multiframe_ds: Dataset) -> None:
        """Test truncate_partial leaves only partial first frame."""
        from unittest.mock import patch

        original_size = len(multiframe_ds.PixelData)
        strategy = PixelDataTruncationStrategy()

        with patch("random.choice", return_value="truncate_partial"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "truncate_partial"
        assert len(multiframe_ds.PixelData) < original_size

    def test_extra_bytes(self, multiframe_ds: Dataset) -> None:
        """Test extra_bytes adds data after declared frames."""
        from unittest.mock import patch

        original_size = len(multiframe_ds.PixelData)
        strategy = PixelDataTruncationStrategy()

        with patch("random.choice", return_value="extra_bytes"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "extra_bytes"
        assert len(multiframe_ds.PixelData) == original_size + 1000

    def test_empty_pixel_data(self, multiframe_ds: Dataset) -> None:
        """Test empty_pixel_data clears pixel data."""
        from unittest.mock import patch

        strategy = PixelDataTruncationStrategy()

        with patch("random.choice", return_value="empty_pixel_data"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "empty_pixel_data"
        assert multiframe_ds.PixelData == b""

    def test_single_byte(self, multiframe_ds: Dataset) -> None:
        """Test single_byte reduces pixel data to one byte."""
        from unittest.mock import patch

        strategy = PixelDataTruncationStrategy()

        with patch("random.choice", return_value="single_byte"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "single_byte"
        assert multiframe_ds.PixelData == b"\x00"


class TestSharedGroupAttackTypes:
    """Individual attack type tests for SharedGroupStrategy."""

    @pytest.fixture
    def ds_with_sfg(self) -> Dataset:
        ds = Dataset()
        ds.NumberOfFrames = 5
        sfg = Dataset()
        pm = Dataset()
        pm.PixelSpacing = [0.5, 0.5]
        pm.SliceThickness = 5.0
        sfg.PixelMeasuresSequence = Sequence([pm])
        po = Dataset()
        po.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        sfg.PlaneOrientationSequence = Sequence([po])
        ds.SharedFunctionalGroupsSequence = Sequence([sfg])
        ds.PerFrameFunctionalGroupsSequence = Sequence([Dataset() for _ in range(5)])
        return ds

    def test_delete_shared_groups(self, ds_with_sfg: Dataset) -> None:
        """Test delete_shared_groups removes the sequence."""
        from unittest.mock import patch

        strategy = SharedGroupStrategy()
        with patch("random.choice", return_value="delete_shared_groups"):
            _, records = strategy.mutate(ds_with_sfg, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "delete_shared_groups"
        assert not hasattr(ds_with_sfg, "SharedFunctionalGroupsSequence")

    def test_empty_shared_groups(self, ds_with_sfg: Dataset) -> None:
        """Test empty_shared_groups creates empty sequence."""
        from unittest.mock import patch

        strategy = SharedGroupStrategy()
        with patch("random.choice", return_value="empty_shared_groups"):
            _, records = strategy.mutate(ds_with_sfg, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "empty_shared_groups"
        assert len(ds_with_sfg.SharedFunctionalGroupsSequence) == 0

    def test_corrupt_pixel_measures(self, ds_with_sfg: Dataset) -> None:
        """Test corrupt_pixel_measures sets invalid spacing/thickness."""
        from unittest.mock import patch

        strategy = SharedGroupStrategy()
        with patch("random.choice", return_value="corrupt_pixel_measures"):
            _, records = strategy.mutate(ds_with_sfg, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "corrupt_pixel_measures"
        sfg = ds_with_sfg.SharedFunctionalGroupsSequence[0]
        assert sfg.PixelMeasuresSequence[0].PixelSpacing == [0.0, 0.0]
        assert sfg.PixelMeasuresSequence[0].SliceThickness == -1.0

    def test_invalid_orientation(self, ds_with_sfg: Dataset) -> None:
        """Test invalid_orientation sets NaN orientation values."""
        import math
        from unittest.mock import patch

        strategy = SharedGroupStrategy()
        with patch("random.choice", return_value="invalid_orientation"):
            _, records = strategy.mutate(ds_with_sfg, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "invalid_orientation"
        sfg = ds_with_sfg.SharedFunctionalGroupsSequence[0]
        orient = sfg.PlaneOrientationSequence[0].ImageOrientationPatient
        assert math.isnan(orient[0])

    def test_conflict_with_per_frame(self, ds_with_sfg: Dataset) -> None:
        """Test conflict_with_per_frame sets conflicting pixel spacing."""
        from unittest.mock import patch

        strategy = SharedGroupStrategy()
        with patch("random.choice", return_value="conflict_with_per_frame"):
            _, records = strategy.mutate(ds_with_sfg, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "conflict_with_per_frame"


class TestPerFrameDimensionAttackTypes:
    """Individual attack type tests for PerFrameDimensionStrategy."""

    @pytest.fixture
    def ds_with_per_frame(self) -> Dataset:
        ds = Dataset()
        ds.NumberOfFrames = 3
        ds.PerFrameFunctionalGroupsSequence = Sequence([Dataset() for _ in range(3)])
        return ds

    def test_varying_matrix_size(self, ds_with_per_frame: Dataset) -> None:
        """Test varying_matrix_size sets different dims per frame."""
        from unittest.mock import patch

        strategy = PerFrameDimensionStrategy()
        with patch("random.choice", return_value=("varying", None, None)):
            _, records = strategy.mutate(ds_with_per_frame, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "varying_matrix_size"

    def test_zero_dimensions(self, ds_with_per_frame: Dataset) -> None:
        """Test zero dimensions attack."""
        from unittest.mock import patch

        strategy = PerFrameDimensionStrategy()
        with patch("random.choice", return_value=("zero", 0, 0)):
            _, records = strategy.mutate(ds_with_per_frame, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "zero_dimensions"

    def test_extreme_dimensions(self, ds_with_per_frame: Dataset) -> None:
        """Test extreme dimensions attack."""
        from unittest.mock import patch

        strategy = PerFrameDimensionStrategy()
        with patch("random.choice", return_value=("extreme", 65535, 65535)):
            _, records = strategy.mutate(ds_with_per_frame, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "extreme_dimensions"
        assert records[0].mutated_value == "65535x65535"

    def test_negative_dimensions(self, ds_with_per_frame: Dataset) -> None:
        """Test negative dimensions attack."""
        from unittest.mock import patch

        strategy = PerFrameDimensionStrategy()
        with patch("random.choice", return_value=("negative", -1, -1)):
            _, records = strategy.mutate(ds_with_per_frame, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "negative_dimensions"


class TestDimensionOverflowAttackTypes:
    """Individual attack type tests for DimensionOverflowStrategy."""

    @pytest.fixture
    def base_ds(self) -> Dataset:
        ds = Dataset()
        ds.NumberOfFrames = 10
        ds.Rows = 256
        ds.Columns = 256
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        return ds

    def test_frame_dimension_overflow(self, base_ds: Dataset) -> None:
        """Test frame_dimension_overflow sets extreme dimensions."""
        from unittest.mock import patch

        strategy = DimensionOverflowStrategy()
        with patch("random.choice", return_value="frame_dimension_overflow"):
            _, records = strategy.mutate(base_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "frame_dimension_overflow"
        assert base_ds.NumberOfFrames == 50000
        assert base_ds.Rows == 10000
        assert base_ds.Columns == 10000

    def test_total_pixel_overflow(self, base_ds: Dataset) -> None:
        """Test total_pixel_overflow sets max 16-bit values."""
        from unittest.mock import patch

        strategy = DimensionOverflowStrategy()
        with patch("random.choice", return_value="total_pixel_overflow"):
            _, records = strategy.mutate(base_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "total_pixel_overflow"
        assert base_ds.NumberOfFrames == 65535
        assert base_ds.Rows == 65535
        assert base_ds.Columns == 65535

    def test_bits_multiplier_overflow(self, base_ds: Dataset) -> None:
        """Test bits_multiplier_overflow sets 64-bit allocation."""
        from unittest.mock import patch

        strategy = DimensionOverflowStrategy()
        with patch("random.choice", return_value="bits_multiplier_overflow"):
            _, records = strategy.mutate(base_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "bits_multiplier_overflow"
        assert base_ds.BitsAllocated == 64

    def test_samples_multiplier_overflow(self, base_ds: Dataset) -> None:
        """Test samples_multiplier_overflow sets max SamplesPerPixel."""
        from unittest.mock import patch

        strategy = DimensionOverflowStrategy()
        with patch("random.choice", return_value="samples_multiplier_overflow"):
            _, records = strategy.mutate(base_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "samples_multiplier_overflow"
        assert base_ds.SamplesPerPixel == 255


class TestFunctionalGroupAttackTypes:
    """Individual attack type tests for FunctionalGroupStrategy."""

    @pytest.fixture
    def ds_with_groups(self) -> Dataset:
        ds = Dataset()
        ds.NumberOfFrames = 5
        ds.PerFrameFunctionalGroupsSequence = Sequence([Dataset() for _ in range(5)])
        return ds

    def test_missing_per_frame_groups(self, ds_with_groups: Dataset) -> None:
        """Test missing_per_frame reduces group count."""
        from unittest.mock import patch

        strategy = FunctionalGroupStrategy()
        handlers = [strategy._attack_missing_per_frame]
        with patch("random.choice", return_value=strategy._attack_missing_per_frame):
            _, records = strategy.mutate(ds_with_groups, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "missing_per_frame_groups"
        pfg = ds_with_groups.PerFrameFunctionalGroupsSequence
        assert len(pfg) < 5

    def test_extra_per_frame_groups(self, ds_with_groups: Dataset) -> None:
        """Test extra_per_frame doubles group count."""
        from unittest.mock import patch

        strategy = FunctionalGroupStrategy()
        with patch("random.choice", return_value=strategy._attack_extra_per_frame):
            _, records = strategy.mutate(ds_with_groups, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "extra_per_frame_groups"
        pfg = ds_with_groups.PerFrameFunctionalGroupsSequence
        assert len(pfg) == 10

    def test_empty_group_items(self, ds_with_groups: Dataset) -> None:
        """Test empty_group_items replaces items with empty datasets."""
        from unittest.mock import patch

        strategy = FunctionalGroupStrategy()
        with patch("random.choice", return_value=strategy._attack_empty_items):
            _, records = strategy.mutate(ds_with_groups, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "empty_group_items"

    def test_null_sequence_items(self, ds_with_groups: Dataset) -> None:
        """Test null_sequence inserts corrupt tag into first group."""
        from unittest.mock import patch

        strategy = FunctionalGroupStrategy()
        with patch("random.choice", return_value=strategy._attack_null_sequence):
            _, records = strategy.mutate(ds_with_groups, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "null_sequence_items"

    def test_deeply_nested_corruption(self, ds_with_groups: Dataset) -> None:
        """Test deeply_nested creates 10-level deep sequences."""
        from unittest.mock import patch

        strategy = FunctionalGroupStrategy()
        with patch("random.choice", return_value=strategy._attack_deeply_nested):
            _, records = strategy.mutate(ds_with_groups, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "deeply_nested_corruption"
        assert records[0].details["nesting_depth"] == 10


class TestFrameCountMismatchAttackTypes:
    """Individual attack type tests for FrameCountMismatchStrategy."""

    @pytest.fixture
    def ds_with_frames(self) -> Dataset:
        ds = Dataset()
        ds.NumberOfFrames = 10
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 16
        ds.SamplesPerPixel = 1
        ds.PixelData = b"\x00" * (64 * 64 * 2 * 10)
        return ds

    def test_too_large(self, ds_with_frames: Dataset) -> None:
        """Test too_large inflates NumberOfFrames."""
        from unittest.mock import patch

        strategy = FrameCountMismatchStrategy()
        with patch("random.choice", return_value="too_large"):
            _, records = strategy.mutate(ds_with_frames, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "too_large"
        assert ds_with_frames.NumberOfFrames == 100  # 10 * 10

    def test_zero(self, ds_with_frames: Dataset) -> None:
        """Test zero sets NumberOfFrames to 0."""
        from unittest.mock import patch

        strategy = FrameCountMismatchStrategy()
        with patch("random.choice", return_value="zero"):
            _, records = strategy.mutate(ds_with_frames, mutation_count=1)

        assert records[0].details["attack_type"] == "zero"
        assert ds_with_frames.NumberOfFrames == 0

    def test_negative(self, ds_with_frames: Dataset) -> None:
        """Test negative sets NumberOfFrames to -1."""
        from unittest.mock import patch

        strategy = FrameCountMismatchStrategy()
        with patch("random.choice", return_value="negative"):
            _, records = strategy.mutate(ds_with_frames, mutation_count=1)

        assert records[0].details["attack_type"] == "negative"
        assert ds_with_frames.NumberOfFrames == -1

    def test_overflow_32bit(self, ds_with_frames: Dataset) -> None:
        """Test overflow_32bit sets max signed 32-bit."""
        from unittest.mock import patch

        strategy = FrameCountMismatchStrategy()
        with patch("random.choice", return_value="overflow_32bit"):
            _, records = strategy.mutate(ds_with_frames, mutation_count=1)

        assert records[0].details["attack_type"] == "overflow_32bit"
        assert ds_with_frames.NumberOfFrames == 2147483647


# --- Encapsulated Pixel Data strategy tests ---


class TestEncapsulatedPixelStrategy:
    """Tests for EncapsulatedPixelStrategy."""

    @pytest.fixture
    def multiframe_ds(self) -> Dataset:
        ds = Dataset()
        ds.NumberOfFrames = 3
        ds.Rows = 16
        ds.Columns = 16
        ds.BitsAllocated = 8
        ds.SamplesPerPixel = 1
        ds.PixelData = b"\x00" * (16 * 16 * 3)
        return ds

    def test_strategy_name(self) -> None:
        """Test strategy_name property."""
        assert EncapsulatedPixelStrategy().strategy_name == "encapsulated_pixel_data"

    def test_mutate_produces_records(self, multiframe_ds: Dataset) -> None:
        """Test mutate produces correct number of records."""
        strategy = EncapsulatedPixelStrategy()
        _, records = strategy.mutate(multiframe_ds, mutation_count=5)
        assert len(records) == 5
        for r in records:
            assert r.strategy == "encapsulated_pixel_data"

    def test_invalid_bot_offsets(self, multiframe_ds: Dataset) -> None:
        """Test invalid_bot_offsets sets offsets past data end."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="invalid_bot_offsets"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "invalid_bot_offsets"

    def test_bot_length_not_multiple_of_4(self, multiframe_ds: Dataset) -> None:
        """Test BOT with non-aligned length."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="bot_length_not_multiple_of_4"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "bot_length_not_multiple_of_4"

    def test_empty_bot_with_eot(self, multiframe_ds: Dataset) -> None:
        """Test empty BOT + empty EOT (prohibited by standard)."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="empty_bot_with_eot"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "empty_bot_with_eot"
        # EOT tag should be present
        from pydicom.tag import Tag

        assert Tag(0x7FE0, 0x0001) in multiframe_ds

    def test_bot_and_eot_coexist(self, multiframe_ds: Dataset) -> None:
        """Test both BOT and EOT populated (violates standard)."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="bot_and_eot_coexist"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "bot_and_eot_coexist"
        from pydicom.tag import Tag

        eot = multiframe_ds[Tag(0x7FE0, 0x0001)].value
        assert len(eot) > 0  # EOT is populated

    def test_fragment_count_mismatch(self, multiframe_ds: Dataset) -> None:
        """Test extra fragments beyond NumberOfFrames."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="fragment_count_mismatch"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "fragment_count_mismatch"

    def test_fragment_embedded_delimiter(self, multiframe_ds: Dataset) -> None:
        """Test fragment containing sequence delimiter bytes."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="fragment_embedded_delimiter"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "fragment_embedded_delimiter"
        # Verify delimiter bytes are embedded in pixel data
        assert b"\xfe\xff\xdd\xe0" in multiframe_ds.PixelData

    def test_fragment_undefined_length(self, multiframe_ds: Dataset) -> None:
        """Test fragment with 0xFFFFFFFF length."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="fragment_undefined_length"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "fragment_undefined_length"
        # Verify undefined length bytes in pixel data
        assert b"\xff\xff\xff\xff" in multiframe_ds.PixelData

    def test_truncated_fragment(self, multiframe_ds: Dataset) -> None:
        """Test fragment claiming more data than available."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="truncated_fragment"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "truncated_fragment"

    def test_missing_seq_delimiter(self, multiframe_ds: Dataset) -> None:
        """Test removal of sequence delimiter."""
        from unittest.mock import patch

        strategy = EncapsulatedPixelStrategy()
        with patch("random.choice", return_value="missing_seq_delimiter"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "missing_seq_delimiter"
        # Verify no trailing delimiter
        assert not multiframe_ds.PixelData.endswith(b"\xfe\xff\xdd\xe0\x00\x00\x00\x00")

    def test_no_pixel_data_no_dims(self) -> None:
        """Test strategy works with minimal dataset (no Rows/Cols)."""
        strategy = EncapsulatedPixelStrategy()
        ds = Dataset()
        ds.NumberOfFrames = 2
        _, records = strategy.mutate(ds, mutation_count=3)
        assert len(records) == 3


# --- Dimension Index strategy tests ---


class TestDimensionIndexStrategy:
    """Tests for DimensionIndexStrategy."""

    @pytest.fixture
    def multiframe_ds(self) -> Dataset:
        ds = Dataset()
        ds.NumberOfFrames = 5
        return ds

    def test_strategy_name(self) -> None:
        """Test strategy_name property."""
        assert DimensionIndexStrategy().strategy_name == "dimension_index_attack"

    def test_mutate_produces_records(self, multiframe_ds: Dataset) -> None:
        """Test mutate produces correct number of records."""
        strategy = DimensionIndexStrategy()
        _, records = strategy.mutate(multiframe_ds, mutation_count=5)
        assert len(records) == 5
        for r in records:
            assert r.strategy == "dimension_index_attack"

    def test_invalid_index_pointer(self, multiframe_ds: Dataset) -> None:
        """Test invalid_index_pointer sets non-existent tag."""
        from unittest.mock import patch

        strategy = DimensionIndexStrategy()
        with patch("random.choice", return_value="invalid_index_pointer"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "invalid_index_pointer"
        assert hasattr(multiframe_ds, "DimensionIndexSequence")

    def test_index_values_length_mismatch(self, multiframe_ds: Dataset) -> None:
        """Test DimensionIndexValues with wrong element count."""
        from unittest.mock import patch

        strategy = DimensionIndexStrategy()
        with patch("random.choice", return_value="index_values_length_mismatch"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "index_values_length_mismatch"

    def test_missing_index_values(self, multiframe_ds: Dataset) -> None:
        """Test removal of DimensionIndexValues from frames."""
        from unittest.mock import patch

        strategy = DimensionIndexStrategy()
        with patch("random.choice", return_value="missing_index_values"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "missing_index_values"
        assert records[0].details["removed_count"] >= 1

    def test_out_of_range_index_values(self, multiframe_ds: Dataset) -> None:
        """Test invalid index values (negative, zero, huge)."""
        from unittest.mock import patch

        strategy = DimensionIndexStrategy()
        with patch("random.choice", return_value="out_of_range_index_values"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "out_of_range_index_values"
        assert "value_type" in records[0].details

    def test_organization_type_mismatch(self, multiframe_ds: Dataset) -> None:
        """Test 3D organization type with 1 dimension."""
        from unittest.mock import patch

        strategy = DimensionIndexStrategy()
        with patch("random.choice", return_value="organization_type_mismatch"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "organization_type_mismatch"
        assert multiframe_ds.DimensionOrganizationType == "3D"
        assert len(multiframe_ds.DimensionIndexSequence) == 1

    def test_empty_dimension_sequence(self, multiframe_ds: Dataset) -> None:
        """Test empty DimensionIndexSequence while frames have values."""
        from unittest.mock import patch

        strategy = DimensionIndexStrategy()
        with patch("random.choice", return_value="empty_dimension_sequence"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "empty_dimension_sequence"
        assert len(multiframe_ds.DimensionIndexSequence) == 0

    def test_duplicate_dimension_pointers(self, multiframe_ds: Dataset) -> None:
        """Test multiple dimensions pointing to same tag."""
        from unittest.mock import patch

        strategy = DimensionIndexStrategy()
        with patch("random.choice", return_value="duplicate_dimension_pointers"):
            _, records = strategy.mutate(multiframe_ds, mutation_count=1)

        assert len(records) == 1
        assert records[0].details["attack_type"] == "duplicate_dimension_pointers"
        # Original 1 + 3 duplicates = 4
        assert len(multiframe_ds.DimensionIndexSequence) >= 4
