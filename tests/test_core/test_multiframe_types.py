"""Tests for multiframe_types module."""

from __future__ import annotations

from dicom_fuzzer.core.mutation.multiframe_types import (
    FrameInfo,
    MultiFrameMutationRecord,
    MultiFrameMutationStrategy,
)


class TestMultiFrameMutationStrategy:
    """Tests for MultiFrameMutationStrategy enum."""

    def test_all_strategies_defined(self) -> None:
        """Verify all 8 mutation strategies are defined."""
        assert len(MultiFrameMutationStrategy) == 8

    def test_strategy_values(self) -> None:
        """Verify strategy values match expected strings."""
        assert (
            MultiFrameMutationStrategy.FRAME_COUNT_MISMATCH.value
            == "frame_count_mismatch"
        )
        assert (
            MultiFrameMutationStrategy.FRAME_TIME_CORRUPTION.value
            == "frame_time_corruption"
        )
        assert (
            MultiFrameMutationStrategy.PER_FRAME_DIMENSION_MISMATCH.value
            == "per_frame_dimension_mismatch"
        )
        assert (
            MultiFrameMutationStrategy.SHARED_GROUP_CORRUPTION.value
            == "shared_group_corruption"
        )
        assert (
            MultiFrameMutationStrategy.FRAME_INCREMENT_INVALID.value
            == "frame_increment_invalid"
        )
        assert (
            MultiFrameMutationStrategy.DIMENSION_OVERFLOW.value == "dimension_overflow"
        )
        assert (
            MultiFrameMutationStrategy.FUNCTIONAL_GROUP_ATTACK.value
            == "functional_group_attack"
        )
        assert (
            MultiFrameMutationStrategy.PIXEL_DATA_TRUNCATION.value
            == "pixel_data_truncation"
        )

    def test_strategy_lookup_by_value(self) -> None:
        """Verify strategies can be looked up by value."""
        assert (
            MultiFrameMutationStrategy("frame_count_mismatch")
            == MultiFrameMutationStrategy.FRAME_COUNT_MISMATCH
        )

    def test_strategy_iteration(self) -> None:
        """Verify all strategies can be iterated."""
        strategies = list(MultiFrameMutationStrategy)
        assert len(strategies) == 8


class TestFrameInfo:
    """Tests for FrameInfo dataclass."""

    def test_frame_info_creation_minimal(self) -> None:
        """Test FrameInfo with minimal parameters."""
        info = FrameInfo(frame_number=1)

        assert info.frame_number == 1
        assert info.position is None
        assert info.orientation is None
        assert info.acquisition_time is None
        assert info.pixel_offset == 0
        assert info.frame_size_bytes == 0

    def test_frame_info_creation_full(self) -> None:
        """Test FrameInfo with all parameters."""
        info = FrameInfo(
            frame_number=5,
            position=(0.0, 0.0, 50.0),
            orientation=(1.0, 0.0, 0.0, 0.0, 1.0, 0.0),
            acquisition_time="20240101120000.000000",
            pixel_offset=262144,
            frame_size_bytes=65536,
        )

        assert info.frame_number == 5
        assert info.position == (0.0, 0.0, 50.0)
        assert info.orientation == (1.0, 0.0, 0.0, 0.0, 1.0, 0.0)
        assert info.acquisition_time == "20240101120000.000000"
        assert info.pixel_offset == 262144
        assert info.frame_size_bytes == 65536

    def test_frame_info_immutable_fields(self) -> None:
        """Test that FrameInfo fields can be accessed."""
        info = FrameInfo(frame_number=1, pixel_offset=1000)
        assert info.pixel_offset == 1000


class TestMultiFrameMutationRecord:
    """Tests for MultiFrameMutationRecord dataclass."""

    def test_record_creation_minimal(self) -> None:
        """Test record creation with minimal parameters."""
        record = MultiFrameMutationRecord(strategy="frame_count_mismatch")

        assert record.strategy == "frame_count_mismatch"
        assert record.frame_number is None
        assert record.tag is None
        assert record.original_value is None
        assert record.mutated_value is None
        assert record.severity == "moderate"
        assert record.details == {}

    def test_record_creation_full(self) -> None:
        """Test record creation with all parameters."""
        record = MultiFrameMutationRecord(
            strategy="dimension_overflow",
            frame_number=3,
            tag="NumberOfFrames",
            original_value="10",
            mutated_value="999999999",
            severity="extreme",
            details={"attack_type": "extreme", "overflow": True},
        )

        assert record.strategy == "dimension_overflow"
        assert record.frame_number == 3
        assert record.tag == "NumberOfFrames"
        assert record.original_value == "10"
        assert record.mutated_value == "999999999"
        assert record.severity == "extreme"
        assert record.details == {"attack_type": "extreme", "overflow": True}

    def test_record_to_dict(self) -> None:
        """Test to_dict serialization."""
        record = MultiFrameMutationRecord(
            strategy="frame_count_mismatch",
            tag="NumberOfFrames",
            original_value="10",
            mutated_value="100",
            details={"attack_type": "too_large"},
        )

        data = record.to_dict()

        assert data["strategy"] == "frame_count_mismatch"
        assert data["tag"] == "NumberOfFrames"
        assert data["original_value"] == "10"
        assert data["mutated_value"] == "100"
        assert data["details"] == {"attack_type": "too_large"}

    def test_record_to_dict_converts_values_to_string(self) -> None:
        """Test that to_dict converts values to strings."""
        record = MultiFrameMutationRecord(
            strategy="test",
            original_value="123",  # String value
            mutated_value="456",  # String value
        )

        data = record.to_dict()

        assert data["original_value"] == "123"
        assert data["mutated_value"] == "456"

    def test_record_to_dict_handles_none_values(self) -> None:
        """Test that to_dict handles None values correctly."""
        record = MultiFrameMutationRecord(strategy="test")

        data = record.to_dict()

        assert data["original_value"] is None
        assert data["mutated_value"] is None


class TestBackwardCompatibilityImports:
    """Test backward compatibility with imports from different locations."""

    def test_import_from_multiframe_types(self) -> None:
        """Verify imports from multiframe_types work."""
        from dicom_fuzzer.core.mutation.multiframe_types import (
            FrameInfo,
            MultiFrameMutationRecord,
            MultiFrameMutationStrategy,
        )

        assert FrameInfo is not None
        assert MultiFrameMutationRecord is not None
        assert MultiFrameMutationStrategy is not None

    def test_import_from_multiframe_handler(self) -> None:
        """Verify imports from multiframe_handler still work."""
        from dicom_fuzzer.core.mutation.multiframe_handler import (
            FrameInfo,
            MultiFrameMutationRecord,
            MultiFrameMutationStrategy,
        )

        assert FrameInfo is not None
        assert MultiFrameMutationRecord is not None
        assert MultiFrameMutationStrategy is not None

    def test_import_from_core(self) -> None:
        """Verify imports from core still work."""
        from dicom_fuzzer.core import (
            FrameInfo,
            MultiFrameMutationRecord,
            MultiFrameMutationStrategy,
        )

        assert FrameInfo is not None
        assert MultiFrameMutationRecord is not None
        assert MultiFrameMutationStrategy is not None
