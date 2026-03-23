"""Tests for MultiFrameMutationRecord."""

from __future__ import annotations

from dicom_fuzzer.attacks.multiframe.format_base import MultiFrameMutationRecord


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
            original_value="123",
            mutated_value="456",
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
