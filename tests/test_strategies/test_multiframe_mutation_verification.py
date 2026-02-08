"""Multiframe Mutation Verification Tests.

Verifies that each multiframe mutation strategy produces the claimed defect.
Calls strategy mutate() methods directly with patched random.choice to force
specific attack types, then asserts dataset-level properties.

Phase 2: 10 strategies, 55 attack types.
"""

from __future__ import annotations

import copy
import math
import random as _random
from unittest.mock import patch

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.tag import Tag

from dicom_fuzzer.attacks.multiframe.dimension_index import DimensionIndexStrategy
from dicom_fuzzer.attacks.multiframe.dimension_overflow import DimensionOverflowStrategy
from dicom_fuzzer.attacks.multiframe.encapsulated_pixel import EncapsulatedPixelStrategy
from dicom_fuzzer.attacks.multiframe.frame_count import FrameCountMismatchStrategy
from dicom_fuzzer.attacks.multiframe.frame_increment import FrameIncrementStrategy
from dicom_fuzzer.attacks.multiframe.frame_time import FrameTimeCorruptionStrategy
from dicom_fuzzer.attacks.multiframe.functional_group import FunctionalGroupStrategy
from dicom_fuzzer.attacks.multiframe.per_frame_dimension import (
    PerFrameDimensionStrategy,
)
from dicom_fuzzer.attacks.multiframe.pixel_truncation import (
    PixelDataTruncationStrategy,
)
from dicom_fuzzer.attacks.multiframe.shared_group import SharedGroupStrategy

# Capture real random.choice before any mocking
_real_choice = _random.choice


def _force_attack(attack_value):
    """Side effect: returns attack_value on first random.choice, real choice after."""
    calls = [0]

    def side_effect(seq):
        calls[0] += 1
        if calls[0] == 1:
            return attack_value
        return _real_choice(seq)

    return side_effect


# =============================================================================
# Fixture
# =============================================================================
@pytest.fixture
def multiframe_ds():
    """10-frame, 512x512, 16-bit multiframe dataset with functional groups."""
    ds = Dataset()
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2.1"
    ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
    ds.Modality = "CT"
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.SamplesPerPixel = 1
    ds.NumberOfFrames = 10

    frame_size = 512 * 512 * 2
    ds.PixelData = bytes(frame_size * 10)

    per_frame_groups = []
    for i in range(10):
        fg = Dataset()
        plane_pos = Dataset()
        plane_pos.ImagePositionPatient = [0.0, 0.0, float(i * 5.0)]
        fg.PlanePositionSequence = Sequence([plane_pos])

        plane_orient = Dataset()
        plane_orient.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        fg.PlaneOrientationSequence = Sequence([plane_orient])

        frame_content = Dataset()
        frame_content.FrameAcquisitionDateTime = f"2023010112{i:02d}00.000000"
        frame_content.TemporalPositionIndex = i + 1
        fg.FrameContentSequence = Sequence([frame_content])

        per_frame_groups.append(fg)

    ds.PerFrameFunctionalGroupsSequence = Sequence(per_frame_groups)

    sfg = Dataset()
    pixel_measures = Dataset()
    pixel_measures.PixelSpacing = [0.5, 0.5]
    pixel_measures.SliceThickness = 5.0
    sfg.PixelMeasuresSequence = Sequence([pixel_measures])
    ds.SharedFunctionalGroupsSequence = Sequence([sfg])

    ds.FrameTime = 33.33
    return ds


# =============================================================================
# Strategy 1: FrameCountMismatch (6 attack types)
# =============================================================================
class TestFrameCountMismatch:
    """Verify FrameCountMismatchStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return FrameCountMismatchStrategy()

    @pytest.mark.parametrize(
        ("attack", "expected_nof"),
        [
            ("too_large", 100),
            ("too_small", 5),
            ("zero", 0),
            ("negative", -1),
            ("overflow_32bit", 2147483647),
            ("extreme", 999999999),
        ],
    )
    def test_number_of_frames(self, strategy, multiframe_ds, attack, expected_nof):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value=attack):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.NumberOfFrames == expected_nof
        assert len(records) == 1
        assert records[0].details["attack_type"] == attack


# =============================================================================
# Strategy 2: FrameTimeCorruption (6 attack types)
# =============================================================================
class TestFrameTimeCorruption:
    """Verify FrameTimeCorruptionStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return FrameTimeCorruptionStrategy()

    def test_negative_frame_time(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="negative_frame_time"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.FrameTime == -33.33

    def test_zero_frame_time(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="zero_frame_time"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.FrameTime == 0.0

    def test_nan_frame_time(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="nan_frame_time"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert math.isnan(result.FrameTime)

    def test_extreme_time_values(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="extreme_time_values"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.FrameTime == 1e308

    def test_invalid_time_vector(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", side_effect=_force_attack("invalid_time_vector")):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert hasattr(result, "FrameTimeVector")
        assert len(result.FrameTimeVector) != 10

    def test_corrupt_temporal_index(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch(
            "random.choice", side_effect=_force_attack("corrupt_temporal_index")
        ):
            result, records = strategy.mutate(ds, mutation_count=1)
        corrupted = False
        for fg in result.PerFrameFunctionalGroupsSequence:
            if hasattr(fg, "FrameContentSequence") and fg.FrameContentSequence:
                idx = getattr(fg.FrameContentSequence[0], "TemporalPositionIndex", None)
                if idx is not None and idx in {0, -1, 999999}:
                    corrupted = True
                    break
        assert corrupted


# =============================================================================
# Strategy 3: PerFrameDimension (4 attack types)
# =============================================================================
class TestPerFrameDimension:
    """Verify PerFrameDimensionStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return PerFrameDimensionStrategy()

    @pytest.mark.parametrize(
        ("attack_tuple", "expected_type"),
        [
            (("varying", None, None), "varying_matrix_size"),
            (("zero", 0, 0), "zero_dimensions"),
            (("extreme", 65535, 65535), "extreme_dimensions"),
            (("negative", -1, -1), "negative_dimensions"),
        ],
    )
    def test_attack_produces_records(
        self, strategy, multiframe_ds, attack_tuple, expected_type
    ):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", side_effect=_force_attack(attack_tuple)):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(records) >= 1
        assert records[0].details["attack_type"] == expected_type


# =============================================================================
# Strategy 4: SharedGroup (5 attack types)
# =============================================================================
class TestSharedGroup:
    """Verify SharedGroupStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return SharedGroupStrategy()

    def test_delete_shared_groups(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="delete_shared_groups"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert not hasattr(result, "SharedFunctionalGroupsSequence")

    def test_empty_shared_groups(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="empty_shared_groups"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.SharedFunctionalGroupsSequence) == 0

    def test_corrupt_pixel_measures(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="corrupt_pixel_measures"):
            result, records = strategy.mutate(ds, mutation_count=1)
        pm = result.SharedFunctionalGroupsSequence[0].PixelMeasuresSequence[0]
        assert list(pm.PixelSpacing) == [0.0, 0.0]
        assert pm.SliceThickness == -1.0

    def test_invalid_orientation(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="invalid_orientation"):
            result, records = strategy.mutate(ds, mutation_count=1)
        sfg = result.SharedFunctionalGroupsSequence[0]
        orient = list(sfg.PlaneOrientationSequence[0].ImageOrientationPatient)
        assert any(math.isnan(v) for v in orient)

    def test_conflict_with_per_frame(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="conflict_with_per_frame"):
            result, records = strategy.mutate(ds, mutation_count=1)
        shared_ps = list(
            result.SharedFunctionalGroupsSequence[0]
            .PixelMeasuresSequence[0]
            .PixelSpacing
        )
        pf_fg = result.PerFrameFunctionalGroupsSequence[0]
        pf_ps = list(pf_fg.PixelMeasuresSequence[0].PixelSpacing)
        assert shared_ps != pf_ps


# =============================================================================
# Strategy 5: FrameIncrement (4 attack types)
# =============================================================================
class TestFrameIncrement:
    """Verify FrameIncrementStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return FrameIncrementStrategy()

    def test_nonexistent_tag(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="nonexistent_tag"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert hasattr(result, "FrameIncrementPointer")
        assert len(records) >= 1

    def test_invalid_format(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="invalid_format"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert hasattr(result, "FrameIncrementPointer")

    def test_point_to_pixel_data(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="point_to_pixel_data"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert hasattr(result, "FrameIncrementPointer")

    def test_multiple_invalid(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="multiple_invalid"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert hasattr(result, "FrameIncrementPointer")


# =============================================================================
# Strategy 6: DimensionOverflow (4 attack types)
# =============================================================================
class TestDimensionOverflow:
    """Verify DimensionOverflowStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return DimensionOverflowStrategy()

    def test_frame_dimension_overflow(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="frame_dimension_overflow"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.NumberOfFrames == 50000
        assert result.Rows == 10000
        assert result.Columns == 10000

    def test_total_pixel_overflow(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="total_pixel_overflow"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.NumberOfFrames == 65535
        assert result.Rows == 65535
        assert result.Columns == 65535

    def test_bits_multiplier_overflow(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="bits_multiplier_overflow"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.BitsAllocated == 64

    def test_samples_multiplier_overflow(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="samples_multiplier_overflow"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.SamplesPerPixel == 255


# =============================================================================
# Strategy 7: FunctionalGroup (5 attack types)
# =============================================================================
class TestFunctionalGroup:
    """Verify FunctionalGroupStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return FunctionalGroupStrategy()

    def test_missing_per_frame_groups(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        handler = strategy._attack_missing_per_frame
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.PerFrameFunctionalGroupsSequence) < 10

    def test_extra_per_frame_groups(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        handler = strategy._attack_extra_per_frame
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.PerFrameFunctionalGroupsSequence) > 10

    def test_empty_group_items(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        handler = strategy._attack_empty_items
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = strategy.mutate(ds, mutation_count=1)
        empty_count = sum(
            1 for fg in result.PerFrameFunctionalGroupsSequence if len(fg) == 0
        )
        assert empty_count >= 1

    def test_null_sequence_items(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        handler = strategy._attack_null_sequence
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "null_sequence_items"

    def test_deeply_nested_corruption(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        handler = strategy._attack_deeply_nested
        with patch("random.choice", side_effect=_force_attack(handler)):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(records) >= 1
        assert records[0].details["attack_type"] == "deeply_nested_corruption"


# =============================================================================
# Strategy 8: PixelDataTruncation (5 attack types)
# =============================================================================
class TestPixelDataTruncation:
    """Verify PixelDataTruncationStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return PixelDataTruncationStrategy()

    def test_truncate_mid_frame(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        original_len = len(ds.PixelData)
        with patch("random.choice", return_value="truncate_mid_frame"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.PixelData) < original_len

    def test_truncate_partial(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="truncate_partial"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.PixelData) < 524288  # Less than one frame

    def test_extra_bytes(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        original_len = len(ds.PixelData)
        with patch("random.choice", return_value="extra_bytes"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.PixelData) > original_len

    def test_empty_pixel_data(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="empty_pixel_data"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.PixelData) == 0

    def test_single_byte(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="single_byte"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.PixelData) == 1


# =============================================================================
# Strategy 9: EncapsulatedPixel (9 attack types)
# =============================================================================
class TestEncapsulatedPixel:
    """Verify EncapsulatedPixelStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return EncapsulatedPixelStrategy()

    @pytest.mark.parametrize(
        "attack",
        [
            "invalid_bot_offsets",
            "bot_length_not_multiple_of_4",
            "empty_bot_with_eot",
            "bot_and_eot_coexist",
            "fragment_count_mismatch",
            "fragment_embedded_delimiter",
            "fragment_undefined_length",
            "truncated_fragment",
            "missing_seq_delimiter",
        ],
    )
    def test_attack_produces_records(self, strategy, multiframe_ds, attack):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", side_effect=_force_attack(attack)):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(records) >= 1
        assert records[0].details["attack_type"] == attack

    def test_fragment_undefined_length_marker(self, strategy, multiframe_ds):
        """Fragment with 0xFFFFFFFF length should appear in pixel data."""
        import struct

        ds = copy.deepcopy(multiframe_ds)
        with patch(
            "random.choice", side_effect=_force_attack("fragment_undefined_length")
        ):
            result, records = strategy.mutate(ds, mutation_count=1)
        if isinstance(result.PixelData, bytes):
            assert struct.pack("<I", 0xFFFFFFFF) in result.PixelData


# =============================================================================
# Strategy 10: DimensionIndex (7 attack types)
# =============================================================================
class TestDimensionIndex:
    """Verify DimensionIndexStrategy attack types."""

    @pytest.fixture
    def strategy(self):
        return DimensionIndexStrategy()

    def test_invalid_index_pointer(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", side_effect=_force_attack("invalid_index_pointer")):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert hasattr(result, "DimensionIndexSequence")
        has_invalid = any(
            item.DimensionIndexPointer == Tag(0x9999, 0x9999)
            for item in result.DimensionIndexSequence
            if hasattr(item, "DimensionIndexPointer")
        )
        assert has_invalid

    def test_index_values_length_mismatch(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch(
            "random.choice",
            side_effect=_force_attack("index_values_length_mismatch"),
        ):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(records) >= 1

    def test_missing_index_values(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", side_effect=_force_attack("missing_index_values")):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(records) >= 1

    def test_out_of_range_index_values(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch(
            "random.choice",
            side_effect=_force_attack("out_of_range_index_values"),
        ):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(records) >= 1

    def test_organization_type_mismatch(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch(
            "random.choice",
            side_effect=_force_attack("organization_type_mismatch"),
        ):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert result.DimensionOrganizationType == "3D"
        assert len(result.DimensionIndexSequence) == 1

    def test_empty_dimension_sequence(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch("random.choice", return_value="empty_dimension_sequence"):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.DimensionIndexSequence) == 0

    def test_duplicate_dimension_pointers(self, strategy, multiframe_ds):
        ds = copy.deepcopy(multiframe_ds)
        with patch(
            "random.choice",
            side_effect=_force_attack("duplicate_dimension_pointers"),
        ):
            result, records = strategy.mutate(ds, mutation_count=1)
        assert len(result.DimensionIndexSequence) >= 4
