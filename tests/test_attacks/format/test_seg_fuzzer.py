"""Tests for SegmentationFuzzer."""

from __future__ import annotations

import copy
import random

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.format.seg_fuzzer import (
    _SEG_SOP_CLASS_UID,
    SegmentationFuzzer,
)


@pytest.fixture
def fuzzer() -> SegmentationFuzzer:
    return SegmentationFuzzer()


@pytest.fixture
def seg_dataset() -> Dataset:
    """Dataset mimicking a Segmentation SOP instance."""
    ds = Dataset()
    ds.SOPClassUID = _SEG_SOP_CLASS_UID
    ds.SOPInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.StudyInstanceUID = generate_uid()
    ds.Modality = "SEG"
    ds.SegmentationType = "BINARY"
    ds.BitsAllocated = 1
    ds.BitsStored = 1
    ds.HighBit = 0
    ds.SamplesPerPixel = 1
    ds.Rows = 64
    ds.Columns = 64
    ds.NumberOfFrames = 2

    # SegmentSequence with 2 segments
    seg1 = Dataset()
    seg1.SegmentNumber = 1
    seg1.SegmentLabel = "Tumor"
    seg1.SegmentAlgorithmType = "AUTOMATIC"
    seg2 = Dataset()
    seg2.SegmentNumber = 2
    seg2.SegmentLabel = "Organ"
    seg2.SegmentAlgorithmType = "SEMIAUTOMATIC"
    ds.SegmentSequence = Sequence([seg1, seg2])

    # PerFrameFunctionalGroupsSequence mapping frames to segments
    frame1 = Dataset()
    sid1 = Dataset()
    sid1.ReferencedSegmentNumber = 1
    frame1.SegmentIdentificationSequence = Sequence([sid1])
    frame2 = Dataset()
    sid2 = Dataset()
    sid2.ReferencedSegmentNumber = 2
    frame2.SegmentIdentificationSequence = Sequence([sid2])
    ds.PerFrameFunctionalGroupsSequence = Sequence([frame1, frame2])

    # ReferencedSeriesSequence
    ref_series = Dataset()
    ref_series.SeriesInstanceUID = generate_uid()
    ref_inst = Dataset()
    ref_inst.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ref_inst.ReferencedSOPInstanceUID = generate_uid()
    ref_series.ReferencedInstanceSequence = Sequence([ref_inst])
    ds.ReferencedSeriesSequence = Sequence([ref_series])

    return ds


# ---------------------------------------------------------------------------
# can_mutate
# ---------------------------------------------------------------------------


class TestCanMutate:
    def test_accepts_seg_sop_class(self, fuzzer: SegmentationFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SEG_SOP_CLASS_UID
        assert fuzzer.can_mutate(ds) is True

    def test_rejects_ct_sop_class(self, fuzzer: SegmentationFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_rejects_missing_sop_class(self, fuzzer: SegmentationFuzzer) -> None:
        ds = Dataset()
        assert fuzzer.can_mutate(ds) is False


# ---------------------------------------------------------------------------
# _segment_sequence_corruption
# ---------------------------------------------------------------------------


class TestSegmentSequenceCorruption:
    def test_duplicate_numbers(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._segment_sequence_corruption(ds)
            seq = getattr(result, "SegmentSequence", None)
            if seq and len(seq) >= 2:
                nums = [item.SegmentNumber for item in seq]
                if len(nums) != len(set(nums)):
                    return
        pytest.fail("duplicate_numbers attack never triggered")

    def test_gap_in_numbers(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._segment_sequence_corruption(ds)
            seq = getattr(result, "SegmentSequence", None)
            if seq and len(seq) >= 2:
                nums = sorted(item.SegmentNumber for item in seq)
                expected = list(range(nums[0], nums[0] + len(nums)))
                if nums != expected:
                    return
        pytest.fail("gap_in_numbers attack never triggered")

    def test_zero_segment_number(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._segment_sequence_corruption(ds)
            seq = getattr(result, "SegmentSequence", None)
            if seq:
                for item in seq:
                    if getattr(item, "SegmentNumber", None) == 0:
                        return
        pytest.fail("zero_segment_number attack never triggered")

    def test_empty_sequence(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._segment_sequence_corruption(ds)
            seq = getattr(result, "SegmentSequence", None)
            if seq is not None and len(seq) == 0:
                return
        pytest.fail("empty_sequence attack never triggered")

    def test_remove_sequence(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._segment_sequence_corruption(ds)
            if "SegmentSequence" not in result:
                return
        pytest.fail("remove_sequence attack never triggered")

    def test_handles_missing_sequence(self, fuzzer: SegmentationFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SEG_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._segment_sequence_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _segment_frame_mapping_attack
# ---------------------------------------------------------------------------


class TestSegmentFrameMappingAttack:
    def test_orphan_reference(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._segment_frame_mapping_attack(ds)
            pffgs = getattr(result, "PerFrameFunctionalGroupsSequence", None)
            if pffgs:
                for frame in pffgs:
                    sid_seq = getattr(frame, "SegmentIdentificationSequence", None)
                    if sid_seq and len(sid_seq) > 0:
                        ref_num = getattr(sid_seq[0], "ReferencedSegmentNumber", None)
                        if ref_num == 999:
                            return
        pytest.fail("orphan_reference attack never triggered")

    def test_zero_reference(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._segment_frame_mapping_attack(ds)
            pffgs = getattr(result, "PerFrameFunctionalGroupsSequence", None)
            if pffgs:
                for frame in pffgs:
                    sid_seq = getattr(frame, "SegmentIdentificationSequence", None)
                    if sid_seq and len(sid_seq) > 0:
                        ref_num = getattr(sid_seq[0], "ReferencedSegmentNumber", None)
                        if ref_num == 0:
                            return
        pytest.fail("zero_reference attack never triggered")

    def test_remove_identification(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._segment_frame_mapping_attack(ds)
            pffgs = getattr(result, "PerFrameFunctionalGroupsSequence", None)
            if pffgs and len(pffgs) > 0:
                if not hasattr(pffgs[0], "SegmentIdentificationSequence"):
                    return
        pytest.fail("remove_identification attack never triggered")

    def test_handles_minimal_dataset(self, fuzzer: SegmentationFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SEG_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._segment_frame_mapping_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _binary_pixel_type_mismatch
# ---------------------------------------------------------------------------


class TestBinaryPixelTypeMismatch:
    def test_binary_with_8bit(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._binary_pixel_type_mismatch(ds)
            seg_type = getattr(result, "SegmentationType", None)
            bits = getattr(result, "BitsAllocated", None)
            if seg_type == "BINARY" and bits == 8:
                return
        pytest.fail("binary_with_8bit attack never triggered")

    def test_fractional_with_1bit(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._binary_pixel_type_mismatch(ds)
            seg_type = getattr(result, "SegmentationType", None)
            bits = getattr(result, "BitsAllocated", None)
            if seg_type == "FRACTIONAL" and bits == 1:
                return
        pytest.fail("fractional_with_1bit attack never triggered")

    def test_invalid_type(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._binary_pixel_type_mismatch(ds)
            seg_type = getattr(result, "SegmentationType", None)
            if seg_type not in ("BINARY", "FRACTIONAL", None):
                return
        pytest.fail("invalid_type attack never triggered")

    def test_handles_minimal_dataset(self, fuzzer: SegmentationFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SEG_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._binary_pixel_type_mismatch(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _referenced_series_corruption
# ---------------------------------------------------------------------------


class TestReferencedSeriesCorruption:
    def test_invalid_uid(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._referenced_series_corruption(ds)
            ref_seq = getattr(result, "ReferencedSeriesSequence", None)
            if ref_seq and len(ref_seq) > 0:
                uid = getattr(ref_seq[0], "SeriesInstanceUID", "")
                if "INVALID" in str(uid):
                    return
        pytest.fail("invalid_uid attack never triggered")

    def test_empty_sequence(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            result = fuzzer._referenced_series_corruption(ds)
            ref_seq = getattr(result, "ReferencedSeriesSequence", None)
            if ref_seq is not None and len(ref_seq) == 0:
                return
        pytest.fail("empty_sequence attack never triggered")

    def test_self_reference(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            original_series_uid = ds.SeriesInstanceUID
            result = fuzzer._referenced_series_corruption(ds)
            ref_seq = getattr(result, "ReferencedSeriesSequence", None)
            if ref_seq and len(ref_seq) > 0:
                uid = str(getattr(ref_seq[0], "SeriesInstanceUID", ""))
                if uid == str(original_series_uid):
                    return
        pytest.fail("self_reference attack never triggered")

    def test_handles_minimal_dataset(self, fuzzer: SegmentationFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SEG_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._referenced_series_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# mutate() integration
# ---------------------------------------------------------------------------


class TestMutateIntegration:
    def test_returns_dataset(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        result = fuzzer.mutate(copy.deepcopy(seg_dataset))
        assert isinstance(result, Dataset)

    def test_does_not_raise(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        for i in range(20):
            random.seed(i)
            fuzzer.mutate(copy.deepcopy(seg_dataset))

    def test_modifies_dataset(
        self, fuzzer: SegmentationFuzzer, seg_dataset: Dataset
    ) -> None:
        modified = False
        for i in range(30):
            random.seed(i)
            ds = copy.deepcopy(seg_dataset)
            original = copy.deepcopy(ds)
            result = fuzzer.mutate(ds)
            if result != original:
                modified = True
                break
        assert modified, "mutate() never modified the dataset"

    def test_handles_empty_dataset(self, fuzzer: SegmentationFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SEG_SOP_CLASS_UID
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)
