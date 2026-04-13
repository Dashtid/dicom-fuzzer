"""Tests for StructuredReportFuzzer.

Verifies all 12 SR content-tree attack sub-strategies plus can_mutate()
and DicomMutator registration.
"""

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.sr_fuzzer import StructuredReportFuzzer

_SR_SOP = "1.2.840.10008.5.1.4.1.1.88.11"  # Basic Text SR


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sr_dataset() -> Dataset:
    """Return a minimal, well-formed SR dataset."""
    ds = Dataset()
    ds.SOPClassUID = _SR_SOP

    text_item = Dataset()
    text_item.RelationshipType = "CONTAINS"
    text_item.ValueType = "TEXT"
    c = Dataset()
    c.CodeValue = "1"
    c.CodingSchemeDesignator = "SCT"
    c.CodeMeaning = "Finding"
    text_item.ConceptNameCodeSequence = Sequence([c])
    text_item.TextValue = "Normal"

    root = Dataset()
    root.RelationshipType = "CONTAINS"
    root.ValueType = "CONTAINER"
    root.ConceptNameCodeSequence = Sequence([c])
    root.ContinuityOfContent = "SEPARATE"
    root.ContentSequence = Sequence([text_item])

    ds.ContentSequence = Sequence([root])
    return ds


def _bare_dataset() -> Dataset:
    ds = Dataset()
    ds.PatientName = "FUZZER^TEST"
    return ds


# ---------------------------------------------------------------------------
# can_mutate()
# ---------------------------------------------------------------------------


class TestCanMutate:
    @pytest.fixture
    def fuzzer(self) -> StructuredReportFuzzer:
        return StructuredReportFuzzer()

    def test_true_for_sr_sop_class(self, fuzzer: StructuredReportFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _SR_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_content_sequence(
        self, fuzzer: StructuredReportFuzzer
    ) -> None:
        ds = Dataset()
        ds.ContentSequence = Sequence([])
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_without_content_seq(
        self, fuzzer: StructuredReportFuzzer
    ) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: StructuredReportFuzzer) -> None:
        assert fuzzer.can_mutate(Dataset()) is False

    def test_true_for_enhanced_sr(self, fuzzer: StructuredReportFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.88.22"
        assert fuzzer.can_mutate(ds) is True


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


def test_strategy_name() -> None:
    assert StructuredReportFuzzer().strategy_name == "structured_report"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    @pytest.fixture
    def fuzzer(self) -> StructuredReportFuzzer:
        return StructuredReportFuzzer()

    def test_returns_dataset(self, fuzzer: StructuredReportFuzzer) -> None:
        ds = _sr_dataset()
        assert isinstance(fuzzer.mutate(ds), Dataset)

    def test_sets_last_variant(self, fuzzer: StructuredReportFuzzer) -> None:
        fuzzer.mutate(_sr_dataset())
        assert isinstance(fuzzer.last_variant, str)

    def test_bare_dataset_does_not_raise(self, fuzzer: StructuredReportFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_bare_dataset()), Dataset)

    def test_multiple_variants_covered(self, fuzzer: StructuredReportFuzzer) -> None:
        variants = set()
        for _ in range(40):
            fuzzer.mutate(_sr_dataset())
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 3


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------


class TestCircularContentRef:
    def test_content_sequence_non_empty(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._circular_content_ref(ds)
        assert len(ds.ContentSequence) > 0

    def test_item_has_content_sequence(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._circular_content_ref(ds)
        item = ds.ContentSequence[0]
        assert hasattr(item, "ContentSequence")


class TestMissingValueType:
    def test_item_has_no_value_type(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._missing_value_type(ds)
        item = ds.ContentSequence[0]
        assert not hasattr(item, "ValueType")


class TestInvalidValueType:
    def test_value_type_not_standard(self) -> None:
        standard = {
            "TEXT",
            "NUM",
            "CODE",
            "IMAGE",
            "CONTAINER",
            "DATE",
            "TIME",
            "UIDREF",
        }
        fuzzer = StructuredReportFuzzer()
        for _ in range(20):
            ds = _sr_dataset()
            fuzzer._invalid_value_type(ds)
            item = ds.ContentSequence[0]
            assert item.ValueType not in standard


class TestNumWithNan:
    def test_numeric_value_is_nan(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._num_with_nan(ds)
        item = ds.ContentSequence[0]
        assert item.MeasuredValueSequence[0].NumericValue == "NaN"


class TestNumWithInf:
    def test_numeric_value_is_inf(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._num_with_inf(ds)
        item = ds.ContentSequence[0]
        assert item.MeasuredValueSequence[0].NumericValue == "Inf"


class TestImageRefMissing:
    def test_image_item_has_no_referenced_sop_seq(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._image_ref_missing(ds)
        item = ds.ContentSequence[0]
        assert item.ValueType == "IMAGE"
        assert not hasattr(item, "ReferencedSOPSequence")


class TestContainerNoChildren:
    def test_container_content_sequence_empty(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._container_no_children(ds)
        container = ds.ContentSequence[0]
        assert container.ValueType == "CONTAINER"
        assert len(container.ContentSequence) == 0


class TestExcessiveNesting:
    def test_nesting_depth_at_least_ten(self) -> None:
        """Verify 20-level nesting is produced."""
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._excessive_nesting(ds)

        depth = 0
        current = ds.ContentSequence[0] if ds.ContentSequence else None
        while current is not None:
            depth += 1
            children = getattr(current, "ContentSequence", None)
            if children and len(children) > 0:
                current = children[0]
            else:
                break
        assert depth >= 10  # at least 10 of the 20 levels verified


class TestCodeMissingScheme:
    def test_code_item_lacks_coding_scheme_designator(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._code_missing_scheme(ds)
        item = ds.ContentSequence[0]
        cn = item.ConceptNameCodeSequence[0]
        assert not hasattr(cn, "CodingSchemeDesignator")


class TestTextOversized:
    def test_text_value_is_large(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._text_oversized(ds)
        item = ds.ContentSequence[0]
        assert len(item.TextValue) >= 1024 * 1024


class TestNoContentSequence:
    def test_removes_content_sequence(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        assert hasattr(ds, "ContentSequence")
        fuzzer._no_content_sequence(ds)
        assert not hasattr(ds, "ContentSequence")

    def test_sets_sr_sop_class(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._no_content_sequence(ds)
        assert str(ds.SOPClassUID) == _SR_SOP


class TestDuplicateObservationUid:
    def test_two_items_with_same_uid(self) -> None:
        fuzzer = StructuredReportFuzzer()
        ds = _sr_dataset()
        fuzzer._duplicate_observation_uid(ds)
        items = ds.ContentSequence
        assert len(items) == 2
        assert items[0].ObservationUID == items[1].ObservationUID


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_structured_report_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "structured_report" in names

    def test_strategy_count_includes_sr(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        assert len(DicomMutator().strategies) >= 35
