"""Tests for EncapsulatedPdfFuzzer."""

from __future__ import annotations

import copy
import random

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.encapsulated_pdf_fuzzer import (
    _ENCAPSULATED_PDF_SOP_CLASS_UID,
    EncapsulatedPdfFuzzer,
)

_MINIMAL_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF"


@pytest.fixture
def fuzzer() -> EncapsulatedPdfFuzzer:
    return EncapsulatedPdfFuzzer()


@pytest.fixture
def pdf_dataset() -> Dataset:
    """Dataset mimicking an Encapsulated PDF SOP instance."""
    ds = Dataset()
    ds.SOPClassUID = _ENCAPSULATED_PDF_SOP_CLASS_UID
    ds.EncapsulatedDocument = _MINIMAL_PDF
    ds.MIMETypeOfEncapsulatedDocument = "application/pdf"
    ds.DocumentTitle = "Test Report"
    ds.BurnedInAnnotation = "NO"

    seq_item = Dataset()
    seq_item.CodeValue = "11528-7"
    seq_item.CodingSchemeDesignator = "LN"
    seq_item.CodeMeaning = "Radiology Report"
    ds.ConceptNameCodeSequence = Sequence([seq_item])

    return ds


# ---------------------------------------------------------------------------
# can_mutate
# ---------------------------------------------------------------------------


class TestCanMutate:
    def test_accepts_pdf_sop_class(self, fuzzer: EncapsulatedPdfFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _ENCAPSULATED_PDF_SOP_CLASS_UID
        assert fuzzer.can_mutate(ds) is True

    def test_rejects_ct_sop_class(self, fuzzer: EncapsulatedPdfFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_rejects_missing_sop_class(self, fuzzer: EncapsulatedPdfFuzzer) -> None:
        ds = Dataset()
        assert fuzzer.can_mutate(ds) is False


# ---------------------------------------------------------------------------
# _document_size_attack
# ---------------------------------------------------------------------------


class TestDocumentSizeAttack:
    def test_zero_length(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        random.seed(0)  # "zero_length" is index 0
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._document_size_attack(ds)
            doc = getattr(result, "EncapsulatedDocument", None)
            if doc == b"":
                return
        pytest.fail("zero_length attack never triggered")

    def test_single_byte(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._document_size_attack(ds)
            doc = getattr(result, "EncapsulatedDocument", None)
            if doc == b"\x00":
                return
        pytest.fail("single_byte attack never triggered")

    def test_truncated(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._document_size_attack(ds)
            doc = getattr(result, "EncapsulatedDocument", None)
            if doc is not None and 0 < len(doc) < len(_MINIMAL_PDF):
                return
        pytest.fail("truncated attack never triggered")

    def test_remove_tag(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._document_size_attack(ds)
            if "EncapsulatedDocument" not in result:
                return
        pytest.fail("remove_tag attack never triggered")

    def test_oversized_padding(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._document_size_attack(ds)
            doc = getattr(result, "EncapsulatedDocument", None)
            if doc is not None and len(doc) > len(_MINIMAL_PDF) + 100_000:
                return
        pytest.fail("oversized_padding attack never triggered")

    def test_handles_missing_document(self, fuzzer: EncapsulatedPdfFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _ENCAPSULATED_PDF_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._document_size_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _mime_type_mismatch
# ---------------------------------------------------------------------------


class TestMimeTypeMismatch:
    def test_changes_mime_type(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        changed = False
        for i in range(30):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._mime_type_mismatch(ds)
            mime = getattr(result, "MIMETypeOfEncapsulatedDocument", None)
            if mime != "application/pdf":
                changed = True
                break
        assert changed, "MIME type was never changed"

    def test_wrong_type_variant(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        valid_wrong_types = {
            "image/jpeg",
            "text/html",
            "application/xml",
            "application/octet-stream",
            "text/plain",
            "application/x-executable",
        }
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._mime_type_mismatch(ds)
            mime = getattr(result, "MIMETypeOfEncapsulatedDocument", None)
            if mime in valid_wrong_types:
                return
        pytest.fail("wrong_type variant never triggered")

    def test_remove_tag_variant(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._mime_type_mismatch(ds)
            if "MIMETypeOfEncapsulatedDocument" not in result:
                return
        pytest.fail("remove_tag variant never triggered")

    def test_handles_missing_mime(self, fuzzer: EncapsulatedPdfFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _ENCAPSULATED_PDF_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._mime_type_mismatch(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# _malformed_pdf_injection
# ---------------------------------------------------------------------------


class TestMalformedPdfInjection:
    def test_replaces_with_non_pdf(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        replaced = False
        for i in range(30):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._malformed_pdf_injection(ds)
            doc = getattr(result, "EncapsulatedDocument", _MINIMAL_PDF)
            if doc != _MINIMAL_PDF:
                replaced = True
                break
        assert replaced, "Payload was never replaced"

    def test_all_payload_types_reachable(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        seen = set()
        for i in range(200):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._malformed_pdf_injection(ds)
            doc = result.EncapsulatedDocument
            if doc.startswith(b"\xff\xd8"):
                seen.add("jpeg")
            elif doc.startswith(b"\x89PNG"):
                seen.add("png")
            elif doc.startswith(b"PK"):
                seen.add("zip")
            elif doc.startswith(b"\x7fELF"):
                seen.add("elf")
            elif doc.startswith(b"%PDF") and b"\x00" * 16 in doc:
                seen.add("pdf_garbage")
            elif doc.startswith(b"<?xml"):
                seen.add("xml")
            elif doc.startswith(b"<html"):
                seen.add("html")
        assert len(seen) >= 5, f"Only hit {len(seen)} payload types: {seen}"

    def test_handles_missing_document(self, fuzzer: EncapsulatedPdfFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _ENCAPSULATED_PDF_SOP_CLASS_UID
        result = fuzzer._malformed_pdf_injection(ds)
        assert hasattr(result, "EncapsulatedDocument")


# ---------------------------------------------------------------------------
# _pdf_metadata_corruption
# ---------------------------------------------------------------------------


class TestPdfMetadataCorruption:
    def test_corrupts_document_title(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        changed = False
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._pdf_metadata_corruption(ds)
            title = getattr(result, "DocumentTitle", "Test Report")
            if title != "Test Report":
                changed = True
                break
        assert changed, "DocumentTitle was never corrupted"

    def test_corrupts_concept_name_sequence(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        changed = False
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            original_code = ds.ConceptNameCodeSequence[0].CodeValue
            result = fuzzer._pdf_metadata_corruption(ds)
            seq = getattr(result, "ConceptNameCodeSequence", None)
            if seq is None:
                changed = True
                break
            if len(seq) > 0 and seq[0].CodeValue != original_code:
                changed = True
                break
        assert changed, "ConceptNameCodeSequence was never corrupted"

    def test_burned_in_annotation(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            result = fuzzer._pdf_metadata_corruption(ds)
            val = getattr(result, "BurnedInAnnotation", "NO")
            if val not in ("YES", "NO"):
                return
        pytest.fail("burned_in_annotation variant never triggered")

    def test_handles_minimal_dataset(self, fuzzer: EncapsulatedPdfFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _ENCAPSULATED_PDF_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._pdf_metadata_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


# ---------------------------------------------------------------------------
# mutate() integration
# ---------------------------------------------------------------------------


class TestMutateIntegration:
    def test_returns_dataset(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        result = fuzzer.mutate(copy.deepcopy(pdf_dataset))
        assert isinstance(result, Dataset)

    def test_does_not_raise(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        for i in range(20):
            random.seed(i)
            fuzzer.mutate(copy.deepcopy(pdf_dataset))

    def test_modifies_dataset(
        self, fuzzer: EncapsulatedPdfFuzzer, pdf_dataset: Dataset
    ) -> None:
        modified = False
        for i in range(30):
            random.seed(i)
            ds = copy.deepcopy(pdf_dataset)
            original_doc = ds.EncapsulatedDocument
            original_mime = ds.MIMETypeOfEncapsulatedDocument
            original_title = ds.DocumentTitle
            result = fuzzer.mutate(ds)
            doc = getattr(result, "EncapsulatedDocument", None)
            mime = getattr(result, "MIMETypeOfEncapsulatedDocument", None)
            title = getattr(result, "DocumentTitle", None)
            if doc != original_doc or mime != original_mime or title != original_title:
                modified = True
                break
        assert modified, "mutate() never modified the dataset"

    def test_handles_empty_dataset(self, fuzzer: EncapsulatedPdfFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _ENCAPSULATED_PDF_SOP_CLASS_UID
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)
