"""Encapsulated PDF Fuzzer - DICOM Encapsulated Document Mutations.

Category: modality-specific (Encapsulated PDF)

Targets Encapsulated PDF Storage (1.2.840.10008.5.1.4.1.1.104.1)
objects with mutations specific to the embedded PDF payload and
document metadata.

Attack surfaces:
- EncapsulatedDocument (0042,0011) byte corruption and truncation
- MIMETypeOfEncapsulatedDocument (0042,0012) mismatches
- Malformed PDF content inside valid DICOM wrapper
- Document metadata (DocumentTitle, ConceptNameCodeSequence)
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_ENCAPSULATED_PDF_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.104.1"


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
            self._corrupt_encapsulated_document,
            self._mime_type_mismatch,
            self._malformed_pdf_injection,
            self._pdf_metadata_corruption,
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
            except NotImplementedError:
                logger.debug("Strategy %s not yet implemented", strategy.__name__)
            except Exception as e:
                logger.debug("Encapsulated PDF mutation failed: %s", e)

        return dataset

    def _corrupt_encapsulated_document(self, dataset: Dataset) -> Dataset:
        """Truncate, corrupt, or replace EncapsulatedDocument (0042,0011) bytes."""
        raise NotImplementedError

    def _mime_type_mismatch(self, dataset: Dataset) -> Dataset:
        """Set MIMETypeOfEncapsulatedDocument (0042,0012) to wrong content type."""
        raise NotImplementedError

    def _malformed_pdf_injection(self, dataset: Dataset) -> Dataset:
        """Keep valid DICOM wrapper but inject corrupted PDF payload."""
        raise NotImplementedError

    def _pdf_metadata_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt DocumentTitle and ConceptNameCodeSequence metadata."""
        raise NotImplementedError


__all__ = ["EncapsulatedPdfFuzzer"]
