"""Conformance Fuzzer - DICOM Conformance and Interoperability Mutations.

Targets DICOM conformance requirements including:
- SOP Class UIDs (what type of object this is)
- Transfer Syntax UIDs (how data is encoded)
- Meta Information version
- Implementation identifiers

These elements define how DICOM data should be interpreted.
Mismatches can cause:
- Wrong modality-specific processing
- Encoding/decoding failures
- Interoperability issues between systems
- Security vulnerabilities from unexpected code paths
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.tag import Tag
from pydicom.uid import (
    ExplicitVRBigEndian,
    ExplicitVRLittleEndian,
    generate_uid,
)

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase
from .uid_attacks import INVALID_UIDS

logger = get_logger(__name__)

# Common SOP Class UIDs
SOP_CLASSES = {
    "CT": "1.2.840.10008.5.1.4.1.1.2",
    "MR": "1.2.840.10008.5.1.4.1.1.4",
    "US": "1.2.840.10008.5.1.4.1.1.6.1",
    "XA": "1.2.840.10008.5.1.4.1.1.12.1",
    "CR": "1.2.840.10008.5.1.4.1.1.1",
    "DX": "1.2.840.10008.5.1.4.1.1.1.1",
    "MG": "1.2.840.10008.5.1.4.1.1.1.2",
    "NM": "1.2.840.10008.5.1.4.1.1.20",
    "PT": "1.2.840.10008.5.1.4.1.1.128",
    "RTDOSE": "1.2.840.10008.5.1.4.1.1.481.2",
    "RTPLAN": "1.2.840.10008.5.1.4.1.1.481.5",
    "RTSTRUCT": "1.2.840.10008.5.1.4.1.1.481.3",
    "SEG": "1.2.840.10008.5.1.4.1.1.66.4",
    "SR": "1.2.840.10008.5.1.4.1.1.88.11",  # Basic Text SR
    "PDF": "1.2.840.10008.5.1.4.1.1.104.1",
    "RAW": "1.2.840.10008.5.1.4.1.1.66",
    "SC": "1.2.840.10008.5.1.4.1.1.7",  # Secondary Capture
    "ENCAPSULATED_PDF": "1.2.840.10008.5.1.4.1.1.104.1",
    "ENCAPSULATED_CDA": "1.2.840.10008.5.1.4.1.1.104.2",
}

# Transfer Syntax UIDs
TRANSFER_SYNTAXES = {
    "implicit_vr_le": "1.2.840.10008.1.2",
    "explicit_vr_le": "1.2.840.10008.1.2.1",
    "explicit_vr_be": "1.2.840.10008.1.2.2",
    "deflated": "1.2.840.10008.1.2.1.99",
    "jpeg_baseline": "1.2.840.10008.1.2.4.50",
    "jpeg_extended": "1.2.840.10008.1.2.4.51",
    "jpeg_lossless": "1.2.840.10008.1.2.4.70",
    "jpeg_ls_lossless": "1.2.840.10008.1.2.4.80",
    "jpeg_ls_lossy": "1.2.840.10008.1.2.4.81",
    "jpeg2000_lossless": "1.2.840.10008.1.2.4.90",
    "jpeg2000_lossy": "1.2.840.10008.1.2.4.91",
    "rle": "1.2.840.10008.1.2.5",
    "mpeg2": "1.2.840.10008.1.2.4.100",
    "mpeg4": "1.2.840.10008.1.2.4.102",
}


class ConformanceFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM conformance elements.

    Targets the metadata that defines how DICOM data should be
    interpreted and processed.
    """

    def __init__(self) -> None:
        """Initialize the conformance fuzzer."""
        self.mutation_strategies = [
            self._invalid_sop_class,
            self._invalid_transfer_syntax,
            self._sop_transfer_mismatch,
            self._missing_file_meta,
            self._corrupted_file_meta,
            self._version_mismatch,
            self._implementation_uid_attack,
            self._modality_sop_mismatch,
            self._uid_format_violations,
            self._retired_syntax_attack,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "conformance"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply conformance-related mutations.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with conformance violations

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug(f"Conformance mutation failed: {e}")

        return dataset

    mutate_conformance = mutate

    def _ensure_file_meta(self, dataset: Dataset) -> None:
        """Ensure dataset has file_meta."""
        if not hasattr(dataset, "file_meta") or dataset.file_meta is None:
            dataset.file_meta = FileMetaDataset()
            dataset.file_meta.MediaStorageSOPClassUID = SOP_CLASSES["CT"]
            dataset.file_meta.MediaStorageSOPInstanceUID = generate_uid()
            dataset.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

    def _invalid_sop_class(self, dataset: Dataset) -> Dataset:
        """Set invalid or unknown SOP Class UID.

        Unknown SOP classes may trigger fallback code paths
        or cause rejection/crashes.
        """
        self._ensure_file_meta(dataset)

        attack = random.choice(
            [
                "completely_invalid",
                "unknown_but_valid_format",
                "retired_sop_class",
                "private_sop_class",
            ]
        )

        try:
            if attack == "completely_invalid":
                uid = random.choice(INVALID_UIDS)

            elif attack == "unknown_but_valid_format":
                # Valid format but unknown SOP class
                uid = "1.2.840.10008.5.1.4.1.1.999.999"

            elif attack == "retired_sop_class":
                # Retired SOP classes that may not be supported
                retired = [
                    "1.2.840.10008.5.1.4.1.1.5",  # Retired NM
                    "1.2.840.10008.5.1.4.1.1.6",  # Retired US
                    "1.2.840.10008.5.1.4.1.1.3",  # Retired US Multi-frame
                    "1.2.840.10008.5.1.1.27",  # Retired Stored Print
                ]
                uid = random.choice(retired)

            elif attack == "private_sop_class":
                # Private/vendor-specific SOP class
                uid = "1.3.6.1.4.1.12345.1.2.3.4"  # Fake vendor

            dataset.file_meta.MediaStorageSOPClassUID = uid
            dataset.SOPClassUID = uid

        except Exception as e:
            logger.debug(f"Invalid SOP class attack failed: {e}")

        return dataset

    def _invalid_transfer_syntax(self, dataset: Dataset) -> Dataset:
        """Set invalid or unsupported Transfer Syntax UID.

        Transfer syntax determines how pixel data is encoded.
        Wrong syntax causes decoding failures.
        """
        self._ensure_file_meta(dataset)

        attack = random.choice(
            [
                "completely_invalid",
                "unknown_syntax",
                "retired_syntax",
                "private_syntax",
            ]
        )

        try:
            if attack == "completely_invalid":
                uid = random.choice(INVALID_UIDS)

            elif attack == "unknown_syntax":
                # Valid format but unknown transfer syntax
                uid = "1.2.840.10008.1.2.999"

            elif attack == "retired_syntax":
                # Retired transfer syntaxes
                retired = [
                    "1.2.840.10008.1.2.4.52",  # Retired JPEG Extended
                    "1.2.840.10008.1.2.4.53",  # Retired Spectral JPEG
                    "1.2.840.10008.1.2.4.54",  # Retired Progressive JPEG
                    "1.2.840.10008.1.2.4.55",  # Retired Lossless JPEG
                ]
                uid = random.choice(retired)

            elif attack == "private_syntax":
                uid = "1.3.6.1.4.1.12345.1.2"

            dataset.file_meta.TransferSyntaxUID = uid

        except Exception as e:
            logger.debug(f"Invalid transfer syntax attack failed: {e}")

        return dataset

    def _sop_transfer_mismatch(self, dataset: Dataset) -> Dataset:
        """Create mismatch between SOP class and transfer syntax.

        Some combinations are invalid (e.g., video syntax with CT).
        """
        self._ensure_file_meta(dataset)

        mismatches = [
            # (SOP Class, Incompatible Transfer Syntax)
            (SOP_CLASSES["CT"], TRANSFER_SYNTAXES["mpeg2"]),  # CT with video
            (SOP_CLASSES["SR"], TRANSFER_SYNTAXES["jpeg_baseline"]),  # SR with JPEG
            (SOP_CLASSES["PDF"], TRANSFER_SYNTAXES["rle"]),  # PDF with RLE
            (SOP_CLASSES["RTDOSE"], TRANSFER_SYNTAXES["mpeg4"]),  # RT with video
        ]

        try:
            sop, ts = random.choice(mismatches)
            dataset.file_meta.MediaStorageSOPClassUID = sop
            dataset.SOPClassUID = sop
            dataset.file_meta.TransferSyntaxUID = ts

        except Exception as e:
            logger.debug(f"SOP/Transfer mismatch attack failed: {e}")

        return dataset

    def _missing_file_meta(self, dataset: Dataset) -> Dataset:
        """Remove or corrupt required File Meta Information.

        File Meta is required for Part 10 files but may be
        missing or incomplete.
        """
        attack = random.choice(
            [
                "remove_all",
                "remove_sop_class",
                "remove_transfer_syntax",
                "remove_sop_instance",
            ]
        )

        try:
            if attack == "remove_all":
                if hasattr(dataset, "file_meta"):
                    dataset.file_meta = None

            elif attack == "remove_sop_class":
                self._ensure_file_meta(dataset)
                if hasattr(dataset.file_meta, "MediaStorageSOPClassUID"):
                    del dataset.file_meta.MediaStorageSOPClassUID

            elif attack == "remove_transfer_syntax":
                self._ensure_file_meta(dataset)
                if hasattr(dataset.file_meta, "TransferSyntaxUID"):
                    del dataset.file_meta.TransferSyntaxUID

            elif attack == "remove_sop_instance":
                self._ensure_file_meta(dataset)
                if hasattr(dataset.file_meta, "MediaStorageSOPInstanceUID"):
                    del dataset.file_meta.MediaStorageSOPInstanceUID

        except Exception as e:
            logger.debug(f"Missing file meta attack failed: {e}")

        return dataset

    def _corrupted_file_meta(self, dataset: Dataset) -> Dataset:
        """Corrupt File Meta Information fields.

        Corrupt the preamble, prefix, or version fields.
        """
        self._ensure_file_meta(dataset)

        attack = random.choice(
            [
                "wrong_preamble",
                "wrong_version",
                "extra_meta_elements",
                "wrong_meta_length",
            ]
        )

        try:
            if attack == "wrong_preamble":
                # Preamble should be 128 zero bytes (or application-specific)
                # but we set it to non-zero pattern
                dataset.preamble = b"\xff" * 128

            elif attack == "wrong_version":
                # FileMetaInformationVersion should be [0, 1]
                dataset.file_meta.FileMetaInformationVersion = b"\xff\xff"

            elif attack == "extra_meta_elements":
                # Add non-standard elements to file meta
                dataset.file_meta.add_new(
                    Tag(0x0002, 0x9999), "LO", "InvalidMetaElement"
                )

            elif attack == "wrong_meta_length":
                # FileMetaInformationGroupLength may be wrong
                dataset.file_meta.FileMetaInformationGroupLength = 99999

        except Exception as e:
            logger.debug(f"Corrupted file meta attack failed: {e}")

        return dataset

    def _version_mismatch(self, dataset: Dataset) -> Dataset:
        """Create version mismatches between components.

        Different DICOM versions may interpret data differently.
        """
        self._ensure_file_meta(dataset)

        try:
            attack = random.choice(
                [
                    "old_version",
                    "future_version",
                    "invalid_version",
                ]
            )

            if attack == "old_version":
                # Very old format indicators
                dataset.file_meta.FileMetaInformationVersion = b"\x00\x00"

            elif attack == "future_version":
                # Future version that doesn't exist
                dataset.file_meta.FileMetaInformationVersion = b"\x00\x99"

            elif attack == "invalid_version":
                # Invalid version bytes
                dataset.file_meta.FileMetaInformationVersion = b"\xff\xff\xff\xff"

        except Exception as e:
            logger.debug(f"Version mismatch attack failed: {e}")

        return dataset

    def _implementation_uid_attack(self, dataset: Dataset) -> Dataset:
        """Attack Implementation Class/Version UIDs.

        These identify the creating application. Some systems
        use them for compatibility decisions.
        """
        self._ensure_file_meta(dataset)

        try:
            attack = random.choice(
                [
                    "known_vulnerable",
                    "invalid_format",
                    "very_long",
                    "empty",
                ]
            )

            if attack == "known_vulnerable":
                # Impersonate a known implementation
                # (could trigger compatibility mode with bugs)
                implementations = [
                    ("1.2.276.0.7230010.3.0.3.6.0", "OFFIS_DCMTK_360"),
                    ("1.2.40.0.13.1.1", "dcm4che-1.x"),
                    ("1.2.840.113619.6.5", "GE_GENESIS"),
                ]
                uid, version = random.choice(implementations)
                dataset.file_meta.ImplementationClassUID = uid
                dataset.file_meta.ImplementationVersionName = version

            elif attack == "invalid_format":
                dataset.file_meta.ImplementationClassUID = random.choice(INVALID_UIDS)

            elif attack == "very_long":
                dataset.file_meta.ImplementationVersionName = "V" * 100

            elif attack == "empty":
                dataset.file_meta.ImplementationClassUID = ""
                dataset.file_meta.ImplementationVersionName = ""

        except Exception as e:
            logger.debug(f"Implementation UID attack failed: {e}")

        return dataset

    def _modality_sop_mismatch(self, dataset: Dataset) -> Dataset:
        """Create mismatch between Modality tag and SOP Class.

        Modality (0008,0060) should match the SOP Class type.
        Mismatches may cause wrong processing pipelines.
        """
        self._ensure_file_meta(dataset)

        # Mismatched pairs (Modality, wrong SOP Class)
        mismatches = [
            ("CT", SOP_CLASSES["MR"]),
            ("MR", SOP_CLASSES["CT"]),
            ("US", SOP_CLASSES["NM"]),
            ("PT", SOP_CLASSES["CR"]),
            ("RTDOSE", SOP_CLASSES["CT"]),
            ("SR", SOP_CLASSES["US"]),
        ]

        try:
            modality, sop = random.choice(mismatches)
            dataset.Modality = modality
            dataset.file_meta.MediaStorageSOPClassUID = sop
            dataset.SOPClassUID = sop

        except Exception as e:
            logger.debug(f"Modality/SOP mismatch attack failed: {e}")

        return dataset

    def _uid_format_violations(self, dataset: Dataset) -> Dataset:
        """Create various UID format violations across the dataset.

        UIDs have strict format requirements that are often
        not properly validated.
        """
        uid_tags = [
            (Tag(0x0008, 0x0016), "SOPClassUID"),
            (Tag(0x0008, 0x0018), "SOPInstanceUID"),
            (Tag(0x0020, 0x000D), "StudyInstanceUID"),
            (Tag(0x0020, 0x000E), "SeriesInstanceUID"),
            (Tag(0x0008, 0x0020), "StudyDate"),  # Not a UID but test wrong VR
        ]

        try:
            tag, name = random.choice(uid_tags[:4])  # Only actual UID tags
            dataset.add_new(tag, "UI", random.choice(INVALID_UIDS))
        except Exception as e:
            logger.debug(f"UID format violation attack failed: {e}")

        return dataset

    def _retired_syntax_attack(self, dataset: Dataset) -> Dataset:
        """Use retired or deprecated syntaxes/classes.

        Retired elements may have incomplete support or
        trigger legacy code paths with bugs.
        """
        self._ensure_file_meta(dataset)

        try:
            attack = random.choice(
                [
                    "retired_transfer_syntax",
                    "retired_sop_with_modern_syntax",
                    "explicit_vr_big_endian",
                ]
            )

            if attack == "retired_transfer_syntax":
                # Retired JPEG syntaxes
                retired_ts = [
                    "1.2.840.10008.1.2.4.52",
                    "1.2.840.10008.1.2.4.53",
                    "1.2.840.10008.1.2.4.54",
                ]
                dataset.file_meta.TransferSyntaxUID = random.choice(retired_ts)

            elif attack == "retired_sop_with_modern_syntax":
                # Old SOP class with new transfer syntax
                dataset.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.5"
                dataset.file_meta.TransferSyntaxUID = TRANSFER_SYNTAXES[
                    "jpeg2000_lossless"
                ]

            elif attack == "explicit_vr_big_endian":
                # Big Endian is retired but may still need support
                dataset.file_meta.TransferSyntaxUID = ExplicitVRBigEndian

        except Exception as e:
            logger.debug(f"Retired syntax attack failed: {e}")

        return dataset
