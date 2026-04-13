"""Structured Report Fuzzer - DICOM SR Content Tree Mutations.

Category: structural

Targets Structured Report (SR) DICOM objects by corrupting the ContentSequence
tree, ConceptNameCodeSequence, and value-type attributes.

Attack surface rationale:
  SR parsers build a DOM-like tree from ContentSequence items. Each item
  has a RelationshipType, ValueType, and type-specific value attributes.
  Parsers that trust ValueType to dispatch to a decode path are vulnerable
  to type mismatches (e.g., declaring VALUE_TYPE="NUM" but providing
  MeasuredValueSequence with a NaN DS value, or declaring "IMAGE" with
  no ReferencedSOPSequence).

Dataset-level attacks:
- circular_content_ref: ContentSequence item references itself via UID
- missing_value_type: ContentSequence item with no ValueType
- invalid_value_type: ValueType = "INVALID" / "SQL" / empty string
- num_with_nan: NUM item with NaN in NumericValue
- num_with_inf: NUM item with Inf in NumericValue
- image_ref_missing: IMAGE item without ReferencedSOPSequence
- container_no_children: CONTAINER item with empty ContentSequence
- excessive_nesting: CONTAINER 20 levels deep (stack overflow risk)
- code_missing_scheme: CODE item with no CodingSchemeDesignator
- text_oversized: TEXT item with 1MB string value
- no_content_sequence: SR with SOPClassUID but no ContentSequence
- duplicate_observation_uid: Two content items with identical ObservationUID
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Basic Text SR SOP Class UID
_SR_SOP = "1.2.840.10008.5.1.4.1.1.88.11"

# All SR SOP class UIDs
_SR_SOP_CLASSES = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.88.11",  # Basic Text SR
        "1.2.840.10008.5.1.4.1.1.88.22",  # Enhanced SR
        "1.2.840.10008.5.1.4.1.1.88.33",  # Comprehensive SR
        "1.2.840.10008.5.1.4.1.1.88.34",  # Comprehensive 3D SR
        "1.2.840.10008.5.1.4.1.1.88.35",  # Extensible SR
        "1.2.840.10008.5.1.4.1.1.88.40",  # Procedure Log
        "1.2.840.10008.5.1.4.1.1.88.50",  # Mammography CAD SR
        "1.2.840.10008.5.1.4.1.1.88.65",  # Chest CAD SR
        "1.2.840.10008.5.1.4.1.1.88.67",  # X-Ray Radiation Dose SR
        "1.2.840.10008.5.1.4.1.1.88.68",  # Radiopharmaceutical Radiation Dose SR
        "1.2.840.10008.5.1.4.1.1.88.69",  # Colon CAD SR
        "1.2.840.10008.5.1.4.1.1.88.70",  # Implantation Plan SR
        "1.2.840.10008.5.1.4.1.1.88.71",  # Acquisition Context SR
        "1.2.840.10008.5.1.4.1.1.88.72",  # Simplified Adult Echo SR
    }
)


def _make_code_seq(meaning: str = "Finding", code: str = "404684003") -> Sequence:
    """Return a minimal CodeSequence item."""
    item = Dataset()
    item.CodeValue = code
    item.CodingSchemeDesignator = "SCT"
    item.CodeMeaning = meaning
    return Sequence([item])


def _make_container_item(children: list[Dataset] | None = None) -> Dataset:
    """Return a minimal CONTAINER content item."""
    item = Dataset()
    item.RelationshipType = "CONTAINS"
    item.ValueType = "CONTAINER"
    item.ConceptNameCodeSequence = _make_code_seq()
    item.ContinuityOfContent = "SEPARATE"
    item.ContentSequence = Sequence(children or [])
    return item


def _make_num_item(value: str = "42") -> Dataset:
    """Return a minimal NUM content item."""
    item = Dataset()
    item.RelationshipType = "CONTAINS"
    item.ValueType = "NUM"
    item.ConceptNameCodeSequence = _make_code_seq("Measurement")
    mv = Dataset()
    mv.NumericValue = value
    mv.MeasurementUnitsCodeSequence = _make_code_seq("mm", "mm")
    item.MeasuredValueSequence = Sequence([mv])
    return item


def _make_text_item(value: str = "Normal") -> Dataset:
    """Return a minimal TEXT content item."""
    item = Dataset()
    item.RelationshipType = "CONTAINS"
    item.ValueType = "TEXT"
    item.ConceptNameCodeSequence = _make_code_seq("Description")
    item.TextValue = value
    return item


def _make_image_item() -> Dataset:
    """Return a minimal IMAGE content item."""
    item = Dataset()
    item.RelationshipType = "CONTAINS"
    item.ValueType = "IMAGE"
    item.ConceptNameCodeSequence = _make_code_seq("Source Image")
    ref = Dataset()
    ref.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    ref.ReferencedSOPInstanceUID = "1.2.3.4.5.6"
    item.ReferencedSOPSequence = Sequence([ref])
    return item


class StructuredReportFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Structured Report ContentSequence trees.

    Targets SR parsers through type mismatches, missing required sub-elements,
    extreme string values, and deep nesting.
    """

    def __init__(self) -> None:
        """Initialize SR fuzzer."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "structured_report"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True for SR datasets or datasets with ContentSequence."""
        has_content_seq = hasattr(dataset, "ContentSequence")
        sop_class = str(getattr(dataset, "SOPClassUID", ""))
        return has_content_seq or sop_class in _SR_SOP_CLASSES

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply SR content tree mutation.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        attacks = [
            self._circular_content_ref,
            self._missing_value_type,
            self._invalid_value_type,
            self._num_with_nan,
            self._num_with_inf,
            self._image_ref_missing,
            self._container_no_children,
            self._excessive_nesting,
            self._code_missing_scheme,
            self._text_oversized,
            self._no_content_sequence,
            self._duplicate_observation_uid,
        ]

        attack = random.choice(attacks)
        try:
            attack(dataset)
            self.last_variant = attack.__name__.lstrip("_")
        except Exception:
            self.last_variant = "fallback"
            self._no_content_sequence(dataset)

        return dataset

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_sr_root(self, dataset: Dataset) -> None:
        """Ensure dataset has SOPClassUID and a root ContentSequence."""
        if not getattr(dataset, "SOPClassUID", None):
            dataset.SOPClassUID = _SR_SOP
        if not hasattr(dataset, "ContentSequence"):
            root = _make_container_item([_make_text_item()])
            dataset.ContentSequence = Sequence([root])

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def _circular_content_ref(self, dataset: Dataset) -> None:
        """ContentSequence item referencing itself via ReferencedContentItemIdentifier."""
        self._ensure_sr_root(dataset)
        item = Dataset()
        item.RelationshipType = "CONTAINS"
        item.ValueType = "CONTAINER"
        item.ConceptNameCodeSequence = _make_code_seq()
        item.ContinuityOfContent = "SEPARATE"
        # Self-referential: point back to the same item's position
        item.ReferencedContentItemIdentifier = [1, 1]  # Points to root item 1
        # Nest the item inside its own ContentSequence
        item.ContentSequence = Sequence([item])  # Circular reference
        dataset.ContentSequence = Sequence([item])

    def _missing_value_type(self, dataset: Dataset) -> None:
        """ContentSequence item with no ValueType attribute."""
        self._ensure_sr_root(dataset)
        bad_item = Dataset()
        bad_item.RelationshipType = "CONTAINS"
        # Deliberately omit ValueType
        bad_item.ConceptNameCodeSequence = _make_code_seq()
        bad_item.TextValue = "Missing ValueType"
        dataset.ContentSequence = Sequence([bad_item])

    def _invalid_value_type(self, dataset: Dataset) -> None:
        """ContentSequence item with unrecognized ValueType string."""
        self._ensure_sr_root(dataset)
        bad_value_types = ["INVALID", "SQL", "", "NULL", "0x41", "IMAGE\x00"]
        item = Dataset()
        item.RelationshipType = "CONTAINS"
        item.ValueType = random.choice(bad_value_types)
        item.ConceptNameCodeSequence = _make_code_seq()
        dataset.ContentSequence = Sequence([item])

    def _num_with_nan(self, dataset: Dataset) -> None:
        """NUM item with NaN in NumericValue (NaN propagates through calculations)."""
        self._ensure_sr_root(dataset)
        item = _make_num_item("NaN")
        dataset.ContentSequence = Sequence([item])

    def _num_with_inf(self, dataset: Dataset) -> None:
        """NUM item with Inf in NumericValue (overflow in display pipeline)."""
        self._ensure_sr_root(dataset)
        item = _make_num_item("Inf")
        dataset.ContentSequence = Sequence([item])

    def _image_ref_missing(self, dataset: Dataset) -> None:
        """IMAGE item without ReferencedSOPSequence (NULL deref on image lookup)."""
        self._ensure_sr_root(dataset)
        item = Dataset()
        item.RelationshipType = "CONTAINS"
        item.ValueType = "IMAGE"
        item.ConceptNameCodeSequence = _make_code_seq()
        # Deliberately omit ReferencedSOPSequence
        dataset.ContentSequence = Sequence([item])

    def _container_no_children(self, dataset: Dataset) -> None:
        """CONTAINER item with empty ContentSequence (parser may dereference first child)."""
        self._ensure_sr_root(dataset)
        container = _make_container_item([])  # Empty children
        dataset.ContentSequence = Sequence([container])

    def _excessive_nesting(self, dataset: Dataset) -> None:
        """CONTAINER nested 20 levels deep (stack overflow risk in recursive parsers)."""
        self._ensure_sr_root(dataset)
        # Build inside-out: deepest item first
        leaf = _make_text_item("deepest")
        current = _make_container_item([leaf])
        for _ in range(19):  # 1 leaf + 19 more = 20 levels
            current = _make_container_item([current])
        dataset.ContentSequence = Sequence([current])

    def _code_missing_scheme(self, dataset: Dataset) -> None:
        """CODE item with ConceptNameCodeSequence lacking CodingSchemeDesignator."""
        self._ensure_sr_root(dataset)
        item = Dataset()
        item.RelationshipType = "CONTAINS"
        item.ValueType = "CODE"
        bad_code = Dataset()
        bad_code.CodeValue = "404684003"
        # Deliberately omit CodingSchemeDesignator
        bad_code.CodeMeaning = "Finding"
        item.ConceptNameCodeSequence = Sequence([bad_code])
        item.ConceptCodeSequence = Sequence([bad_code])
        dataset.ContentSequence = Sequence([item])

    def _text_oversized(self, dataset: Dataset) -> None:
        """TEXT item with 1MB string (buffer overflow in string handling)."""
        self._ensure_sr_root(dataset)
        item = _make_text_item("A" * (1024 * 1024))  # 1MB text
        dataset.ContentSequence = Sequence([item])

    def _no_content_sequence(self, dataset: Dataset) -> None:
        """SR with SOPClassUID but no ContentSequence (NULL deref if root is assumed)."""
        if hasattr(dataset, "ContentSequence"):
            del dataset.ContentSequence
        dataset.SOPClassUID = _SR_SOP

    def _duplicate_observation_uid(self, dataset: Dataset) -> None:
        """Two content items sharing the same ObservationUID (UID uniqueness violation)."""
        self._ensure_sr_root(dataset)
        obs_uid = "1.2.3.4.5.6.7.8.9.0"
        item_a = _make_text_item("First")
        item_a.ObservationUID = obs_uid
        item_b = _make_text_item("Second")
        item_b.ObservationUID = obs_uid  # Same UID -- should be unique
        dataset.ContentSequence = Sequence([item_a, item_b])
