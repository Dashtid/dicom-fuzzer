"""Pre-mutation safety checks for critical DICOM tags.

Provides snapshot/restore logic that preserves tags essential for file
parsing and routing.  Used by ``DicomMutator`` in ``_apply_single_mutation``
when a safety mode is active.

Safety modes:

* ``"lenient"`` -- protect Tier-1 tags only (TransferSyntaxUID).
  Files remain parseable but may be rejected at SOP classification.
* ``"strict"`` -- protect Tier-1/2/3 tags.  Files are accepted for
  storage/routing and reach deep parser code paths.
"""

from __future__ import annotations

import copy
from typing import Any

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Tag tiers
# ---------------------------------------------------------------------------

# Tier 1 -- without these the parser cannot decode the byte stream at all.
_TIER_1_FILE_META: frozenset[str] = frozenset({"TransferSyntaxUID"})
_TIER_1_DATASET: frozenset[str] = frozenset()

# Tier 2 -- file rejected at SOP classification stage.
_TIER_2_FILE_META: frozenset[str] = frozenset(
    {"MediaStorageSOPClassUID", "MediaStorageSOPInstanceUID"}
)
_TIER_2_DATASET: frozenset[str] = frozenset({"SOPClassUID"})

# Tier 3 -- file rejected at PACS routing / storage stage.
_TIER_3_DATASET: frozenset[str] = frozenset(
    {"SOPInstanceUID", "StudyInstanceUID", "SeriesInstanceUID"}
)

SAFETY_LEVELS: dict[str, dict[str, frozenset[str]]] = {
    "lenient": {
        "file_meta": _TIER_1_FILE_META,
        "dataset": _TIER_1_DATASET,
    },
    "strict": {
        "file_meta": _TIER_1_FILE_META | _TIER_2_FILE_META,
        "dataset": _TIER_1_DATASET | _TIER_2_DATASET | _TIER_3_DATASET,
    },
}

VALID_SAFETY_MODES: frozenset[str] = frozenset({"off", "lenient", "strict"})

# ---------------------------------------------------------------------------
# Snapshot / restore
# ---------------------------------------------------------------------------


def snapshot_critical_tags(dataset: Dataset, mode: str) -> dict[str, Any]:
    """Capture the current values of critical tags before mutation.

    Returns a dict keyed by ``"meta:<attr>"`` or ``"ds:<attr>"`` with
    shallow copies of the :class:`~pydicom.dataelem.DataElement` values.
    Only tags that actually exist on *dataset* are captured.
    """
    level = SAFETY_LEVELS.get(mode)
    if level is None:
        return {}

    snap: dict[str, Any] = {}

    # Dataset-level tags
    for attr in level["dataset"]:
        if hasattr(dataset, attr):
            snap[f"ds:{attr}"] = copy.copy(getattr(dataset, attr))

    # File-meta tags
    file_meta = getattr(dataset, "file_meta", None)
    if file_meta is not None:
        for attr in level["file_meta"]:
            if hasattr(file_meta, attr):
                snap[f"meta:{attr}"] = copy.copy(getattr(file_meta, attr))

    return snap


def restore_critical_tags(dataset: Dataset, snapshot: dict[str, Any], mode: str) -> int:
    """Restore critical tags that were deleted or changed by a mutation.

    Compares the current dataset state against *snapshot* and restores any
    critical tag that is now missing or has a different value.

    Returns the number of tags restored.
    """
    if not snapshot:
        return 0

    level = SAFETY_LEVELS.get(mode)
    if level is None:
        return 0

    restored = 0

    # Dataset-level tags
    for attr in level["dataset"]:
        key = f"ds:{attr}"
        if key not in snapshot:
            continue
        original = snapshot[key]
        current = getattr(dataset, attr, _SENTINEL)
        if current is _SENTINEL or current != original:
            setattr(dataset, attr, original)
            restored += 1
            logger.debug("Restored critical tag %s", attr)

    # File-meta tags
    file_meta = getattr(dataset, "file_meta", None)
    if file_meta is not None:
        for attr in level["file_meta"]:
            key = f"meta:{attr}"
            if key not in snapshot:
                continue
            original = snapshot[key]
            current = getattr(file_meta, attr, _SENTINEL)
            if current is _SENTINEL or current != original:
                setattr(file_meta, attr, original)
                restored += 1
                logger.debug("Restored critical file-meta tag %s", attr)

    return restored


# Sentinel for distinguishing "attribute missing" from "attribute is None".
_SENTINEL = object()
