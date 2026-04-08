"""DICOM dataset sanitizer -- strip PHI from seed files.

Provides :func:`sanitize_dataset` for in-memory sanitization and
:func:`sanitize_file` / :func:`sanitize_directory` for file-level
operations.  Calls :func:`anonymize_patient_info` for the three core
patient demographics and handles the full PHI tag set on top.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

import pydicom
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.utils.anonymizer import anonymize_patient_info
from dicom_fuzzer.utils.phi_tags import (
    PHI_DATE_KEYWORDS,
    PHI_DELETE_KEYWORDS,
    PHI_UID_KEYWORDS,
)

# ---------------------------------------------------------------------------
# Dataset-level sanitization
# ---------------------------------------------------------------------------


def sanitize_dataset(
    dataset: Dataset,
    *,
    keep_private: bool = False,
    keep_uids: bool = False,
    date_offset_days: int | None = None,
    uid_map: dict[str, str] | None = None,
) -> Dataset:
    """Remove or replace PHI tags in *dataset* (mutated in-place).

    Args:
        dataset: DICOM dataset to sanitize.
        keep_private: If *True*, retain private (odd-group) tags.
        keep_uids: If *True*, do not regenerate UIDs.
        date_offset_days: Fixed date shift in days.  If *None*, a random
            offset between 30 and 3650 days is chosen.
        uid_map: Shared UID mapping table for consistent regeneration
            across multiple files in the same study.  Mutated in-place.

    Returns:
        The same dataset with PHI removed.

    """
    # 1. Core patient demographics (PatientName, PatientID, PatientBirthDate)
    anonymize_patient_info(dataset)

    # 2. Delete PHI tags
    for keyword in PHI_DELETE_KEYWORDS:
        if hasattr(dataset, keyword):
            delattr(dataset, keyword)

    # 3. Regenerate UIDs (with consistent mapping)
    if not keep_uids:
        if uid_map is None:
            uid_map = {}
        for keyword in PHI_UID_KEYWORDS:
            old_uid = getattr(dataset, keyword, None)
            if old_uid is not None:
                old_str = str(old_uid)
                if old_str not in uid_map:
                    uid_map[old_str] = generate_uid()
                setattr(dataset, keyword, uid_map[old_str])
        # Keep file_meta in sync
        _sync_file_meta_uids(dataset)

    # 4. Shift dates
    offset = (
        date_offset_days if date_offset_days is not None else random.randint(30, 3650)
    )
    _shift_dates(dataset, offset)

    # 5. Remove private tags
    if not keep_private:
        dataset.remove_private_tags()

    return dataset


# ---------------------------------------------------------------------------
# File / directory helpers
# ---------------------------------------------------------------------------


def sanitize_file(
    input_path: Path,
    output_path: Path,
    *,
    keep_private: bool = False,
    keep_uids: bool = False,
    date_offset_days: int | None = None,
    uid_map: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Read a DICOM file, sanitize it, and write to *output_path*.

    Returns:
        ``(True, "ok")`` on success or ``(False, error_message)`` on failure.

    """
    try:
        ds = pydicom.dcmread(str(input_path), force=True)
    except Exception as exc:
        return False, f"read error: {exc}"

    try:
        sanitize_dataset(
            ds,
            keep_private=keep_private,
            keep_uids=keep_uids,
            date_offset_days=date_offset_days,
            uid_map=uid_map,
        )
    except Exception as exc:
        return False, f"sanitize error: {exc}"

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        ds.save_as(str(output_path), write_like_original=False)
    except Exception as exc:
        return False, f"write error: {exc}"

    return True, "ok"


def sanitize_directory(
    input_dir: Path,
    output_dir: Path,
    *,
    keep_private: bool = False,
    keep_uids: bool = False,
    date_offset_days: int | None = None,
    recursive: bool = False,
) -> dict[str, int]:
    """Sanitize all DICOM files in *input_dir*.

    Returns:
        Dict with keys ``"processed"``, ``"succeeded"``, ``"failed"``.

    """
    pattern = "**/*.dcm" if recursive else "*.dcm"
    files = list(input_dir.glob(pattern))
    # Also pick up .dicom extension
    dicom_pattern = "**/*.dicom" if recursive else "*.dicom"
    files.extend(input_dir.glob(dicom_pattern))

    uid_map: dict[str, str] = {}
    stats = {"processed": 0, "succeeded": 0, "failed": 0}

    for filepath in files:
        rel = filepath.relative_to(input_dir)
        out_path = output_dir / rel
        ok, _msg = sanitize_file(
            filepath,
            out_path,
            keep_private=keep_private,
            keep_uids=keep_uids,
            date_offset_days=date_offset_days,
            uid_map=uid_map,
        )
        stats["processed"] += 1
        if ok:
            stats["succeeded"] += 1
        else:
            stats["failed"] += 1

    return stats


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _shift_dates(dataset: Dataset, offset_days: int) -> None:
    """Shift all PHI date tags by *offset_days* (positive = into the past)."""
    for keyword in PHI_DATE_KEYWORDS:
        raw = getattr(dataset, keyword, None)
        if raw is None:
            continue
        try:
            dt = datetime.strptime(str(raw), "%Y%m%d")
            shifted = dt - timedelta(days=offset_days)
            setattr(dataset, keyword, shifted.strftime("%Y%m%d"))
        except (ValueError, TypeError):
            # Unparseable date -- delete rather than leak
            delattr(dataset, keyword)


def _sync_file_meta_uids(dataset: Dataset) -> None:
    """Copy regenerated dataset UIDs into file_meta so the file is consistent."""
    meta = getattr(dataset, "file_meta", None)
    if meta is None:
        return
    sop_uid = getattr(dataset, "SOPInstanceUID", None)
    if sop_uid is not None and hasattr(meta, "MediaStorageSOPInstanceUID"):
        meta.MediaStorageSOPInstanceUID = sop_uid
    sop_class = getattr(dataset, "SOPClassUID", None)
    if sop_class is not None and hasattr(meta, "MediaStorageSOPClassUID"):
        meta.MediaStorageSOPClassUID = sop_class
