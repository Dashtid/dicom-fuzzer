"""DICOM-aware crash minimizer.

Takes a crashing DICOM file and reduces it to the smallest subset of
DICOM elements that still produces the same target return code.
Output is always a structurally valid DICOM file (parseable by pydicom)
so it can be filed as an upstream issue with a real `.dcm` reproducer.

Phase A only: top-level element removal via delta debugging (ddmin).
Per-element value reduction is deferred to Phase B.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypeVar

import pydicom
from pydicom.dataset import Dataset, FileDataset

from dicom_fuzzer.utils.logger import get_logger

__all__ = [
    "MinimizeContext",
    "MinimizeResult",
    "MinimizationError",
    "ddmin",
    "minimize_dicom",
]

logger = get_logger(__name__)

T = TypeVar("T")


class MinimizationError(RuntimeError):
    """Raised when minimization cannot proceed."""


@dataclass
class MinimizeContext:
    """Per-run state for one minimization, carried through ddmin trials."""

    target_exe: Path
    expected_returncode: int
    timeout: float
    max_trials: int
    trial_count: int = 0


@dataclass
class MinimizeResult:
    """Outcome of a minimization run."""

    original_element_count: int
    minimized_element_count: int
    original_byte_size: int
    minimized_byte_size: int
    trial_count: int
    elements_kept: list[str] = field(default_factory=list)
    elements_removed: list[str] = field(default_factory=list)

    @property
    def reduction_ratio(self) -> float:
        """Fraction of elements removed (0.0 = none, 1.0 = all)."""
        if self.original_element_count == 0:
            return 0.0
        return 1.0 - (self.minimized_element_count / self.original_element_count)


def ddmin(items: list[T], predicate: Callable[[list[T]], bool]) -> list[T]:
    """Generic delta debugging.

    Returns the smallest subset of *items* (in original order) for which
    *predicate* still returns True. *predicate* receives a list and must
    return True iff the property of interest still holds.

    Standard ddmin from Zeller & Hildebrandt (2002): try each chunk
    alone, then each complement, then refine granularity. O(n²) worst case.
    """
    items = list(items)
    n = 2
    while len(items) >= 2:
        chunk_size = max(1, len(items) // n)
        chunks = [items[i : i + chunk_size] for i in range(0, len(items), chunk_size)]

        reduced = False
        # Try each chunk alone
        for chunk in chunks:
            if predicate(chunk):
                items = chunk
                n = 2
                reduced = True
                break

        if not reduced:
            # Try complements (everything except chunk i)
            for i in range(len(chunks)):
                complement = [
                    item for j, c in enumerate(chunks) for item in c if j != i
                ]
                if complement and predicate(complement):
                    items = complement
                    n = max(n - 1, 2)
                    reduced = True
                    break

        if not reduced:
            if n >= len(items):
                break
            n = min(n * 2, len(items))

    return items


def _build_dataset_subset(
    ds_orig: FileDataset, keep_tags: Iterable[int]
) -> FileDataset:
    """Return a fresh FileDataset containing only elements whose tags are in keep_tags.

    Builds from scratch rather than calling ds_orig.copy(): pydicom's Dataset.copy()
    shares the underlying dict, so deletions leak back to ds_orig and corrupt
    subsequent ddmin trials.
    """
    keep = set(keep_tags)
    new_ds = FileDataset(
        filename_or_obj="",
        dataset={},
        file_meta=ds_orig.file_meta,
        preamble=ds_orig.preamble,
    )
    # Preserve transfer-syntax flags so save_as picks the right encoding
    if hasattr(ds_orig, "is_little_endian"):
        new_ds.is_little_endian = ds_orig.is_little_endian
    if hasattr(ds_orig, "is_implicit_VR"):
        new_ds.is_implicit_VR = ds_orig.is_implicit_VR
    for elem in ds_orig:
        if elem.tag in keep:
            new_ds[elem.tag] = elem
    return new_ds


def _run_target(ds: Dataset, ctx: MinimizeContext) -> int | None:
    """Write *ds* to a temp .dcm, run target on it, return exit code.

    Returns None if the trial budget is exhausted or the file can't be written.
    """
    if ctx.trial_count >= ctx.max_trials:
        return None
    ctx.trial_count += 1

    fd, tmp_path = tempfile.mkstemp(suffix=".dcm")
    os.close(fd)
    try:
        try:
            ds.save_as(tmp_path, write_like_original=False)
        except Exception as exc:
            logger.debug("save_as failed during minimization: %s", exc)
            return None

        try:
            result = subprocess.run(
                [str(ctx.target_exe), tmp_path],
                timeout=ctx.timeout,
                capture_output=True,
            )
            return result.returncode
        except subprocess.TimeoutExpired:
            return None
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _make_predicate(
    ds_orig: FileDataset, ctx: MinimizeContext
) -> Callable[[list[pydicom.DataElement]], bool]:
    """Build the predicate ddmin will call: 'does this subset still crash?'"""

    def predicate(subset: list[pydicom.DataElement]) -> bool:
        candidate = _build_dataset_subset(ds_orig, (e.tag for e in subset))
        rc = _run_target(candidate, ctx)
        return rc == ctx.expected_returncode

    return predicate


def minimize_dicom(
    crashing_path: Path,
    target_exe: Path,
    expected_returncode: int,
    timeout: float = 10.0,
    max_trials: int = 500,
    output_path: Path | None = None,
) -> MinimizeResult:
    """Minimize *crashing_path* to a smaller .dcm that still triggers *expected_returncode*.

    Args:
        crashing_path: Path to the original crashing DICOM file.
        target_exe: Path to the harness/target executable.
        expected_returncode: Exit code that defines "still crashes the same way".
        timeout: Per-trial timeout in seconds.
        max_trials: Hard cap on subprocess invocations (safety).
        output_path: Where to write the minimized file. Defaults to
            ``<crashing_path>.minimized.dcm`` next to the input.

    Returns:
        MinimizeResult with stats about the reduction.

    Raises:
        MinimizationError: if the original file doesn't produce
            expected_returncode (can't minimize what doesn't crash).
        FileNotFoundError: if crashing_path or target_exe is missing.

    """
    crashing_path = Path(crashing_path)
    target_exe = Path(target_exe)
    if not crashing_path.exists():
        raise FileNotFoundError(f"Crashing file not found: {crashing_path}")
    if not target_exe.exists():
        raise FileNotFoundError(f"Target executable not found: {target_exe}")

    ds_orig = pydicom.dcmread(str(crashing_path), force=True)
    original_elements = list(ds_orig)
    original_size = crashing_path.stat().st_size

    ctx = MinimizeContext(
        target_exe=target_exe,
        expected_returncode=expected_returncode,
        timeout=timeout,
        max_trials=max_trials,
    )

    # Sanity check: original file must actually crash with the expected code.
    rc = _run_target(ds_orig, ctx)
    if rc != expected_returncode:
        raise MinimizationError(
            f"Original file does not reproduce expected exit code "
            f"(got {rc}, expected {expected_returncode}). "
            f"Cannot minimize a non-reproducing crash."
        )

    predicate = _make_predicate(ds_orig, ctx)
    minimal_elements = ddmin(original_elements, predicate)

    final_ds = _build_dataset_subset(ds_orig, (e.tag for e in minimal_elements))

    if output_path is None:
        output_path = crashing_path.with_suffix(".minimized.dcm")
    output_path = Path(output_path)
    final_ds.save_as(str(output_path), write_like_original=False)

    kept_tags = {e.tag for e in minimal_elements}
    elements_kept = [
        f"{e.tag} {e.name}" for e in original_elements if e.tag in kept_tags
    ]
    elements_removed = [
        f"{e.tag} {e.name}" for e in original_elements if e.tag not in kept_tags
    ]

    return MinimizeResult(
        original_element_count=len(original_elements),
        minimized_element_count=len(minimal_elements),
        original_byte_size=original_size,
        minimized_byte_size=output_path.stat().st_size,
        trial_count=ctx.trial_count,
        elements_kept=elements_kept,
        elements_removed=elements_removed,
    )
