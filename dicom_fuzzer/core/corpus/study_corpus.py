"""Study Corpus Manager - Manages 3D DICOM studies as atomic corpus units.

Provides study-level corpus management for fuzzing complete 3D DICOM studies
(multi-slice volumes) as atomic units.
    manager.add_study(Path("./my_study"))
    next_study = manager.get_next_study()
    manager.update_priority(next_study.study_id, crash_found=True)
    manager.save_index()
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pydicom
from pydicom.errors import InvalidDicomError

from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CrashInfo(SerializableMixin):
    """Information about a crash triggered by a study."""

    crash_id: str
    crash_type: str  # ACCESS_VIOLATION, HEAP_CORRUPTION, etc.
    timestamp: str
    trigger_slice: str | None = None  # Specific slice that triggered crash
    exit_code: int | None = None
    notes: str | None = None


@dataclass
class SeriesInfo(SerializableMixin):
    """Information about a series within a study."""

    series_uid: str
    modality: str
    slice_count: int
    is_multiframe: bool = False
    description: str | None = None


@dataclass
class StudyCorpusEntry(SerializableMixin):
    """Entry for a 3D DICOM study in the corpus."""

    study_id: str  # Hash-based unique ID
    study_dir: str  # Path to study directory (stored as string for JSON)
    study_uid: str  # DICOM StudyInstanceUID
    patient_id: str | None = None
    study_date: str | None = None
    study_description: str | None = None
    series_list: list[SeriesInfo] = field(default_factory=list)
    total_slices: int = 0
    modalities: list[str] = field(
        default_factory=list
    )  # Changed from set to list for JSON
    mutations_applied: list[str] = field(default_factory=list)
    crashes_triggered: list[CrashInfo] = field(default_factory=list)
    priority: int = 3  # 1=highest, 5=lowest
    test_count: int = 0
    last_tested: str | None = None  # ISO format datetime string
    added_timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def study_path(self) -> Path:
        """Get study directory as Path object."""
        return Path(self.study_dir)

    @property
    def crash_count(self) -> int:
        """Get number of crashes triggered by this study."""
        return len(self.crashes_triggered)

    @property
    def is_crash_triggering(self) -> bool:
        """Check if this study has triggered any crashes."""
        return len(self.crashes_triggered) > 0


class StudyCorpusManager:
    """Manages a corpus of 3D DICOM studies.

    Provides study-level tracking and priority-based selection
    for fuzzing complete 3D volumes.
    """

    INDEX_FILENAME = "study_corpus_index.json"
    STUDIES_DIRNAME = "studies"

    def __init__(self, corpus_dir: Path, auto_load: bool = True):
        """Initialize StudyCorpusManager.

        Args:
            corpus_dir: Directory to store corpus index and studies
            auto_load: Whether to load existing index on init

        """
        self.corpus_dir = corpus_dir
        self.studies_dir = corpus_dir / self.STUDIES_DIRNAME
        self.index_path = corpus_dir / self.INDEX_FILENAME
        self.studies: dict[str, StudyCorpusEntry] = {}

        # Create directories
        corpus_dir.mkdir(parents=True, exist_ok=True)
        self.studies_dir.mkdir(parents=True, exist_ok=True)

        if auto_load and self.index_path.exists():
            self.load_index()

        logger.info(
            "StudyCorpusManager initialized",
            corpus_dir=str(corpus_dir),
            study_count=len(self.studies),
        )

    def add_study(
        self,
        study_dir: Path,
        copy_to_corpus: bool = True,
        priority: int = 3,
    ) -> StudyCorpusEntry:
        """Add a study to the corpus.

        Args:
            study_dir: Directory containing DICOM slices
            copy_to_corpus: Whether to copy files to corpus directory
            priority: Initial priority (1=highest, 5=lowest)

        Returns:
            StudyCorpusEntry for the added study

        Raises:
            ValueError: If study directory is empty or invalid

        """
        if not study_dir.exists():
            raise ValueError(f"Study directory not found: {study_dir}")

        # Analyze study
        entry = self._analyze_study(study_dir)
        entry.priority = priority

        # Check for duplicate
        if entry.study_id in self.studies:
            logger.warning("Study already in corpus", study_id=entry.study_id)
            return self.studies[entry.study_id]

        # Copy to corpus if requested
        if copy_to_corpus:
            dest_dir = self.studies_dir / entry.study_id
            if not dest_dir.exists():
                shutil.copytree(study_dir, dest_dir)
                entry.study_dir = str(dest_dir)
                logger.info("Copied study to corpus", dest_dir=str(dest_dir))

        # Add to index
        self.studies[entry.study_id] = entry
        logger.info(
            "Added study",
            study_id=entry.study_id,
            total_slices=entry.total_slices,
            series_count=len(entry.series_list),
        )

        return entry

    def get_study(self, study_id: str) -> StudyCorpusEntry | None:
        """Get a study by ID.

        Args:
            study_id: Study ID

        Returns:
            StudyCorpusEntry or None if not found

        """
        return self.studies.get(study_id)

    def remove_study(self, study_id: str, delete_files: bool = False) -> bool:
        """Remove a study from the corpus.

        Args:
            study_id: Study ID to remove
            delete_files: Whether to delete study files

        Returns:
            True if study was removed

        """
        if study_id not in self.studies:
            return False

        entry = self.studies[study_id]

        if delete_files:
            study_path = Path(entry.study_dir)
            if study_path.exists() and study_path.is_relative_to(self.corpus_dir):
                shutil.rmtree(study_path, ignore_errors=True)
                logger.info("Deleted study files", study_path=str(study_path))

        del self.studies[study_id]
        logger.info("Removed study from corpus", study_id=study_id)
        return True

    def get_next_study(self) -> StudyCorpusEntry | None:
        """Get the next study to test based on priority.

        Priority factors:
        1. Numeric priority (lower = higher priority)
        2. Crash-triggering studies get priority boost
        3. Less-tested studies preferred
        4. Older last-tested preferred

        Returns:
            Next study to test, or None if corpus is empty

        """
        if not self.studies:
            return None

        def priority_score(entry: StudyCorpusEntry) -> tuple[float, str]:
            """Calculate priority score (lower = higher priority)."""
            # Base priority
            score = entry.priority

            # Boost for crash-triggering studies
            if entry.is_crash_triggering:
                score -= 1

            # Prefer less-tested studies
            test_penalty = min(entry.test_count / 10, 2)

            # Prefer older last-tested
            if entry.last_tested:
                try:
                    last_dt = datetime.fromisoformat(entry.last_tested)
                    # Handle both naive (legacy) and aware timestamps
                    if last_dt.tzinfo is None:
                        last_dt = last_dt.replace(tzinfo=UTC)
                    hours_since = (datetime.now(UTC) - last_dt).total_seconds() / 3600
                    recency_penalty = max(0, 1 - hours_since / 24)  # Decay over 24h
                except ValueError:
                    recency_penalty = 0
            else:
                recency_penalty = -1  # Never tested = highest priority

            return (score + test_penalty + recency_penalty, entry.study_id)

        sorted_studies = sorted(self.studies.values(), key=priority_score)
        return sorted_studies[0] if sorted_studies else None

    def prioritize_studies(self) -> list[StudyCorpusEntry]:
        """Get all studies sorted by priority.

        Returns:
            List of studies sorted by priority (highest first)

        """
        return sorted(
            self.studies.values(),
            key=lambda e: (e.priority, -e.crash_count, e.test_count),
        )

    def update_priority(
        self,
        study_id: str,
        crash_found: bool = False,
        new_priority: int | None = None,
    ) -> None:
        """Update study priority after testing.

        Args:
            study_id: Study ID
            crash_found: Whether a crash was found in this test
            new_priority: Explicit new priority (overrides calculation)

        """
        if study_id not in self.studies:
            logger.warning("Study not found for priority update", study_id=study_id)
            return

        entry = self.studies[study_id]
        entry.test_count += 1
        entry.last_tested = datetime.now(UTC).isoformat()

        if new_priority is not None:
            entry.priority = max(1, min(5, new_priority))
        elif crash_found:
            # Boost priority on crash
            entry.priority = max(1, entry.priority - 1)

        logger.debug("Updated priority", study_id=study_id, priority=entry.priority)

    def record_crash(
        self,
        study_id: str,
        crash_type: str,
        trigger_slice: str | None = None,
        exit_code: int | None = None,
        notes: str | None = None,
    ) -> CrashInfo:
        """Record a crash for a study.

        Args:
            study_id: Study ID that triggered crash
            crash_type: Type of crash (e.g., ACCESS_VIOLATION)
            trigger_slice: Specific slice that triggered crash
            exit_code: Process exit code
            notes: Additional notes

        Returns:
            CrashInfo object

        """
        if study_id not in self.studies:
            raise ValueError(f"Study not found: {study_id}")

        crash = CrashInfo(
            crash_id=hashlib.sha256(
                f"{study_id}-{crash_type}-{datetime.now(UTC).isoformat()}".encode()
            ).hexdigest()[:16],
            crash_type=crash_type,
            timestamp=datetime.now(UTC).isoformat(),
            trigger_slice=trigger_slice,
            exit_code=exit_code,
            notes=notes,
        )

        self.studies[study_id].crashes_triggered.append(crash)
        self.update_priority(study_id, crash_found=True)

        logger.info("Recorded crash", study_id=study_id, crash_type=crash_type)
        return crash

    def record_mutation(self, study_id: str, mutation_name: str) -> None:
        """Record a mutation applied to a study.

        Args:
            study_id: Study ID
            mutation_name: Name of mutation applied

        """
        if study_id in self.studies:
            if mutation_name not in self.studies[study_id].mutations_applied:
                self.studies[study_id].mutations_applied.append(mutation_name)

    def save_index(self) -> None:
        """Save corpus index to JSON file."""
        index_data = {
            "version": "1.0",
            "created": datetime.now(UTC).isoformat(),
            "study_count": len(self.studies),
            "studies": {
                study_id: entry.to_dict() for study_id, entry in self.studies.items()
            },
        }

        with open(self.index_path, "w", encoding="utf-8") as f:
            json.dump(index_data, f, indent=2)

        logger.info("Saved corpus index", study_count=len(self.studies))

    def load_index(self) -> None:
        """Load corpus index from JSON file."""
        if not self.index_path.exists():
            logger.warning("Index file not found", index_path=str(self.index_path))
            return

        try:
            with open(self.index_path, encoding="utf-8") as f:
                index_data = json.load(f)

            self.studies.clear()
            for study_id, study_data in index_data.get("studies", {}).items():
                # Reconstruct SeriesInfo and CrashInfo objects
                series_list = [
                    SeriesInfo(**s) for s in study_data.get("series_list", [])
                ]
                crashes = [
                    CrashInfo(**c) for c in study_data.get("crashes_triggered", [])
                ]

                # Remove nested objects before creating entry
                study_data_clean = {
                    k: v
                    for k, v in study_data.items()
                    if k not in ("series_list", "crashes_triggered")
                }

                entry = StudyCorpusEntry(
                    **study_data_clean,
                    series_list=series_list,
                    crashes_triggered=crashes,
                )
                self.studies[study_id] = entry

            logger.info("Loaded corpus index", study_count=len(self.studies))

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.error("Failed to load corpus index", error=str(e))
            raise

    def get_modality_distribution(self) -> dict[str, int]:
        """Get distribution of modalities in corpus.

        Returns:
            Dict mapping modality to count

        """
        distribution: dict[str, int] = {}
        for entry in self.studies.values():
            for modality in entry.modalities:
                distribution[modality] = distribution.get(modality, 0) + 1
        return distribution

    def get_crash_summary(self) -> dict[str, list[CrashInfo]]:
        """Get summary of crashes by type.

        Returns:
            Dict mapping crash type to list of CrashInfo

        """
        summary: dict[str, list[CrashInfo]] = {}
        for entry in self.studies.values():
            for crash in entry.crashes_triggered:
                if crash.crash_type not in summary:
                    summary[crash.crash_type] = []
                summary[crash.crash_type].append(crash)
        return summary

    def get_statistics(self) -> dict[str, Any]:
        """Get corpus statistics.

        Returns:
            Dict with corpus statistics

        """
        total_slices = sum(e.total_slices for e in self.studies.values())
        total_crashes = sum(e.crash_count for e in self.studies.values())
        crash_studies = sum(1 for e in self.studies.values() if e.is_crash_triggering)

        return {
            "study_count": len(self.studies),
            "total_slices": total_slices,
            "total_crashes": total_crashes,
            "crash_triggering_studies": crash_studies,
            "modality_distribution": self.get_modality_distribution(),
            "average_slices_per_study": total_slices / len(self.studies)
            if self.studies
            else 0,
        }

    def _analyze_study(self, study_dir: Path) -> StudyCorpusEntry:
        """Analyze a study directory and create entry.

        Args:
            study_dir: Path to study directory

        Returns:
            StudyCorpusEntry with analysis results

        """
        # Find DICOM files
        dicom_files = self._find_dicom_files(study_dir)
        if not dicom_files:
            raise ValueError(f"No DICOM files found in {study_dir}")

        # Generate study ID from directory hash
        dir_hash = hashlib.sha256(str(study_dir.resolve()).encode()).hexdigest()[:12]
        study_id = f"study_{dir_hash}"

        # Read first file for study-level info
        study_uid = ""
        patient_id = None
        study_date = None
        study_description = None

        try:
            first_ds = pydicom.dcmread(dicom_files[0], stop_before_pixels=True)
            study_uid = str(getattr(first_ds, "StudyInstanceUID", ""))
            patient_id = str(getattr(first_ds, "PatientID", "")) or None
            study_date = str(getattr(first_ds, "StudyDate", "")) or None
            study_description = str(getattr(first_ds, "StudyDescription", "")) or None
        except (InvalidDicomError, Exception) as e:
            logger.warning("Could not read study metadata", error=str(e))

        # Analyze series
        series_dict: dict[str, SeriesInfo] = {}
        modalities: set[str] = set()

        for dcm_file in dicom_files:
            try:
                ds = pydicom.dcmread(dcm_file, stop_before_pixels=True)
                series_uid = str(getattr(ds, "SeriesInstanceUID", "unknown"))
                modality = str(getattr(ds, "Modality", "OT"))
                is_multiframe = int(getattr(ds, "NumberOfFrames", 1)) > 1

                modalities.add(modality)

                if series_uid not in series_dict:
                    series_dict[series_uid] = SeriesInfo(
                        series_uid=series_uid,
                        modality=modality,
                        slice_count=0,
                        is_multiframe=is_multiframe,
                        description=str(getattr(ds, "SeriesDescription", "")) or None,
                    )

                series_dict[series_uid].slice_count += 1

            except (InvalidDicomError, Exception):
                # Skip non-DICOM files
                continue

        return StudyCorpusEntry(
            study_id=study_id,
            study_dir=str(study_dir),
            study_uid=study_uid,
            patient_id=patient_id,
            study_date=study_date,
            study_description=study_description,
            series_list=list(series_dict.values()),
            total_slices=len(dicom_files),
            modalities=list(modalities),
        )

    def _find_dicom_files(self, directory: Path) -> list[Path]:
        """Find DICOM files in directory.

        Args:
            directory: Directory to search

        Returns:
            List of DICOM file paths

        """
        dicom_files: list[Path] = []
        extensions = {".dcm", ".dicom", ".dic", ""}

        for f in directory.rglob("*"):
            if f.is_file():
                if f.suffix.lower() in extensions:
                    # Quick check for DICOM magic number
                    try:
                        with open(f, "rb") as fp:
                            fp.seek(128)
                            magic = fp.read(4)
                            if magic == b"DICM":
                                dicom_files.append(f)
                            elif f.suffix.lower() in {".dcm", ".dicom", ".dic"}:
                                # Trust extension if no magic
                                dicom_files.append(f)
                    except Exception:
                        continue

        return sorted(dicom_files)

    def list_studies(self) -> list[dict[str, Any]]:
        """List all studies with summary info.

        Returns:
            List of study summaries

        """
        return [
            {
                "study_id": e.study_id,
                "study_uid": e.study_uid[:40] + "..."
                if len(e.study_uid) > 40
                else e.study_uid,
                "total_slices": e.total_slices,
                "series_count": len(e.series_list),
                "modalities": e.modalities,
                "priority": e.priority,
                "crash_count": e.crash_count,
                "test_count": e.test_count,
            }
            for e in self.prioritize_studies()
        ]


def create_study_corpus(corpus_dir: Path) -> StudyCorpusManager:
    """Factory function to create a StudyCorpusManager.

    Args:
        corpus_dir: Directory for corpus storage

    Returns:
        Configured StudyCorpusManager instance

    """
    return StudyCorpusManager(corpus_dir)
