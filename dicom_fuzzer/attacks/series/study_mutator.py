"""Study-Level DICOM Mutation Strategies

This module provides StudyMutator for fuzzing complete DICOM studies containing
multiple series. Unlike series-level fuzzing, study-level attacks target
cross-series relationships and study-wide consistency.

MUTATION STRATEGIES:
1. Cross-Series Reference Attacks - Corrupt ReferencedSeriesSequence
2. Frame of Reference Attacks - Misaligned registration/fusion data
3. Patient Consistency Attacks - Conflicting demographics across series
4. Study Metadata Corruption - StudyInstanceUID, StudyDate mismatches

SECURITY RATIONALE:
Medical imaging applications often merge multiple series into unified views.
Inconsistencies across series can trigger:
- Memory corruption during series merging
- Logic errors in registration algorithms
- Patient safety issues from misidentified data
- Crashes in multi-series viewers

USAGE:
    mutator = StudyMutator(severity="aggressive")
    fuzzed_study, records = mutator.mutate_study(
        study, strategy=StudyMutationStrategy.CROSS_SERIES_REFERENCE
    )
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import pydicom
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from dicom_fuzzer.core.dicom.dicom_series import DicomSeries
from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.core.series.series_detector import SeriesDetector
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class StudyMutationStrategy(Enum):
    """Available study-level mutation strategies."""

    CROSS_SERIES_REFERENCE = "cross_series_reference"
    FRAME_OF_REFERENCE = "frame_of_reference"
    PATIENT_CONSISTENCY = "patient_consistency"
    STUDY_METADATA = "study_metadata"
    MIXED_MODALITY_STUDY = "mixed_modality_study"


@dataclass
class StudyMutationRecord(SerializableMixin):
    """Record of a study-level mutation.

    Tracks mutations applied across multiple series in a study.
    """

    strategy: str
    series_index: int | None = None
    series_uid: str | None = None
    tag: str | None = None
    original_value: str | None = None
    mutated_value: str | None = None
    severity: str = "moderate"
    details: dict[str, Any] = field(default_factory=dict)

    def _custom_serialization(self, data: dict[str, Any]) -> dict[str, Any]:
        """Ensure values are converted to strings for JSON serialization."""
        if data.get("original_value") is not None:
            data["original_value"] = str(data["original_value"])
        if data.get("mutated_value") is not None:
            data["mutated_value"] = str(data["mutated_value"])
        return data


@dataclass
class DicomStudy:
    """Container for a DICOM study with multiple series.

    Attributes:
        study_uid: StudyInstanceUID
        patient_id: PatientID
        series_list: List of DicomSeries in this study
        study_dir: Root directory of the study

    """

    study_uid: str
    patient_id: str
    series_list: list[DicomSeries]
    study_dir: Path | None = None

    @property
    def series_count(self) -> int:
        """Return number of series in study."""
        return len(self.series_list)

    def get_total_slices(self) -> int:
        """Return total slice count across all series."""
        return sum(s.slice_count for s in self.series_list)


class StudyMutator:
    """Mutator for complete DICOM studies with multiple series.

    This class implements study-level fuzzing that targets vulnerabilities
    in multi-series DICOM loading, patient merging, and registration.
    """

    def __init__(self, severity: str = "moderate", seed: int | None = None):
        """Initialize StudyMutator.

        Args:
            severity: Mutation severity (minimal, moderate, aggressive, extreme)
            seed: Random seed for reproducibility

        """
        if severity not in ["minimal", "moderate", "aggressive", "extreme"]:
            raise ValueError(f"Invalid severity: {severity}")

        self.severity = severity
        self.seed = seed
        if seed is not None:
            random.seed(seed)

        self._mutation_counts = {
            "minimal": (1, 2),
            "moderate": (2, 4),
            "aggressive": (4, 8),
            "extreme": (8, 15),
        }

        logger.info(f"StudyMutator initialized (severity={severity})")

    def load_study(self, study_dir: Path) -> DicomStudy:
        """Load a DICOM study from a directory.

        Args:
            study_dir: Directory containing DICOM files (may have subdirs)

        Returns:
            DicomStudy object with detected series

        Raises:
            ValueError: If no valid DICOM series found

        """
        study_dir = Path(study_dir)
        if not study_dir.exists():
            raise ValueError(f"Study directory does not exist: {study_dir}")

        detector = SeriesDetector()
        series_list = detector.detect_series(study_dir)

        if not series_list:
            raise ValueError(f"No valid DICOM series found in: {study_dir}")

        # Extract study-level metadata from first slice of first series
        first_ds = pydicom.dcmread(series_list[0].slices[0], stop_before_pixels=True)
        study_uid = getattr(first_ds, "StudyInstanceUID", generate_uid())
        patient_id = getattr(first_ds, "PatientID", "UNKNOWN")

        study = DicomStudy(
            study_uid=str(study_uid),
            patient_id=str(patient_id),
            series_list=series_list,
            study_dir=study_dir,
        )

        logger.info(
            f"Loaded study {study_uid[:16]}... with {study.series_count} series, "
            f"{study.get_total_slices()} total slices"
        )

        return study

    def mutate_study(
        self,
        study: DicomStudy,
        strategy: str | StudyMutationStrategy | None = None,
        mutation_count: int | None = None,
    ) -> tuple[list[list[Dataset]], list[StudyMutationRecord]]:
        """Mutate a complete DICOM study.

        Args:
            study: DicomStudy to mutate
            strategy: Mutation strategy (random if None)
            mutation_count: Number of mutations (severity-based if None)

        Returns:
            Tuple of (list of series datasets, list of mutation records)

        """
        if study.series_count == 0:
            raise ValueError("Cannot mutate empty study")

        # Select strategy
        if strategy is None:
            strategy = random.choice(list(StudyMutationStrategy)).value
        elif not isinstance(strategy, str):
            strategy = strategy.value

        if strategy not in [s.value for s in StudyMutationStrategy]:
            raise ValueError(f"Invalid strategy: {strategy}")

        # Determine mutation count
        if mutation_count is None:
            min_count, max_count = self._mutation_counts[self.severity]
            mutation_count = random.randint(min_count, max_count)

        logger.info(
            f"Mutating study with {mutation_count} mutations "
            f"(strategy={strategy}, severity={self.severity})"
        )

        # Load all datasets for all series
        all_datasets = self._load_study_datasets(study)

        # Apply strategy
        strategy_method = {
            StudyMutationStrategy.CROSS_SERIES_REFERENCE.value: self._mutate_cross_series_reference,
            StudyMutationStrategy.FRAME_OF_REFERENCE.value: self._mutate_frame_of_reference,
            StudyMutationStrategy.PATIENT_CONSISTENCY.value: self._mutate_patient_consistency,
            StudyMutationStrategy.STUDY_METADATA.value: self._mutate_study_metadata,
            StudyMutationStrategy.MIXED_MODALITY_STUDY.value: self._mutate_mixed_modality,
        }[strategy]

        mutated_datasets, records = strategy_method(all_datasets, study, mutation_count)

        logger.info(f"Applied {len(records)} study-level mutations")
        return mutated_datasets, records

    def _load_study_datasets(self, study: DicomStudy) -> list[list[Dataset]]:
        """Load all datasets for all series in study.

        Returns:
            List of lists - outer list is series, inner list is slices

        """
        all_datasets: list[list[Dataset]] = []

        for series in study.series_list:
            series_datasets: list[Dataset] = []
            for slice_path in series.slices:
                try:
                    ds = pydicom.dcmread(slice_path)
                    series_datasets.append(copy.deepcopy(ds))
                except Exception as e:
                    logger.error(f"Failed to load slice {slice_path}: {e}")
                    raise
            all_datasets.append(series_datasets)

        return all_datasets

    def _mutate_cross_series_reference(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        mutation_count: int,
    ) -> tuple[list[list[Dataset]], list[StudyMutationRecord]]:
        """Strategy 1: Cross-Series Reference Attacks.

        Corrupts ReferencedSeriesSequence to create invalid references:
        - Point to non-existent series UIDs
        - Create circular references
        - Empty or malformed sequence items

        Targets: Registration algorithms, fusion viewers, series linking
        """
        records: list[StudyMutationRecord] = []

        for _ in range(mutation_count):
            if len(all_datasets) < 1:
                break

            series_idx = random.randint(0, len(all_datasets) - 1)
            if not all_datasets[series_idx]:
                continue

            slice_idx = random.randint(0, len(all_datasets[series_idx]) - 1)
            ds = all_datasets[series_idx][slice_idx]

            attack_type = random.choice(
                [
                    "nonexistent_reference",
                    "circular_reference",
                    "empty_sequence",
                    "invalid_uid_format",
                    "duplicate_references",
                ]
            )

            if attack_type == "nonexistent_reference":
                # Create reference to non-existent series
                ref_seq = Sequence()
                ref_item = Dataset()
                ref_item.SeriesInstanceUID = generate_uid() + ".FUZZED.NONEXISTENT"
                ref_seq.append(ref_item)
                ds.ReferencedSeriesSequence = ref_seq

                records.append(
                    StudyMutationRecord(
                        strategy="cross_series_reference",
                        series_index=series_idx,
                        series_uid=study.series_list[series_idx].series_uid,
                        tag="ReferencedSeriesSequence",
                        original_value="<none>",
                        mutated_value=ref_item.SeriesInstanceUID,
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "circular_reference":
                # Reference own series (circular)
                ref_seq = Sequence()
                ref_item = Dataset()
                ref_item.SeriesInstanceUID = study.series_list[series_idx].series_uid
                ref_seq.append(ref_item)
                ds.ReferencedSeriesSequence = ref_seq

                records.append(
                    StudyMutationRecord(
                        strategy="cross_series_reference",
                        series_index=series_idx,
                        series_uid=study.series_list[series_idx].series_uid,
                        tag="ReferencedSeriesSequence",
                        original_value="<none>",
                        mutated_value="<circular>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "empty_sequence":
                # Empty sequence (may cause null pointer)
                ds.ReferencedSeriesSequence = Sequence()

                records.append(
                    StudyMutationRecord(
                        strategy="cross_series_reference",
                        series_index=series_idx,
                        series_uid=study.series_list[series_idx].series_uid,
                        tag="ReferencedSeriesSequence",
                        original_value="<none>",
                        mutated_value="<empty>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_uid_format":
                # Invalid UID format
                ref_seq = Sequence()
                ref_item = Dataset()
                ref_item.SeriesInstanceUID = "!@#$%^INVALID_UID*&()"
                ref_seq.append(ref_item)
                ds.ReferencedSeriesSequence = ref_seq

                records.append(
                    StudyMutationRecord(
                        strategy="cross_series_reference",
                        series_index=series_idx,
                        series_uid=study.series_list[series_idx].series_uid,
                        tag="ReferencedSeriesSequence",
                        original_value="<none>",
                        mutated_value=ref_item.SeriesInstanceUID,
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "duplicate_references":
                # Multiple references to same series
                ref_seq = Sequence()
                for _ in range(10):
                    ref_item = Dataset()
                    ref_item.SeriesInstanceUID = study.series_list[0].series_uid
                    ref_seq.append(ref_item)
                ds.ReferencedSeriesSequence = ref_seq

                records.append(
                    StudyMutationRecord(
                        strategy="cross_series_reference",
                        series_index=series_idx,
                        series_uid=study.series_list[series_idx].series_uid,
                        tag="ReferencedSeriesSequence",
                        original_value="<none>",
                        mutated_value="<10_duplicates>",
                        severity=self.severity,
                        details={"attack_type": attack_type, "count": 10},
                    )
                )

        return all_datasets, records

    def _for_attack_different(
        self,
        all_datasets: list[list[Dataset]],
        series_idx: int,
        study: DicomStudy,
    ) -> StudyMutationRecord:
        """Apply different FoR per series attack."""
        new_for = generate_uid()
        original = None
        for ds in all_datasets[series_idx]:
            original = getattr(ds, "FrameOfReferenceUID", None)
            ds.FrameOfReferenceUID = new_for
        return StudyMutationRecord(
            strategy="frame_of_reference",
            series_index=series_idx,
            series_uid=study.series_list[series_idx].series_uid,
            tag="FrameOfReferenceUID",
            original_value=str(original) if original else "<none>",
            mutated_value=new_for,
            severity=self.severity,
            details={"attack_type": "different_for_per_series"},
        )

    def _for_attack_same_unrelated(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
    ) -> StudyMutationRecord | None:
        """Apply same FoR to unrelated series attack."""
        if len(all_datasets) <= 1:
            return None
        shared_for = generate_uid()
        for series_datasets in all_datasets:
            for ds in series_datasets:
                ds.FrameOfReferenceUID = shared_for
        return StudyMutationRecord(
            strategy="frame_of_reference",
            series_index=None,
            series_uid=None,
            tag="FrameOfReferenceUID",
            original_value="<various>",
            mutated_value=shared_for,
            severity=self.severity,
            details={
                "attack_type": "same_for_unrelated",
                "series_count": len(all_datasets),
            },
        )

    def _for_attack_empty(
        self,
        all_datasets: list[list[Dataset]],
        series_idx: int,
        study: DicomStudy,
    ) -> StudyMutationRecord:
        """Apply empty FoR attack."""
        original = None
        for ds in all_datasets[series_idx]:
            original = getattr(ds, "FrameOfReferenceUID", None)
            ds.FrameOfReferenceUID = ""
        return StudyMutationRecord(
            strategy="frame_of_reference",
            series_index=series_idx,
            series_uid=study.series_list[series_idx].series_uid,
            tag="FrameOfReferenceUID",
            original_value=str(original) if original else "<none>",
            mutated_value="<empty>",
            severity=self.severity,
            details={"attack_type": "empty_for"},
        )

    def _for_attack_invalid(
        self,
        all_datasets: list[list[Dataset]],
        series_idx: int,
        study: DicomStudy,
    ) -> StudyMutationRecord:
        """Apply invalid FoR attack."""
        original = None
        for ds in all_datasets[series_idx]:
            original = getattr(ds, "FrameOfReferenceUID", None)
            ds.FrameOfReferenceUID = "INVALID-FoR-!@#$%"
        return StudyMutationRecord(
            strategy="frame_of_reference",
            series_index=series_idx,
            series_uid=study.series_list[series_idx].series_uid,
            tag="FrameOfReferenceUID",
            original_value=str(original) if original else "<none>",
            mutated_value="INVALID-FoR-!@#$%",
            severity=self.severity,
            details={"attack_type": "invalid_for"},
        )

    def _for_attack_inconsistent(
        self,
        all_datasets: list[list[Dataset]],
        series_idx: int,
        study: DicomStudy,
    ) -> StudyMutationRecord:
        """Apply inconsistent FoR within series attack."""
        for ds in all_datasets[series_idx]:
            ds.FrameOfReferenceUID = generate_uid()
        return StudyMutationRecord(
            strategy="frame_of_reference",
            series_index=series_idx,
            series_uid=study.series_list[series_idx].series_uid,
            tag="FrameOfReferenceUID",
            original_value="<consistent>",
            mutated_value="<inconsistent_per_slice>",
            severity=self.severity,
            details={
                "attack_type": "inconsistent_within_series",
                "slice_count": len(all_datasets[series_idx]),
            },
        )

    def _mutate_frame_of_reference(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        mutation_count: int,
    ) -> tuple[list[list[Dataset]], list[StudyMutationRecord]]:
        """Strategy 2: Frame of Reference Attacks.

        Manipulates FrameOfReferenceUID to break registration:
        - Different FoR for series that should be co-registered
        - Same FoR for unrelated series (fusion confusion)
        - Invalid/empty FoR values

        Targets: Image registration, PET/CT fusion, treatment planning
        """
        attack_types = [
            "different_for_per_series",
            "same_for_unrelated",
            "empty_for",
            "invalid_for",
            "inconsistent_within_series",
        ]
        records: list[StudyMutationRecord] = []

        for _ in range(mutation_count):
            if len(all_datasets) < 1:
                break

            series_idx = random.randint(0, len(all_datasets) - 1)
            attack_type = random.choice(attack_types)

            record: StudyMutationRecord | None = None
            if attack_type == "different_for_per_series":
                record = self._for_attack_different(all_datasets, series_idx, study)
            elif attack_type == "same_for_unrelated":
                record = self._for_attack_same_unrelated(all_datasets, study)
            elif attack_type == "empty_for":
                record = self._for_attack_empty(all_datasets, series_idx, study)
            elif attack_type == "invalid_for":
                record = self._for_attack_invalid(all_datasets, series_idx, study)
            elif attack_type == "inconsistent_within_series":
                record = self._for_attack_inconsistent(all_datasets, series_idx, study)

            if record:
                records.append(record)

        return all_datasets, records

    def _patient_attack_different_id(
        self,
        all_datasets: list[list[Dataset]],
        series_idx: int,
        study: DicomStudy,
    ) -> StudyMutationRecord:
        """Apply different patient ID attack."""
        new_patient_id = f"FUZZED_{random.randint(10000, 99999)}"
        original = None
        for ds in all_datasets[series_idx]:
            original = getattr(ds, "PatientID", None)
            ds.PatientID = new_patient_id
        return StudyMutationRecord(
            strategy="patient_consistency",
            series_index=series_idx,
            series_uid=study.series_list[series_idx].series_uid,
            tag="PatientID",
            original_value=str(original) if original else "<none>",
            mutated_value=new_patient_id,
            severity=self.severity,
            details={"attack_type": "different_patient_id"},
        )

    def _patient_attack_demographics(
        self,
        all_datasets: list[list[Dataset]],
        series_idx: int,
        study: DicomStudy,
    ) -> StudyMutationRecord:
        """Apply conflicting demographics attack."""
        new_sex = random.choice(["M", "F", "O", "INVALID", ""])
        original = None
        for ds in all_datasets[series_idx]:
            original = getattr(ds, "PatientSex", None)
            ds.PatientSex = new_sex
        return StudyMutationRecord(
            strategy="patient_consistency",
            series_index=series_idx,
            series_uid=study.series_list[series_idx].series_uid,
            tag="PatientSex",
            original_value=str(original) if original else "<none>",
            mutated_value=new_sex,
            severity=self.severity,
            details={"attack_type": "conflicting_demographics"},
        )

    def _patient_attack_mixed_name(
        self,
        all_datasets: list[list[Dataset]],
        series_idx: int,
        study: DicomStudy,
    ) -> StudyMutationRecord:
        """Apply mixed patient name attack."""
        new_name = f"FUZZED^PATIENT^{random.randint(1, 999)}"
        original = None
        for ds in all_datasets[series_idx]:
            original = getattr(ds, "PatientName", None)
            ds.PatientName = new_name
        return StudyMutationRecord(
            strategy="patient_consistency",
            series_index=series_idx,
            series_uid=study.series_list[series_idx].series_uid,
            tag="PatientName",
            original_value=str(original) if original else "<none>",
            mutated_value=new_name,
            severity=self.severity,
            details={"attack_type": "mixed_patient_name"},
        )

    def _patient_attack_birthdate(
        self,
        all_datasets: list[list[Dataset]],
        series_idx: int,
        study: DicomStudy,
    ) -> StudyMutationRecord:
        """Apply conflicting birthdate attack."""
        new_birthdate = f"{random.randint(1920, 2020)}{random.randint(1, 12):02d}{random.randint(1, 28):02d}"
        original = None
        for ds in all_datasets[series_idx]:
            original = getattr(ds, "PatientBirthDate", None)
            ds.PatientBirthDate = new_birthdate
        return StudyMutationRecord(
            strategy="patient_consistency",
            series_index=series_idx,
            series_uid=study.series_list[series_idx].series_uid,
            tag="PatientBirthDate",
            original_value=str(original) if original else "<none>",
            mutated_value=new_birthdate,
            severity=self.severity,
            details={"attack_type": "conflicting_birthdate"},
        )

    # Patient consistency attack dispatch table
    _PATIENT_ATTACK_HANDLERS = [
        _patient_attack_different_id,
        _patient_attack_demographics,
        _patient_attack_mixed_name,
        _patient_attack_birthdate,
    ]

    def _mutate_patient_consistency(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        mutation_count: int,
    ) -> tuple[list[list[Dataset]], list[StudyMutationRecord]]:
        """Strategy 3: Patient Consistency Attacks.

        Creates patient identity conflicts across series:
        - Different PatientID in different series
        - Conflicting demographics (age, sex, birthdate)
        - Mixed patient names

        Targets: Patient matching, study merging, worklist integration
        """
        records: list[StudyMutationRecord] = []

        for _ in range(mutation_count):
            if len(all_datasets) < 2:
                break

            series_idx = random.randint(1, len(all_datasets) - 1)
            handler = random.choice(self._PATIENT_ATTACK_HANDLERS)
            records.append(handler(self, all_datasets, series_idx, study))

        return all_datasets, records

    def _study_meta_uid_mismatch(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        records: list[StudyMutationRecord],
    ) -> None:
        """Apply study UID mismatch attack."""
        if len(all_datasets) <= 1:
            return
        for series_idx, series_datasets in enumerate(all_datasets):
            new_uid = generate_uid()
            original = (
                getattr(series_datasets[0], "StudyInstanceUID", None)
                if series_datasets
                else None
            )
            for ds in series_datasets:
                ds.StudyInstanceUID = new_uid
            records.append(
                StudyMutationRecord(
                    strategy="study_metadata",
                    series_index=series_idx,
                    series_uid=study.series_list[series_idx].series_uid,
                    tag="StudyInstanceUID",
                    original_value=str(original) if original else "<none>",
                    mutated_value=new_uid,
                    severity=self.severity,
                    details={"attack_type": "study_uid_mismatch"},
                )
            )

    def _study_meta_date_conflict(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        records: list[StudyMutationRecord],
    ) -> None:
        """Apply study date conflict attack."""
        series_idx = random.randint(0, len(all_datasets) - 1)
        new_date = f"{random.randint(1990, 2030)}{random.randint(1, 12):02d}{random.randint(1, 28):02d}"
        original = (
            getattr(all_datasets[series_idx][0], "StudyDate", None)
            if all_datasets[series_idx]
            else None
        )
        for ds in all_datasets[series_idx]:
            ds.StudyDate = new_date
        records.append(
            StudyMutationRecord(
                strategy="study_metadata",
                series_index=series_idx,
                series_uid=study.series_list[series_idx].series_uid,
                tag="StudyDate",
                original_value=str(original) if original else "<none>",
                mutated_value=new_date,
                severity=self.severity,
                details={"attack_type": "study_date_conflict"},
            )
        )

    def _study_meta_extreme_id(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        records: list[StudyMutationRecord],
    ) -> None:
        """Apply extreme study ID attack."""
        series_idx = random.randint(0, len(all_datasets) - 1)
        # Robustness testing patterns only (no exploit payloads)
        extreme_ids = [
            "A" * 1000,  # Long string - buffer handling
            "",  # Empty string - null handling
            "\x00\x00",  # Null bytes - binary handling
            "X" * 10000,  # Very long string - memory allocation
            " " * 100,  # Whitespace only - trimming behavior
        ]
        new_id = random.choice(extreme_ids)
        original = (
            getattr(all_datasets[series_idx][0], "StudyID", None)
            if all_datasets[series_idx]
            else None
        )
        for ds in all_datasets[series_idx]:
            ds.StudyID = new_id
        records.append(
            StudyMutationRecord(
                strategy="study_metadata",
                series_index=series_idx,
                series_uid=study.series_list[series_idx].series_uid,
                tag="StudyID",
                original_value=str(original) if original else "<none>",
                mutated_value=repr(new_id)[:50],
                severity=self.severity,
                details={"attack_type": "extreme_study_id"},
            )
        )

    def _study_meta_empty_uid(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        records: list[StudyMutationRecord],
    ) -> None:
        """Apply empty study UID attack."""
        series_idx = random.randint(0, len(all_datasets) - 1)
        original = (
            getattr(all_datasets[series_idx][0], "StudyInstanceUID", None)
            if all_datasets[series_idx]
            else None
        )
        for ds in all_datasets[series_idx]:
            ds.StudyInstanceUID = ""
        records.append(
            StudyMutationRecord(
                strategy="study_metadata",
                series_index=series_idx,
                series_uid=study.series_list[series_idx].series_uid,
                tag="StudyInstanceUID",
                original_value=str(original) if original else "<none>",
                mutated_value="<empty>",
                severity=self.severity,
                details={"attack_type": "empty_study_uid"},
            )
        )

    def _mutate_study_metadata(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        mutation_count: int,
    ) -> tuple[list[list[Dataset]], list[StudyMutationRecord]]:
        """Strategy 4: Study Metadata Corruption.

        Corrupts study-level metadata:
        - StudyInstanceUID mismatches across series
        - StudyDate/Time conflicts
        - Invalid or extreme values

        Targets: Study grouping, timeline views, reporting
        """
        records: list[StudyMutationRecord] = []
        handlers = {
            "uid_mismatch": self._study_meta_uid_mismatch,
            "date_conflict": self._study_meta_date_conflict,
            "extreme_id": self._study_meta_extreme_id,
            "empty_uid": self._study_meta_empty_uid,
        }

        for _ in range(mutation_count):
            if len(all_datasets) < 1:
                break
            handler = handlers[random.choice(list(handlers.keys()))]
            handler(all_datasets, study, records)

        return all_datasets, records

    def _mutate_mixed_modality(
        self,
        all_datasets: list[list[Dataset]],
        study: DicomStudy,
        mutation_count: int,
    ) -> tuple[list[list[Dataset]], list[StudyMutationRecord]]:
        """Strategy 5: Mixed Modality Study.

        Creates unexpected modality combinations:
        - CT series with MR modality tag
        - Mixed modalities within single series
        - Invalid modality codes

        Targets: Modality-specific viewers, hanging protocols, AI pipelines
        """
        records: list[StudyMutationRecord] = []
        modalities = ["CT", "MR", "US", "XA", "PT", "NM", "CR", "DX", "MG", "FUZZ"]

        for _ in range(mutation_count):
            if len(all_datasets) < 1:
                break

            series_idx = random.randint(0, len(all_datasets) - 1)

            attack_type = random.choice(
                [
                    "wrong_modality",
                    "mixed_within_series",
                    "invalid_modality",
                ]
            )

            if attack_type == "wrong_modality":
                # Change entire series to different modality
                new_modality = random.choice(modalities)
                for ds in all_datasets[series_idx]:
                    original = getattr(ds, "Modality", None)
                    ds.Modality = new_modality

                records.append(
                    StudyMutationRecord(
                        strategy="mixed_modality_study",
                        series_index=series_idx,
                        series_uid=study.series_list[series_idx].series_uid,
                        tag="Modality",
                        original_value=str(original) if original else "<none>",
                        mutated_value=new_modality,
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "mixed_within_series":
                # Different modality per slice
                for i, ds in enumerate(all_datasets[series_idx]):
                    original = getattr(ds, "Modality", None)
                    ds.Modality = modalities[i % len(modalities)]

                records.append(
                    StudyMutationRecord(
                        strategy="mixed_modality_study",
                        series_index=series_idx,
                        series_uid=study.series_list[series_idx].series_uid,
                        tag="Modality",
                        original_value="<consistent>",
                        mutated_value="<mixed_per_slice>",
                        severity=self.severity,
                        details={
                            "attack_type": attack_type,
                            "slice_count": len(all_datasets[series_idx]),
                        },
                    )
                )

            elif attack_type == "invalid_modality":
                # Invalid modality codes
                invalid_modalities = [
                    "",  # Empty
                    "XXXXXXXXXXXXX",  # Too long
                    "12",  # Numeric
                    "\x00",  # Null
                    "CT\\MR",  # Multiple values
                ]
                new_modality = random.choice(invalid_modalities)
                for ds in all_datasets[series_idx]:
                    original = getattr(ds, "Modality", None)
                    ds.Modality = new_modality

                records.append(
                    StudyMutationRecord(
                        strategy="mixed_modality_study",
                        series_index=series_idx,
                        series_uid=study.series_list[series_idx].series_uid,
                        tag="Modality",
                        original_value=str(original) if original else "<none>",
                        mutated_value=repr(new_modality),
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return all_datasets, records
