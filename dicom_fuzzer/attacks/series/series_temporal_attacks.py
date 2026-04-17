"""Temporal and Cross-Slice Attack Strategies (v1.8.0)

This module provides the TemporalAttacksMixin with two specialized mutation
strategies targeting cross-slice references and temporal ordering vulnerabilities.

Strategies:
11. Cross-Slice Reference - Corrupts ReferencedSOPInstanceUID relationships
12. Temporal Inconsistency - Creates temporal ordering conflicts
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING, Any

import pydicom
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from .series_types import SeriesMutationRecord

if TYPE_CHECKING:
    from dicom_fuzzer.core.dicom.series import DicomSeries


class TemporalAttacksMixin:
    """Mixin providing temporal and cross-slice attack strategies.

    This mixin assumes the class has:
    - self.severity: str - The mutation severity level
    """

    severity: str  # Type hint for mixin

    # Default SOP Class UID for CT Image Storage
    _CT_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.2"

    # --- Cross-Slice Reference Helpers ---

    def _create_ref_record(
        self,
        attack_type: str,
        slice_index: int | None,
        mutated_value: str,
        tag: str = "ReferencedImageSequence",
        details: dict[str, Any] | None = None,
    ) -> SeriesMutationRecord:
        """Create a SeriesMutationRecord for cross-slice reference attacks."""
        return SeriesMutationRecord(
            strategy="cross_slice_reference",
            slice_index=slice_index,
            tag=tag,
            original_value="<none>",
            mutated_value=mutated_value,
            severity=self.severity,
            details={"attack_type": attack_type, **(details or {})},
        )

    def _add_reference(
        self, ds: Dataset, instance_uid: str, class_uid: str | None = None
    ) -> None:
        """Add a reference item to dataset's ReferencedImageSequence."""
        if not hasattr(ds, "ReferencedImageSequence"):
            ds.ReferencedImageSequence = pydicom.Sequence([])

        ref_item = pydicom.Dataset()
        ref_item.ReferencedSOPClassUID = class_uid or self._CT_SOP_CLASS_UID
        ref_item.ReferencedSOPInstanceUID = instance_uid
        ds.ReferencedImageSequence.append(ref_item)

    def _handle_reference_nonexistent(
        self, datasets: list[Dataset], existing_uids: list[str]
    ) -> SeriesMutationRecord:
        """Handle reference_nonexistent attack type."""
        slice_idx = random.randint(0, len(datasets) - 1)
        fake_uid = generate_uid() + ".NONEXISTENT.999"
        self._add_reference(datasets[slice_idx], fake_uid)
        return self._create_ref_record(
            attack_type="reference_nonexistent",
            slice_index=slice_idx,
            mutated_value=f"references {fake_uid[:40]}...",
            details={"fake_uid": fake_uid},
        )

    def _handle_circular_reference(
        self, datasets: list[Dataset], existing_uids: list[str]
    ) -> SeriesMutationRecord | None:
        """Handle circular_reference attack type."""
        if len(datasets) < 3:
            return None

        for i in range(min(3, len(datasets))):
            next_idx = (i + 1) % min(3, len(datasets))
            next_uid = (
                existing_uids[next_idx]
                if next_idx < len(existing_uids)
                else generate_uid()
            )
            self._add_reference(datasets[i], next_uid)

        return self._create_ref_record(
            attack_type="circular_reference",
            slice_index=None,
            mutated_value="circular: 0->1->2->0",
        )

    def _handle_invalid_uid_format(
        self, datasets: list[Dataset], existing_uids: list[str]
    ) -> SeriesMutationRecord:
        """Handle invalid_uid_format attack type."""
        invalid_uids = [
            "",
            "not.a.valid.uid.format!@#$%",
            "a" * 100,
            "1.2.3.",
            ".1.2.3",
            "1..2..3",
            "\x00\x00\x00",
        ]
        slice_idx = random.randint(0, len(datasets) - 1)
        invalid_uid = random.choice(invalid_uids)
        self._add_reference(datasets[slice_idx], invalid_uid)
        return self._create_ref_record(
            attack_type="invalid_uid_format",
            slice_index=slice_idx,
            mutated_value=repr(invalid_uid)[:50],
            tag="ReferencedSOPInstanceUID",
        )

    def _handle_self_reference(
        self, datasets: list[Dataset], existing_uids: list[str]
    ) -> SeriesMutationRecord:
        """Handle self_reference attack type."""
        slice_idx = random.randint(0, len(datasets) - 1)
        ds = datasets[slice_idx]
        own_uid = getattr(ds, "SOPInstanceUID", generate_uid())
        class_uid = getattr(ds, "SOPClassUID", self._CT_SOP_CLASS_UID)
        self._add_reference(ds, own_uid, class_uid)
        return self._create_ref_record(
            attack_type="self_reference",
            slice_index=slice_idx,
            mutated_value="<self_reference>",
        )

    def _handle_duplicate_references(
        self, datasets: list[Dataset], existing_uids: list[str]
    ) -> SeriesMutationRecord:
        """Handle duplicate_references attack type."""
        slice_idx = random.randint(0, len(datasets) - 1)
        target_uid = existing_uids[0] if existing_uids else generate_uid()
        for _ in range(10):
            self._add_reference(datasets[slice_idx], target_uid)
        return self._create_ref_record(
            attack_type="duplicate_references",
            slice_index=slice_idx,
            mutated_value="10x duplicate references",
        )

    def _handle_missing_reference_chain(
        self, datasets: list[Dataset], existing_uids: list[str]
    ) -> SeriesMutationRecord | None:
        """Handle missing_reference_chain attack type."""
        if len(datasets) < 2:
            return None

        uid1 = existing_uids[1] if len(existing_uids) > 1 else generate_uid()
        self._add_reference(datasets[0], uid1)
        self._add_reference(datasets[1], generate_uid() + ".MISSING")

        return self._create_ref_record(
            attack_type="missing_reference_chain",
            slice_index=None,
            mutated_value="broken chain: 0->1->missing",
        )

    def _mutate_cross_slice_reference(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 11: Cross-Slice Reference Corruption.

        Manipulates ReferencedSOPInstanceUID and related cross-slice references:
        - Reference non-existent slices
        - Create circular references between slices
        - Use invalid UID format
        - Reference deleted/missing slices
        - Self-referencing (slice references itself)

        Targets: Series reconstruction, slice linking, registration algorithms
        """
        records: list[SeriesMutationRecord] = []

        if not datasets:
            return datasets, records

        existing_uids = [
            str(ds.SOPInstanceUID) for ds in datasets if hasattr(ds, "SOPInstanceUID")
        ]

        attack_handlers = {
            "reference_nonexistent": self._handle_reference_nonexistent,
            "circular_reference": self._handle_circular_reference,
            "invalid_uid_format": self._handle_invalid_uid_format,
            "self_reference": self._handle_self_reference,
            "duplicate_references": self._handle_duplicate_references,
            "missing_reference_chain": self._handle_missing_reference_chain,
        }

        for _ in range(mutation_count):
            attack_type = random.choice(list(attack_handlers.keys()))
            handler = attack_handlers[attack_type]
            record = handler(datasets, existing_uids)
            if record:
                records.append(record)

        return datasets, records

    def _temporal_randomize(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord]
    ) -> None:
        """Randomize acquisition times across all slices."""
        for ds in datasets:
            ds.AcquisitionTime = (
                f"{random.randint(0, 23):02d}{random.randint(0, 59):02d}"
                f"{random.randint(0, 59):02d}"
            )
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=None,
                tag="AcquisitionTime",
                original_value="<sequential>",
                mutated_value="<randomized>",
                severity=self.severity,
                details={"attack_type": "randomize_acquisition_time"},
            )
        )

    def _temporal_duplicate(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord]
    ) -> None:
        """Set all slices to identical timestamp."""
        for ds in datasets:
            ds.AcquisitionTime = "120000.000000"
            ds.AcquisitionDateTime = "20230101120000.000000"
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=None,
                tag="AcquisitionTime",
                original_value="<unique>",
                mutated_value="all=120000.000000",
                severity=self.severity,
                details={"attack_type": "duplicate_timestamps"},
            )
        )

    def _temporal_extreme_date(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord], past: bool
    ) -> None:
        """Set extreme date (1900 or 9999)."""
        slice_idx = random.randint(0, len(datasets) - 1)
        ds = datasets[slice_idx]
        if past:
            ds.AcquisitionDate = "19000101"
            ds.AcquisitionDateTime = "19000101000000.000000"
            mutated = "19000101"
        else:
            ds.AcquisitionDate = "99991231"
            ds.AcquisitionDateTime = "99991231235959.999999"
            mutated = "99991231"
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=slice_idx,
                tag="AcquisitionDate",
                original_value="<modern>",
                mutated_value=mutated,
                severity=self.severity,
                details={
                    "attack_type": "extreme_past_date"
                    if past
                    else "extreme_future_date"
                },
            )
        )

    def _temporal_invalid_format(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord]
    ) -> None:
        """Set invalid time format."""
        slice_idx = random.randint(0, len(datasets) - 1)
        invalid_times = [
            "25:00:00",
            "12:60:00",
            "-1:00:00",
            "abc",
            "",
            "999999999999",
            "12.34.56",
        ]
        datasets[slice_idx].AcquisitionTime = random.choice(invalid_times)
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=slice_idx,
                tag="AcquisitionTime",
                original_value="<valid>",
                mutated_value=repr(datasets[slice_idx].AcquisitionTime),
                severity=self.severity,
                details={"attack_type": "invalid_time_format"},
            )
        )

    def _temporal_reversal(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord]
    ) -> None:
        """Reverse temporal order vs InstanceNumber."""
        for i, ds in enumerate(datasets):
            ds.AcquisitionTime = f"12{len(datasets) - 1 - i:02d}00.000000"
            ds.InstanceNumber = i + 1
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=None,
                tag="AcquisitionTime",
                original_value="<matches_instance_order>",
                mutated_value="<reversed_vs_instance>",
                severity=self.severity,
                details={"attack_type": "temporal_order_reversal"},
            )
        )

    def _temporal_subsecond(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord]
    ) -> None:
        """Conflicts within same millisecond."""
        for i, ds in enumerate(datasets):
            ds.AcquisitionTime = f"120000.{(i * 7) % 1000:06d}"
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=None,
                tag="AcquisitionTime",
                original_value="<spread_over_seconds>",
                mutated_value="<all_within_1ms>",
                severity=self.severity,
                details={"attack_type": "subsecond_conflicts"},
            )
        )

    def _temporal_instance_creation_chaos(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord]
    ) -> None:
        """Corrupt InstanceCreationTime/Date to disagree with AcquisitionTime.

        DICOM PS3.3 C.12.1: InstanceCreationDate/Time describe when the
        SOP Instance was created -- typically very close to AcquisitionTime.
        Implementations that sort or correlate instances by creation time
        (rather than AcquisitionTime) may produce incorrect multi-frame
        reconstructions when these fields diverge.
        """
        slice_idx = random.randint(0, len(datasets) - 1)
        ds = datasets[slice_idx]
        sub = random.choice(["past_date", "future_date", "invalid_time", "empty_time"])
        if sub == "past_date":
            ds.InstanceCreationDate = "19000101"
            ds.InstanceCreationTime = "000000.000000"
            mutated = "19000101 000000.000000"
        elif sub == "future_date":
            ds.InstanceCreationDate = "99991231"
            ds.InstanceCreationTime = "235959.999999"
            mutated = "99991231 235959.999999"
        elif sub == "invalid_time":
            ds.InstanceCreationTime = "25:00:00"
            mutated = "25:00:00"
        else:  # empty_time
            ds.InstanceCreationTime = ""
            mutated = ""
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=slice_idx,
                tag="InstanceCreationTime",
                original_value="<matches_acquisition>",
                mutated_value=mutated,
                severity=self.severity,
                details={"attack_type": "instance_creation_chaos", "sub": sub},
            )
        )

    def _temporal_delta_violation(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord]
    ) -> None:
        """Inject impossible time deltas between consecutive slices.

        For a correctly ordered series AcquisitionTime[i+1] > AcquisitionTime[i].
        Three violation patterns:
        - negative_delta: later slices get earlier times (order reversal per slice)
        - zero_delta: consecutive slices share identical timestamps
        - huge_delta: a 23-hour jump between adjacent slices

        Targets 4D cardiac/perfusion viewers that compute inter-frame
        timing from AcquisitionTime without range-checking the deltas.
        """
        if len(datasets) < 2:
            return
        sub = random.choice(["negative_delta", "zero_delta", "huge_delta"])
        if sub == "negative_delta":
            # Descending time: each slice 1 minute earlier than the previous
            for i, ds in enumerate(datasets):
                seconds = 120000 - i * 100  # 120000 HHMMSS, subtract 100s = 1m40s
                ds.AcquisitionTime = f"{max(0, seconds):06d}.000000"
            mutated = "descending per slice"
        elif sub == "zero_delta":
            # First two slices share the same timestamp
            datasets[0].AcquisitionTime = "120000.000000"
            datasets[1].AcquisitionTime = "120000.000000"
            mutated = "slices 0+1 share 120000.000000"
        else:  # huge_delta
            # 23-hour gap between slice 0 and slice 1
            datasets[0].AcquisitionTime = "000000.000000"
            datasets[1].AcquisitionTime = "230000.000000"
            mutated = "0->1: 23-hour gap"
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=None,
                tag="AcquisitionTime",
                original_value="<monotone_increasing>",
                mutated_value=mutated,
                severity=self.severity,
                details={"attack_type": "delta_violation", "sub": sub},
            )
        )

    def _temporal_cardiac_trigger_chaos(
        self, datasets: list[Dataset], records: list[SeriesMutationRecord]
    ) -> None:
        """Corrupt TriggerTime for cardiac gating attacks.

        TriggerTime (0018,1060) is the time in milliseconds from the
        R-wave trigger to the image acquisition in cardiac-gated series.
        At a typical heart rate of 60 bpm the RR interval is 1000 ms, so
        valid TriggerTime values fall in [0, 1000).

        Attack patterns:
        - negative_trigger: TriggerTime < 0 (impossible)
        - exceed_rr: TriggerTime > expected RR interval (contradicts HeartRate)
        - zero_trigger: all slices at TriggerTime=0 (duplicate cardiac phases)
        - nan_trigger: non-numeric string value

        Targets cardiac cine viewers and perfusion maps that interpolate
        between trigger times without validating the range.
        """
        sub = random.choice(
            ["negative_trigger", "exceed_rr", "zero_trigger", "nan_trigger"]
        )
        if sub == "negative_trigger":
            for ds in datasets:
                ds.TriggerTime = -1.0
            mutated = "-1.0"
        elif sub == "exceed_rr":
            # At 60 bpm RR=1000 ms; set trigger to 5000 ms (5x overshoot)
            for ds in datasets:
                ds.TriggerTime = 5000.0
                ds.HeartRate = 60
            mutated = "5000.0 (RR@60bpm=1000ms)"
        elif sub == "zero_trigger":
            for ds in datasets:
                ds.TriggerTime = 0.0
            mutated = "0.0 (all phases identical)"
        else:  # nan_trigger
            for ds in datasets:
                ds.TriggerTime = float("nan")
            mutated = "NaN"
        records.append(
            SeriesMutationRecord(
                strategy="temporal_inconsistency",
                slice_index=None,
                tag="TriggerTime",
                original_value="<valid_cardiac_phase>",
                mutated_value=mutated,
                severity=self.severity,
                details={"attack_type": "cardiac_trigger_chaos", "sub": sub},
            )
        )

    def _mutate_temporal_inconsistency(
        self, datasets: list[Dataset], series: DicomSeries, mutation_count: int
    ) -> tuple[list[Dataset], list[SeriesMutationRecord]]:
        """Strategy 12: Temporal Inconsistency Injection.

        Creates temporal ordering conflicts across slices:
        - Randomized AcquisitionTime values
        - Duplicate timestamps across slices
        - Extreme time values (year 1900, year 9999)
        - Invalid time format strings
        - AcquisitionTime conflicts with InstanceNumber order
        - InstanceCreationTime/Date disagreeing with AcquisitionTime
        - Impossible inter-slice time deltas (negative, zero, 23-hour)
        - Cardiac TriggerTime outside valid RR interval

        Targets: 4D reconstruction, temporal sorting, cine viewers,
        cardiac gating, and perfusion map generation.
        """
        records: list[SeriesMutationRecord] = []
        attacks = [
            "randomize",
            "duplicate",
            "past",
            "future",
            "invalid",
            "reversal",
            "subsecond",
            "instance_creation",
            "delta_violation",
            "cardiac_trigger",
        ]

        for _ in range(mutation_count):
            attack = random.choice(attacks)
            if attack == "randomize":
                self._temporal_randomize(datasets, records)
            elif attack == "duplicate":
                self._temporal_duplicate(datasets, records)
            elif attack == "past":
                self._temporal_extreme_date(datasets, records, past=True)
            elif attack == "future":
                self._temporal_extreme_date(datasets, records, past=False)
            elif attack == "invalid":
                self._temporal_invalid_format(datasets, records)
            elif attack == "reversal":
                self._temporal_reversal(datasets, records)
            elif attack == "subsecond":
                self._temporal_subsecond(datasets, records)
            elif attack == "instance_creation":
                self._temporal_instance_creation_chaos(datasets, records)
            elif attack == "delta_violation":
                self._temporal_delta_violation(datasets, records)
            elif attack == "cardiac_trigger":
                self._temporal_cardiac_trigger_chaos(datasets, records)

        return datasets, records
