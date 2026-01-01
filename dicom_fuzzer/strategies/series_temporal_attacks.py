"""Temporal and Cross-Slice Attack Strategies (v1.8.0)

This module provides the TemporalAttacksMixin with two specialized mutation
strategies targeting cross-slice references and temporal ordering vulnerabilities.

Strategies:
11. Cross-Slice Reference - Corrupts ReferencedSOPInstanceUID relationships
12. Temporal Inconsistency - Creates temporal ordering conflicts
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

import pydicom
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

if TYPE_CHECKING:
    from dicom_fuzzer.core.dicom_series import DicomSeries
    from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord


class TemporalAttacksMixin:
    """Mixin providing temporal and cross-slice attack strategies.

    This mixin assumes the class has:
    - self.severity: str - The mutation severity level
    """

    severity: str  # Type hint for mixin

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
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        records: list[SeriesMutationRecord] = []

        # Collect existing SOPInstanceUIDs for reference
        existing_uids = []
        for ds in datasets:
            if hasattr(ds, "SOPInstanceUID"):
                existing_uids.append(str(ds.SOPInstanceUID))

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "reference_nonexistent",
                    "circular_reference",
                    "invalid_uid_format",
                    "self_reference",
                    "duplicate_references",
                    "missing_reference_chain",
                ]
            )

            if attack_type == "reference_nonexistent":
                # Add reference to a SOP Instance that doesn't exist
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]

                fake_uid = generate_uid() + ".NONEXISTENT.999"

                # Add to ReferencedImageSequence
                if not hasattr(ds, "ReferencedImageSequence"):
                    ds.ReferencedImageSequence = pydicom.Sequence([])

                ref_item = pydicom.Dataset()
                ref_item.ReferencedSOPClassUID = (
                    "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
                )
                ref_item.ReferencedSOPInstanceUID = fake_uid
                ds.ReferencedImageSequence.append(ref_item)

                records.append(
                    SeriesMutationRecord(
                        strategy="cross_slice_reference",
                        slice_index=slice_idx,
                        tag="ReferencedImageSequence",
                        original_value="<none>",
                        mutated_value=f"references {fake_uid[:40]}...",
                        severity=self.severity,
                        details={"attack_type": attack_type, "fake_uid": fake_uid},
                    )
                )

            elif attack_type == "circular_reference":
                # Create A -> B -> C -> A circular reference
                if len(datasets) >= 3:
                    for i in range(min(3, len(datasets))):
                        ds = datasets[i]
                        next_idx = (i + 1) % min(3, len(datasets))
                        next_uid = (
                            existing_uids[next_idx]
                            if next_idx < len(existing_uids)
                            else generate_uid()
                        )

                        if not hasattr(ds, "ReferencedImageSequence"):
                            ds.ReferencedImageSequence = pydicom.Sequence([])

                        ref_item = pydicom.Dataset()
                        ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                        ref_item.ReferencedSOPInstanceUID = next_uid
                        ds.ReferencedImageSequence.append(ref_item)

                    records.append(
                        SeriesMutationRecord(
                            strategy="cross_slice_reference",
                            slice_index=None,
                            tag="ReferencedImageSequence",
                            original_value="<no_circular>",
                            mutated_value="circular: 0->1->2->0",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

            elif attack_type == "invalid_uid_format":
                # Use completely invalid UID format
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]

                invalid_uids = [
                    "",  # Empty
                    "not.a.valid.uid.format!@#$%",  # Special chars
                    "a" * 100,  # Too long, letters
                    "1.2.3.",  # Trailing dot
                    ".1.2.3",  # Leading dot
                    "1..2..3",  # Double dots
                    "\x00\x00\x00",  # Null bytes
                ]
                invalid_uid = random.choice(invalid_uids)

                if not hasattr(ds, "ReferencedImageSequence"):
                    ds.ReferencedImageSequence = pydicom.Sequence([])

                ref_item = pydicom.Dataset()
                ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                ref_item.ReferencedSOPInstanceUID = invalid_uid
                ds.ReferencedImageSequence.append(ref_item)

                records.append(
                    SeriesMutationRecord(
                        strategy="cross_slice_reference",
                        slice_index=slice_idx,
                        tag="ReferencedSOPInstanceUID",
                        original_value="<none>",
                        mutated_value=repr(invalid_uid)[:50],
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "self_reference":
                # Slice references itself
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                own_uid = getattr(ds, "SOPInstanceUID", generate_uid())

                if not hasattr(ds, "ReferencedImageSequence"):
                    ds.ReferencedImageSequence = pydicom.Sequence([])

                ref_item = pydicom.Dataset()
                ref_item.ReferencedSOPClassUID = getattr(
                    ds, "SOPClassUID", "1.2.840.10008.5.1.4.1.1.2"
                )
                ref_item.ReferencedSOPInstanceUID = own_uid
                ds.ReferencedImageSequence.append(ref_item)

                records.append(
                    SeriesMutationRecord(
                        strategy="cross_slice_reference",
                        slice_index=slice_idx,
                        tag="ReferencedImageSequence",
                        original_value="<none>",
                        mutated_value="<self_reference>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "duplicate_references":
                # Same slice referenced multiple times
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]

                target_uid = existing_uids[0] if existing_uids else generate_uid()

                if not hasattr(ds, "ReferencedImageSequence"):
                    ds.ReferencedImageSequence = pydicom.Sequence([])

                # Add same reference 10 times
                for _ in range(10):
                    ref_item = pydicom.Dataset()
                    ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                    ref_item.ReferencedSOPInstanceUID = target_uid
                    ds.ReferencedImageSequence.append(ref_item)

                records.append(
                    SeriesMutationRecord(
                        strategy="cross_slice_reference",
                        slice_index=slice_idx,
                        tag="ReferencedImageSequence",
                        original_value="<none>",
                        mutated_value="10x duplicate references",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "missing_reference_chain":
                # Create broken reference chain A -> B -> [missing]
                if len(datasets) >= 2:
                    # First slice references second
                    ds0 = datasets[0]
                    if not hasattr(ds0, "ReferencedImageSequence"):
                        ds0.ReferencedImageSequence = pydicom.Sequence([])

                    ref_item = pydicom.Dataset()
                    ref_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                    ref_item.ReferencedSOPInstanceUID = (
                        existing_uids[1] if len(existing_uids) > 1 else generate_uid()
                    )
                    ds0.ReferencedImageSequence.append(ref_item)

                    # Second slice references non-existent
                    ds1 = datasets[1]
                    if not hasattr(ds1, "ReferencedImageSequence"):
                        ds1.ReferencedImageSequence = pydicom.Sequence([])

                    ref_item2 = pydicom.Dataset()
                    ref_item2.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
                    ref_item2.ReferencedSOPInstanceUID = generate_uid() + ".MISSING"
                    ds1.ReferencedImageSequence.append(ref_item2)

                    records.append(
                        SeriesMutationRecord(
                            strategy="cross_slice_reference",
                            slice_index=None,
                            tag="ReferencedImageSequence",
                            original_value="<none>",
                            mutated_value="broken chain: 0->1->missing",
                            severity=self.severity,
                            details={"attack_type": attack_type},
                        )
                    )

        return datasets, records

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

        Targets: 4D reconstruction, temporal sorting, cine viewers
        """
        from dicom_fuzzer.strategies.series_mutator import SeriesMutationRecord

        records: list[SeriesMutationRecord] = []

        for _ in range(mutation_count):
            attack_type = random.choice(
                [
                    "randomize_acquisition_time",
                    "duplicate_timestamps",
                    "extreme_past_date",
                    "extreme_future_date",
                    "invalid_time_format",
                    "temporal_order_reversal",
                    "subsecond_conflicts",
                ]
            )

            if attack_type == "randomize_acquisition_time":
                # Completely randomize acquisition times
                for _i, ds in enumerate(datasets):
                    random_hour = random.randint(0, 23)
                    random_min = random.randint(0, 59)
                    random_sec = random.randint(0, 59)
                    ds.AcquisitionTime = (
                        f"{random_hour:02d}{random_min:02d}{random_sec:02d}"
                    )

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=None,
                        tag="AcquisitionTime",
                        original_value="<sequential>",
                        mutated_value="<randomized>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "duplicate_timestamps":
                # All slices have identical timestamp
                duplicate_time = "120000.000000"
                for ds in datasets:
                    ds.AcquisitionTime = duplicate_time
                    ds.AcquisitionDateTime = "20230101120000.000000"

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=None,
                        tag="AcquisitionTime",
                        original_value="<unique>",
                        mutated_value=f"all={duplicate_time}",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extreme_past_date":
                # Date from 1900
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                ds.AcquisitionDate = "19000101"
                ds.AcquisitionDateTime = "19000101000000.000000"

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=slice_idx,
                        tag="AcquisitionDate",
                        original_value="<modern>",
                        mutated_value="19000101",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "extreme_future_date":
                # Date in year 9999
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]
                ds.AcquisitionDate = "99991231"
                ds.AcquisitionDateTime = "99991231235959.999999"

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=slice_idx,
                        tag="AcquisitionDate",
                        original_value="<modern>",
                        mutated_value="99991231",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "invalid_time_format":
                # Invalid DICOM time format
                slice_idx = random.randint(0, len(datasets) - 1)
                ds = datasets[slice_idx]

                invalid_times = [
                    "25:00:00",  # Invalid hour
                    "12:60:00",  # Invalid minute
                    "-1:00:00",  # Negative
                    "abc",  # Non-numeric
                    "",  # Empty
                    "999999999999",  # Too long
                    "12.34.56",  # Wrong separator
                ]
                ds.AcquisitionTime = random.choice(invalid_times)

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=slice_idx,
                        tag="AcquisitionTime",
                        original_value="<valid>",
                        mutated_value=repr(ds.AcquisitionTime),
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "temporal_order_reversal":
                # Acquisition times in reverse order vs InstanceNumber
                for i, ds in enumerate(datasets):
                    reversed_idx = len(datasets) - 1 - i
                    # Time increases as instance number decreases
                    ds.AcquisitionTime = f"12{reversed_idx:02d}00.000000"
                    # But keep InstanceNumber sequential
                    ds.InstanceNumber = i + 1

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=None,
                        tag="AcquisitionTime",
                        original_value="<matches_instance_order>",
                        mutated_value="<reversed_vs_instance>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

            elif attack_type == "subsecond_conflicts":
                # Multiple acquisitions in same millisecond
                base_time = "120000"
                for i, ds in enumerate(datasets):
                    # All within same millisecond but different microseconds
                    microsec = (i * 7) % 1000  # Spread within 1ms
                    ds.AcquisitionTime = f"{base_time}.{microsec:06d}"

                records.append(
                    SeriesMutationRecord(
                        strategy="temporal_inconsistency",
                        slice_index=None,
                        tag="AcquisitionTime",
                        original_value="<spread_over_seconds>",
                        mutated_value="<all_within_1ms>",
                        severity=self.severity,
                        details={"attack_type": attack_type},
                    )
                )

        return datasets, records
