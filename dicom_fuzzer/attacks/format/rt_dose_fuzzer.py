"""RT Dose Fuzzer - DICOM RT Dose Mutations.

Category: modality-specific (RT Dose)

Attacks:
- DoseGridScaling zero, negative, NaN, extreme values
- DVHSequence with malformed DVHData arrays
- GridFrameOffsetVector length mismatches and non-monotonic values
- DoseType/DoseSummationType invalid enumeration values
- Referenced RT Plan link corruption
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.uid import generate_uid

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_RT_DOSE_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.481.2"


class RTDoseFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM RT Dose objects to test dose display robustness.

    RT Dose has pixel-like dose grid data that generic pixel fuzzers
    partially cover, but domain-specific tags like DoseGridScaling,
    DVHSequence, and GridFrameOffsetVector need targeted mutations.
    """

    def __init__(self) -> None:
        """Initialize the RT dose fuzzer with attack strategies."""
        super().__init__()
        self.mutation_strategies = [
            self._dose_grid_scaling_attack,
            self._dvh_sequence_corruption,
            self._grid_frame_offset_attack,
            self._dose_type_enumeration_attack,
            self._referenced_rt_plan_corruption,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "rt_dose"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate RT Dose Storage datasets."""
        sop_class = getattr(dataset, "SOPClassUID", None)
        return str(sop_class) == _RT_DOSE_SOP_CLASS_UID

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply RT dose mutations to the dataset.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with dose-specific corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("RT dose mutation failed: %s", e)

        return dataset

    def _dose_grid_scaling_attack(self, dataset: Dataset) -> Dataset:
        """Set DoseGridScaling to zero, negative, NaN, or extreme values."""
        attack = random.choice(
            [
                "zero_scaling",
                "negative_scaling",
                "nan_scaling",
                "extreme_scaling",
                "remove_scaling",
            ]
        )

        try:
            if attack == "zero_scaling":
                dataset.DoseGridScaling = "0.0"
            elif attack == "negative_scaling":
                dataset.DoseGridScaling = "-0.001"
            elif attack == "nan_scaling":
                dataset.DoseGridScaling = random.choice(["NaN", "Inf", "-Inf"])
            elif attack == "extreme_scaling":
                dataset.DoseGridScaling = random.choice(["1e308", "1e-308"])
            elif attack == "remove_scaling":
                if "DoseGridScaling" in dataset:
                    del dataset.DoseGridScaling
        except Exception as e:
            logger.debug("Dose grid scaling attack failed: %s", e)

        return dataset

    def _dvh_sequence_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt DVHSequence with malformed DVHData dose/volume arrays."""
        attack = random.choice(
            [
                "truncated_dvh_data",
                "nan_dvh_values",
                "bin_count_mismatch",
                "inverted_statistics",
                "remove_dvh_sequence",
            ]
        )

        try:
            if attack == "truncated_dvh_data":
                dvh_seq = getattr(dataset, "DVHSequence", None)
                if dvh_seq and len(dvh_seq) > 0:
                    dvh_seq[0].DVHData = ["1.0", "100.0", "5.0"]  # odd count
                else:
                    item = Dataset()
                    item.DVHType = "CUMULATIVE"
                    item.DVHData = ["1.0", "100.0", "5.0"]  # odd count
                    item.DVHNumberOfBins = 2
                    dataset.DVHSequence = Sequence([item])
            elif attack == "nan_dvh_values":
                dvh_seq = getattr(dataset, "DVHSequence", None)
                if dvh_seq and len(dvh_seq) > 0:
                    dvh_seq[0].DVHData = [
                        "NaN",
                        "Inf",
                        "-Inf",
                        "100.0",
                        "1e308",
                        "0.0",
                    ]
                else:
                    item = Dataset()
                    item.DVHType = "CUMULATIVE"
                    item.DVHData = [
                        "NaN",
                        "Inf",
                        "-Inf",
                        "100.0",
                        "1e308",
                        "0.0",
                    ]
                    item.DVHNumberOfBins = 3
                    dataset.DVHSequence = Sequence([item])
            elif attack == "bin_count_mismatch":
                dvh_seq = getattr(dataset, "DVHSequence", None)
                if dvh_seq and len(dvh_seq) > 0:
                    dvh_seq[0].DVHNumberOfBins = 999  # actual pairs << 999
                else:
                    item = Dataset()
                    item.DVHType = "CUMULATIVE"
                    item.DVHData = ["1.0", "100.0", "5.0", "80.0"]
                    item.DVHNumberOfBins = 999
                    dataset.DVHSequence = Sequence([item])
            elif attack == "inverted_statistics":
                dvh_seq = getattr(dataset, "DVHSequence", None)
                if dvh_seq and len(dvh_seq) > 0:
                    dvh_seq[0].DVHMinimumDose = "100.0"
                    dvh_seq[0].DVHMaximumDose = "1.0"
                    dvh_seq[0].DVHMeanDose = "200.0"
                else:
                    item = Dataset()
                    item.DVHType = "CUMULATIVE"
                    item.DVHMinimumDose = "100.0"
                    item.DVHMaximumDose = "1.0"
                    item.DVHMeanDose = "200.0"
                    dataset.DVHSequence = Sequence([item])
            elif attack == "remove_dvh_sequence":
                if "DVHSequence" in dataset:
                    del dataset.DVHSequence
        except Exception as e:
            logger.debug("DVH sequence corruption failed: %s", e)

        return dataset

    def _grid_frame_offset_attack(self, dataset: Dataset) -> Dataset:
        """Create GridFrameOffsetVector length mismatches and non-monotonic values."""
        attack = random.choice(
            [
                "length_mismatch",
                "non_monotonic",
                "nan_offsets",
                "reversed_order",
                "remove_offsets",
            ]
        )

        try:
            if attack == "length_mismatch":
                dataset.NumberOfFrames = "3"
                dataset.GridFrameOffsetVector = [
                    "0.0",
                    "2.5",
                    "5.0",
                    "7.5",
                    "10.0",
                    "12.5",
                    "15.0",
                    "17.5",
                    "20.0",
                    "22.5",
                ]  # 10 offsets for 3 frames
            elif attack == "non_monotonic":
                dataset.GridFrameOffsetVector = [
                    "0.0",
                    "5.0",
                    "2.5",
                    "7.5",
                    "3.0",
                ]
            elif attack == "nan_offsets":
                dataset.GridFrameOffsetVector = [
                    "0.0",
                    "NaN",
                    "Inf",
                    "-Inf",
                    "5.0",
                ]
            elif attack == "reversed_order":
                dataset.GridFrameOffsetVector = [
                    "20.0",
                    "15.0",
                    "10.0",
                    "5.0",
                    "0.0",
                ]
            elif attack == "remove_offsets":
                if "GridFrameOffsetVector" in dataset:
                    del dataset.GridFrameOffsetVector
        except Exception as e:
            logger.debug("Grid frame offset attack failed: %s", e)

        return dataset

    def _dose_type_enumeration_attack(self, dataset: Dataset) -> Dataset:
        """Set DoseType and DoseSummationType to invalid enumeration values."""
        attack = random.choice(
            [
                "invalid_dose_type",
                "invalid_summation_type",
                "invalid_dose_units",
                "empty_enums",
                "remove_enums",
            ]
        )

        try:
            if attack == "invalid_dose_type":
                dataset.DoseType = random.choice(["INVALID", "QUANTUM", "A" * 5000])
            elif attack == "invalid_summation_type":
                dataset.DoseSummationType = random.choice(
                    ["INVALID", "TOTAL", "A" * 5000]
                )
            elif attack == "invalid_dose_units":
                dataset.DoseUnits = random.choice(
                    ["INVALID", "RAD", "SIEVERT", "A" * 5000]
                )
            elif attack == "empty_enums":
                dataset.DoseType = ""
                dataset.DoseSummationType = ""
                dataset.DoseUnits = ""
            elif attack == "remove_enums":
                for tag in ("DoseType", "DoseSummationType", "DoseUnits"):
                    if tag in dataset:
                        del dataset[tag]
        except Exception as e:
            logger.debug("Dose type enumeration attack failed: %s", e)

        return dataset

    def _referenced_rt_plan_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt ReferencedRTPlanSequence links to treatment plans."""
        attack = random.choice(
            [
                "invalid_plan_uid",
                "orphan_beam_ref",
                "missing_fraction_ref",
                "empty_plan_sequence",
                "remove_plan_ref",
            ]
        )

        try:
            if attack == "invalid_plan_uid":
                ref_seq = getattr(dataset, "ReferencedRTPlanSequence", None)
                if ref_seq and len(ref_seq) > 0:
                    ref_seq[0].ReferencedSOPInstanceUID = "INVALID_UID"
                else:
                    item = Dataset()
                    item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.481.5"
                    item.ReferencedSOPInstanceUID = "INVALID_UID"
                    dataset.ReferencedRTPlanSequence = Sequence([item])
            elif attack == "orphan_beam_ref":
                ref_seq = getattr(dataset, "ReferencedRTPlanSequence", None)
                if ref_seq and len(ref_seq) > 0:
                    beam_item = Dataset()
                    beam_item.ReferencedBeamNumber = 9999
                    ref_seq[0].ReferencedBeamSequence = Sequence([beam_item])
                else:
                    plan_item = Dataset()
                    plan_item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.481.5"
                    plan_item.ReferencedSOPInstanceUID = generate_uid()
                    beam_item = Dataset()
                    beam_item.ReferencedBeamNumber = 9999
                    plan_item.ReferencedBeamSequence = Sequence([beam_item])
                    dataset.ReferencedRTPlanSequence = Sequence([plan_item])
            elif attack == "missing_fraction_ref":
                ref_seq = getattr(dataset, "ReferencedRTPlanSequence", None)
                if ref_seq and len(ref_seq) > 0:
                    if "ReferencedFractionGroupSequence" in ref_seq[0]:
                        del ref_seq[0].ReferencedFractionGroupSequence
                else:
                    item = Dataset()
                    item.ReferencedSOPClassUID = "1.2.840.10008.5.1.4.1.1.481.5"
                    item.ReferencedSOPInstanceUID = generate_uid()
                    dataset.ReferencedRTPlanSequence = Sequence([item])
            elif attack == "empty_plan_sequence":
                dataset.ReferencedRTPlanSequence = Sequence([])
            elif attack == "remove_plan_ref":
                if "ReferencedRTPlanSequence" in dataset:
                    del dataset.ReferencedRTPlanSequence
        except Exception as e:
            logger.debug("Referenced RT plan corruption failed: %s", e)

        return dataset


__all__ = ["RTDoseFuzzer"]
