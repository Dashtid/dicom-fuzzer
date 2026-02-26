"""PET Fuzzer - DICOM PET Image Mutations.

Category: modality-specific (PET)

Attacks:
- SUV calibration chain corruption (Units, DecayCorrection, weight, size)
- Radiopharmaceutical decay parameter manipulation
- Temporal parameter corruption (DecayFactor, FrameReferenceTime)
- CorrectedImage flag combinations
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_PET_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.128"


class PetFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM PET objects to test SUV and decay handling robustness.

    PET images have a calibration chain (Units -> DecayCorrection ->
    PatientWeight -> RadionuclideHalfLife) that must be consistent for
    SUV computation. Corrupting any link in this chain tests how the
    viewer handles invalid quantitative data.
    """

    def __init__(self) -> None:
        """Initialize the PET fuzzer with attack strategies."""
        super().__init__()
        self.mutation_strategies = [
            self._suv_calibration_chain_attack,
            self._radiopharmaceutical_decay_attack,
            self._temporal_parameter_corruption,
            self._corrected_image_flag_attack,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "pet"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate PET Image Storage datasets."""
        sop_class = getattr(dataset, "SOPClassUID", None)
        return str(sop_class) == _PET_SOP_CLASS_UID

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply PET-specific mutations to the dataset.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with PET-specific corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("PET mutation failed: %s", e)

        return dataset

    def _suv_calibration_chain_attack(self, dataset: Dataset) -> Dataset:
        """Create inconsistencies in Units / DecayCorrection / PatientWeight / PatientSize."""
        attack = random.choice(
            [
                "invalid_units",
                "missing_weight",
                "zero_weight",
                "conflicting_suv_type",
                "remove_units",
            ]
        )

        try:
            if attack == "invalid_units":
                dataset.Units = random.choice(["", "INVALID", "BQML\\CNTS", "A" * 5000])
            elif attack == "missing_weight":
                if "PatientWeight" in dataset:
                    del dataset.PatientWeight
                if "PatientSize" in dataset:
                    del dataset.PatientSize
            elif attack == "zero_weight":
                dataset.PatientWeight = random.choice(["0.0", "-70.0", "999999.0"])
            elif attack == "conflicting_suv_type":
                dataset.Units = "CNTS"
                dataset.SUVType = "BW"  # SUVType requires Units=BQML
            elif attack == "remove_units":
                for tag in ("Units", "DecayCorrection", "SUVType"):
                    if tag in dataset:
                        del dataset[tag]
        except Exception as e:
            logger.debug("SUV calibration chain attack failed: %s", e)

        return dataset

    def _radiopharmaceutical_decay_attack(self, dataset: Dataset) -> Dataset:
        """Corrupt RadionuclideHalfLife, RadionuclideTotalDose, RadiopharmaceuticalStartDateTime."""
        attack = random.choice(
            [
                "zero_half_life",
                "negative_dose",
                "future_start_time",
                "zero_positron_fraction",
                "remove_sequence",
            ]
        )

        try:
            if attack == "zero_half_life":
                seq = getattr(dataset, "RadiopharmaceuticalInformationSequence", None)
                if seq and len(seq) > 0:
                    seq[0].RadionuclideHalfLife = "0.0"
                else:
                    item = Dataset()
                    item.RadionuclideHalfLife = "0.0"
                    dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
            elif attack == "negative_dose":
                seq = getattr(dataset, "RadiopharmaceuticalInformationSequence", None)
                if seq and len(seq) > 0:
                    seq[0].RadionuclideTotalDose = "-370000000.0"
                else:
                    item = Dataset()
                    item.RadionuclideTotalDose = "-370000000.0"
                    dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
            elif attack == "future_start_time":
                seq = getattr(dataset, "RadiopharmaceuticalInformationSequence", None)
                if seq and len(seq) > 0:
                    seq[0].RadiopharmaceuticalStartDateTime = "29991231235959.000000"
                else:
                    item = Dataset()
                    item.RadiopharmaceuticalStartDateTime = "29991231235959.000000"
                    dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
            elif attack == "zero_positron_fraction":
                seq = getattr(dataset, "RadiopharmaceuticalInformationSequence", None)
                if seq and len(seq) > 0:
                    seq[0].RadionuclidePositronFraction = "0.0"
                else:
                    item = Dataset()
                    item.RadionuclidePositronFraction = "0.0"
                    dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
            elif attack == "remove_sequence":
                if "RadiopharmaceuticalInformationSequence" in dataset:
                    del dataset.RadiopharmaceuticalInformationSequence
        except Exception as e:
            logger.debug("Radiopharmaceutical decay attack failed: %s", e)

        return dataset

    def _temporal_parameter_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt DecayFactor / FrameReferenceTime / ActualFrameDuration timing data."""
        attack = random.choice(
            [
                "zero_decay_factor",
                "negative_frame_time",
                "duration_mismatch",
                "invalid_datetime",
                "remove_timing",
            ]
        )

        try:
            if attack == "zero_decay_factor":
                dataset.DecayFactor = "0.0"
            elif attack == "negative_frame_time":
                dataset.FrameReferenceTime = "-1000.0"
            elif attack == "duration_mismatch":
                dataset.ActualFrameDuration = "1"  # 1 ms
                dataset.NumberOfFrames = 999999
            elif attack == "invalid_datetime":
                dataset.DecayCorrectionDateTime = random.choice(
                    [
                        "",
                        "NOT_A_DATE",
                        "99999999999999.999999",
                        "A" * 5000,
                    ]
                )
            elif attack == "remove_timing":
                for tag in (
                    "DecayFactor",
                    "FrameReferenceTime",
                    "ActualFrameDuration",
                    "DecayCorrectionDateTime",
                ):
                    if tag in dataset:
                        del dataset[tag]
        except Exception as e:
            logger.debug("Temporal parameter corruption failed: %s", e)

        return dataset

    def _corrected_image_flag_attack(self, dataset: Dataset) -> Dataset:
        """Set invalid CorrectedImage (0028,0051) flag combinations."""
        attack = random.choice(
            [
                "contradictory_flags",
                "empty_flags",
                "invalid_flags",
                "missing_attenuation",
                "remove_corrected",
            ]
        )

        try:
            if attack == "contradictory_flags":
                dataset.CorrectedImage = ["ATTN", "DECAY", "SCAT", "RAN"]
                if "AttenuationCorrectionMethod" in dataset:
                    del dataset.AttenuationCorrectionMethod
            elif attack == "empty_flags":
                dataset.CorrectedImage = []
            elif attack == "invalid_flags":
                dataset.CorrectedImage = random.choice(
                    [
                        ["INVALID", "FAKE"],
                        ["A" * 5000],
                        ["ATTN\x00DECAY"],
                    ]
                )
            elif attack == "missing_attenuation":
                dataset.AttenuationCorrectionMethod = "CT"
                dataset.CorrectedImage = ["DECAY", "SCAT", "RAN"]  # no ATTN
            elif attack == "remove_corrected":
                if "CorrectedImage" in dataset:
                    del dataset.CorrectedImage
                if "AttenuationCorrectionMethod" in dataset:
                    del dataset.AttenuationCorrectionMethod
        except Exception as e:
            logger.debug("Corrected image flag attack failed: %s", e)

        return dataset


__all__ = ["PetFuzzer"]
