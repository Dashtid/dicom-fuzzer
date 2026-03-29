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

from ._radiopharmaceutical import radiopharmaceutical_attacks
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
        self.structural_strategies = [
            self._corrupt_radiopharmaceutical_sequence,  # [STRUCTURAL] empty/malformed RadiopharmaceuticalInformationSequence
        ]
        self.content_strategies = [
            self._suv_calibration_chain_attack,  # [CONTENT] calibration chain metadata values
            radiopharmaceutical_attacks,  # [CONTENT] radiopharmaceutical tag values
            self._temporal_parameter_corruption,  # [CONTENT] decay/timing parameter values
            self._corrected_image_flag_attack,  # [CONTENT] CorrectedImage flag combinations
        ]
        self.mutation_strategies = self.structural_strategies + self.content_strategies

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
        selected = list(
            self.structural_strategies
        )  # always run the 1 structural attack
        if random.random() < 0.33:
            selected.append(random.choice(self.content_strategies))
        self.last_variant = ",".join(s.__name__ for s in selected)

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
                "invalid_decay_correction",
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
            elif attack == "invalid_decay_correction":
                dataset.DecayCorrection = random.choice(
                    ["", "INVALID", "START\\ADMIN", "A" * 5000]
                )
        except Exception as e:
            logger.debug("SUV calibration chain attack failed: %s", e)

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

    def _corrupt_radiopharmaceutical_sequence(self, dataset: Dataset) -> Dataset:
        """Corrupt the RadiopharmaceuticalInformationSequence structure.

        Attacks the sequence's structural integrity rather than its values.
        An empty sequence where at least one item is required triggers
        null-pointer dereferences in viewers that index directly into the
        sequence. A count mismatch vs NumberOfRadionuclides causes
        off-by-one allocation in viewers that pre-allocate per radionuclide.
        """
        attack = random.choice(
            ["empty_sequence", "count_mismatch", "missing_sequence", "extra_nesting"]
        )

        try:
            if attack == "empty_sequence":
                # Parser expects >= 1 item; empty sequence causes index-0 crash
                dataset.RadiopharmaceuticalInformationSequence = Sequence([])

            elif attack == "count_mismatch":
                # 5 items but NumberOfRadionuclides says 1 — allocation mismatch
                items = [Dataset() for _ in range(5)]
                dataset.RadiopharmaceuticalInformationSequence = Sequence(items)
                dataset.NumberOfRadionuclides = 1

            elif attack == "missing_sequence":
                # Remove entirely — viewers that don't guard against absence crash
                if hasattr(dataset, "RadiopharmaceuticalInformationSequence"):
                    del dataset.RadiopharmaceuticalInformationSequence
                dataset.NumberOfRadionuclides = 3  # claims 3 but sequence absent

            elif attack == "extra_nesting":
                # Nest a sequence inside a sequence item where a flat value expected
                inner = Dataset()
                inner.RadiopharmaceuticalInformationSequence = Sequence([Dataset()])
                dataset.RadiopharmaceuticalInformationSequence = Sequence([inner])

        except Exception as e:
            logger.debug("Radiopharmaceutical sequence corruption failed: %s", e)

        return dataset


__all__ = ["PetFuzzer"]
