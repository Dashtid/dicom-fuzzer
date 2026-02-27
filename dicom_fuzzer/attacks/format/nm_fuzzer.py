"""Nuclear Medicine Fuzzer - DICOM NM Image Mutations.

Category: modality-specific (NM)

Attacks:
- Energy window keV range corruption
- Detector geometry mismatches
- SPECT rotation parameter inconsistencies
- Radiopharmaceutical data corruption
- Slice/time slice count vs frame count mismatches
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

_NM_SOP_CLASS_UID = "1.2.840.10008.5.1.4.1.1.20"


class NuclearMedicineFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM Nuclear Medicine objects to test NM-specific handling.

    NM images have domain-specific sequences (energy windows, detectors,
    rotation parameters) that generic fuzzers never touch because they
    don't exist in CT seed files.
    """

    def __init__(self) -> None:
        """Initialize the nuclear medicine fuzzer with attack strategies."""
        super().__init__()
        self.mutation_strategies = [
            self._energy_window_corruption,
            self._detector_geometry_mismatch,
            self._rotation_parameter_attack,
            self._radiopharmaceutical_corruption,
            self._slice_count_mismatch,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "nuclear_medicine"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Only mutate Nuclear Medicine Image Storage datasets."""
        sop_class = getattr(dataset, "SOPClassUID", None)
        return str(sop_class) == _NM_SOP_CLASS_UID

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply nuclear medicine mutations to the dataset.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with NM-specific corruptions

        """
        num_strategies = random.randint(1, 2)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("Nuclear medicine mutation failed: %s", e)

        return dataset

    def _energy_window_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt EnergyWindowInformationSequence keV ranges."""
        attack = random.choice(
            [
                "inverted_range",
                "zero_width",
                "negative_kev",
                "count_mismatch",
                "empty_sequence",
            ]
        )

        try:
            if attack == "inverted_range":
                item = Dataset()
                item.EnergyWindowLowerLimit = "200.0"
                item.EnergyWindowUpperLimit = "100.0"  # lower > upper
                item.EnergyWindowName = "Inverted"
                dataset.EnergyWindowInformationSequence = Sequence([item])
                dataset.NumberOfEnergyWindows = 1
            elif attack == "zero_width":
                item = Dataset()
                item.EnergyWindowLowerLimit = "140.0"
                item.EnergyWindowUpperLimit = "140.0"  # zero width
                item.EnergyWindowName = "ZeroWidth"
                dataset.EnergyWindowInformationSequence = Sequence([item])
                dataset.NumberOfEnergyWindows = 1
            elif attack == "negative_kev":
                item = Dataset()
                item.EnergyWindowLowerLimit = "-50.0"
                item.EnergyWindowUpperLimit = "-10.0"
                item.EnergyWindowName = "Negative"
                dataset.EnergyWindowInformationSequence = Sequence([item])
                dataset.NumberOfEnergyWindows = 1
            elif attack == "count_mismatch":
                item = Dataset()
                item.EnergyWindowLowerLimit = "126.0"
                item.EnergyWindowUpperLimit = "154.0"
                dataset.EnergyWindowInformationSequence = Sequence([item])
                dataset.NumberOfEnergyWindows = 5  # says 5, only 1 item
            elif attack == "empty_sequence":
                dataset.EnergyWindowInformationSequence = Sequence([])
                dataset.NumberOfEnergyWindows = 0
        except Exception as e:
            logger.debug("Energy window corruption failed: %s", e)

        return dataset

    def _detector_geometry_mismatch(self, dataset: Dataset) -> Dataset:
        """Create inconsistencies in DetectorInformationSequence fields."""
        attack = random.choice(
            [
                "count_mismatch",
                "duplicate_vectors",
                "invalid_type",
                "zero_size",
                "remove_sequence",
            ]
        )

        try:
            if attack == "count_mismatch":
                item = Dataset()
                item.DetectorVector = 1
                dataset.DetectorInformationSequence = Sequence([item])
                dataset.NumberOfDetectors = 4  # says 4, only 1 item
            elif attack == "duplicate_vectors":
                item1 = Dataset()
                item1.DetectorVector = 1
                item2 = Dataset()
                item2.DetectorVector = 1  # duplicate
                dataset.DetectorInformationSequence = Sequence([item1, item2])
                dataset.NumberOfDetectors = 2
            elif attack == "invalid_type":
                item = Dataset()
                item.DetectorVector = 1
                item.DetectorType = random.choice(
                    [
                        "",
                        "INVALID",
                        "SCINTILLATION\x00SOLID STATE",
                        "A" * 5000,
                    ]
                )
                dataset.DetectorInformationSequence = Sequence([item])
                dataset.NumberOfDetectors = 1
            elif attack == "zero_size":
                item = Dataset()
                item.DetectorVector = 1
                item.DetectorElementSize = [0.0, 0.0]
                dataset.DetectorInformationSequence = Sequence([item])
                dataset.NumberOfDetectors = 1
            elif attack == "remove_sequence":
                if "DetectorInformationSequence" in dataset:
                    del dataset.DetectorInformationSequence
                if "NumberOfDetectors" in dataset:
                    del dataset.NumberOfDetectors
        except Exception as e:
            logger.debug("Detector geometry mismatch failed: %s", e)

        return dataset

    def _rotation_parameter_attack(self, dataset: Dataset) -> Dataset:
        """Corrupt RotationInformationSequence SPECT parameters."""
        attack = random.choice(
            [
                "impossible_angle",
                "zero_step",
                "frame_count_mismatch",
                "invalid_motion",
                "remove_sequence",
            ]
        )

        try:
            if attack == "impossible_angle":
                item = Dataset()
                item.StartAngle = "720.0"  # > 360
                item.AngularStep = "6.0"
                item.TypeOfDetectorMotion = "STEP"
                item.NumberOfFramesInRotation = 60
                dataset.RotationInformationSequence = Sequence([item])
            elif attack == "zero_step":
                item = Dataset()
                item.StartAngle = "0.0"
                item.AngularStep = "0.0"  # zero step -> infinite loop potential
                item.TypeOfDetectorMotion = "STEP"
                item.NumberOfFramesInRotation = 60
                dataset.RotationInformationSequence = Sequence([item])
            elif attack == "frame_count_mismatch":
                item = Dataset()
                item.StartAngle = "0.0"
                item.AngularStep = "6.0"
                item.TypeOfDetectorMotion = "STEP"
                item.NumberOfFramesInRotation = 999  # vs NumberOfFrames
                dataset.RotationInformationSequence = Sequence([item])
                dataset.NumberOfFrames = 60
            elif attack == "invalid_motion":
                item = Dataset()
                item.StartAngle = "0.0"
                item.AngularStep = "6.0"
                item.TypeOfDetectorMotion = random.choice(
                    [
                        "",
                        "INVALID",
                        "STEP\x00CONTINUOUS",
                        "A" * 5000,
                    ]
                )
                item.NumberOfFramesInRotation = 60
                dataset.RotationInformationSequence = Sequence([item])
            elif attack == "remove_sequence":
                if "RotationInformationSequence" in dataset:
                    del dataset.RotationInformationSequence
        except Exception as e:
            logger.debug("Rotation parameter attack failed: %s", e)

        return dataset

    def _radiopharmaceutical_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt RadiopharmaceuticalInformationSequence isotope and dose data."""
        attack = random.choice(
            [
                "empty_isotope",
                "negative_dose",
                "time_reversal",
                "invalid_route",
                "remove_nuclide",
            ]
        )

        try:
            if attack == "empty_isotope":
                item = Dataset()
                item.Radiopharmaceutical = ""
                item.RadiopharmaceuticalRoute = "IV"
                dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
            elif attack == "negative_dose":
                item = Dataset()
                item.Radiopharmaceutical = "Tc-99m MIBI"
                item.RadiopharmaceuticalVolume = "-5.0"
                item.RadiopharmaceuticalSpecificActivity = "-100.0"
                item.RadiopharmaceuticalRoute = "IV"
                dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
            elif attack == "time_reversal":
                item = Dataset()
                item.Radiopharmaceutical = "Tc-99m MIBI"
                item.RadiopharmaceuticalStartTime = "150000.000"
                item.RadiopharmaceuticalStopTime = "100000.000"  # stop < start
                item.RadiopharmaceuticalRoute = "IV"
                dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
            elif attack == "invalid_route":
                item = Dataset()
                item.Radiopharmaceutical = "Tc-99m MIBI"
                item.RadiopharmaceuticalRoute = random.choice(
                    [
                        "",
                        "INVALID_ROUTE",
                        "IV\x00ORAL",
                        "A" * 5000,
                    ]
                )
                dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
            elif attack == "remove_nuclide":
                seq = getattr(dataset, "RadiopharmaceuticalInformationSequence", None)
                if seq and len(seq) > 0:
                    if "RadionuclideCodeSequence" in seq[0]:
                        del seq[0].RadionuclideCodeSequence
                else:
                    item = Dataset()
                    item.Radiopharmaceutical = "Tc-99m MIBI"
                    dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
        except Exception as e:
            logger.debug("Radiopharmaceutical corruption failed: %s", e)

        return dataset

    def _slice_count_mismatch(self, dataset: Dataset) -> Dataset:
        """Create NumberOfSlices / NumberOfTimeSlices vs frame count mismatches."""
        attack = random.choice(
            [
                "slice_frame_mismatch",
                "time_slice_mismatch",
                "zero_slices",
                "impossible_ratio",
                "remove_counts",
            ]
        )

        try:
            if attack == "slice_frame_mismatch":
                dataset.NumberOfSlices = 999
                dataset.NumberOfFrames = 60
            elif attack == "time_slice_mismatch":
                dataset.NumberOfTimeSlices = 999
                dataset.NumberOfFrames = 60
            elif attack == "zero_slices":
                dataset.NumberOfSlices = 0
                dataset.NumberOfTimeSlices = 0
                dataset.NumberOfFrames = 60
            elif attack == "impossible_ratio":
                dataset.NumberOfSlices = 100
                dataset.NumberOfTimeSlices = 100
                dataset.NumberOfFrames = 5  # 100*100 != 5
            elif attack == "remove_counts":
                for tag in (
                    "NumberOfSlices",
                    "NumberOfTimeSlices",
                    "NumberOfFrames",
                ):
                    if tag in dataset:
                        del dataset[tag]
        except Exception as e:
            logger.debug("Slice count mismatch failed: %s", e)

        return dataset


__all__ = ["NuclearMedicineFuzzer"]
