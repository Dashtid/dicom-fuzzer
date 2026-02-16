"""Nuclear Medicine Fuzzer - DICOM NM Image Mutations.

Category: modality-specific (NM)

Targets Nuclear Medicine Image Storage (1.2.840.10008.5.1.4.1.1.20)
objects with mutations specific to energy window, detector, rotation,
and radiopharmaceutical structures.

Attack surfaces:
- EnergyWindowInformationSequence keV range corruption
- DetectorInformationSequence geometry mismatches
- RotationInformationSequence SPECT parameter inconsistencies
- RadiopharmaceuticalInformationSequence (shared with PET)
- NumberOfSlices / NumberOfTimeSlices vs frame count mismatches
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset

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
            except NotImplementedError:
                logger.debug("Strategy %s not yet implemented", strategy.__name__)
            except Exception as e:
                logger.debug("Nuclear medicine mutation failed: %s", e)

        return dataset

    def _energy_window_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt EnergyWindowInformationSequence keV ranges."""
        raise NotImplementedError

    def _detector_geometry_mismatch(self, dataset: Dataset) -> Dataset:
        """Create inconsistencies in DetectorInformationSequence fields."""
        raise NotImplementedError

    def _rotation_parameter_attack(self, dataset: Dataset) -> Dataset:
        """Corrupt RotationInformationSequence SPECT parameters."""
        raise NotImplementedError

    def _radiopharmaceutical_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt RadiopharmaceuticalInformationSequence isotope and dose data."""
        raise NotImplementedError

    def _slice_count_mismatch(self, dataset: Dataset) -> Dataset:
        """Create NumberOfSlices / NumberOfTimeSlices vs frame count mismatches."""
        raise NotImplementedError


__all__ = ["NuclearMedicineFuzzer"]
