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
            except NotImplementedError:
                logger.debug("Strategy %s not yet implemented", strategy.__name__)
            except Exception as e:
                logger.debug("RT dose mutation failed: %s", e)

        return dataset

    def _dose_grid_scaling_attack(self, dataset: Dataset) -> Dataset:
        """Set DoseGridScaling to zero, negative, NaN, or extreme values."""
        raise NotImplementedError

    def _dvh_sequence_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt DVHSequence with malformed DVHData dose/volume arrays."""
        raise NotImplementedError

    def _grid_frame_offset_attack(self, dataset: Dataset) -> Dataset:
        """Create GridFrameOffsetVector length mismatches and non-monotonic values."""
        raise NotImplementedError

    def _dose_type_enumeration_attack(self, dataset: Dataset) -> Dataset:
        """Set DoseType and DoseSummationType to invalid enumeration values."""
        raise NotImplementedError

    def _referenced_rt_plan_corruption(self, dataset: Dataset) -> Dataset:
        """Corrupt ReferencedRTPlanSequence links to treatment plans."""
        raise NotImplementedError


__all__ = ["RTDoseFuzzer"]
