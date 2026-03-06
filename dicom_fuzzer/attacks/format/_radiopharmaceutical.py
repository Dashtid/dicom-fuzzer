"""Shared radiopharmaceutical attacks for NM and PET fuzzers.

Provides a standalone function that corrupts
RadiopharmaceuticalInformationSequence fields shared across Nuclear
Medicine and PET modalities.  Each modality fuzzer delegates to this
helper as one of its mutation strategies.

Variants (11 unique):
- empty_isotope: blank Radiopharmaceutical name
- negative_volume_activity: negative volume and specific activity
- time_reversal: stop time before start time (TM tags)
- invalid_route: invalid RadiopharmaceuticalRoute enum
- remove_nuclide: delete RadionuclideCodeSequence
- zero_half_life: RadionuclideHalfLife = 0
- negative_total_dose: negative RadionuclideTotalDose
- future_start_time: RadiopharmaceuticalStartDateTime in year 2999
- zero_positron_fraction: RadionuclidePositronFraction = 0
- remove_sequence: delete entire RadiopharmaceuticalInformationSequence
- stop_before_start: RadiopharmaceuticalStopDateTime before start (DT tags)
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

_ATTACK_VARIANTS = [
    "empty_isotope",
    "negative_volume_activity",
    "time_reversal",
    "invalid_route",
    "remove_nuclide",
    "zero_half_life",
    "negative_total_dose",
    "future_start_time",
    "zero_positron_fraction",
    "remove_sequence",
    "stop_before_start",
]


def radiopharmaceutical_attacks(dataset: Dataset) -> Dataset:
    """Apply a random radiopharmaceutical corruption to *dataset*.

    Picks one of 11 attack variants that target
    RadiopharmaceuticalInformationSequence fields common to NM and PET.

    Args:
        dataset: The DICOM dataset to mutate.

    Returns:
        The mutated dataset.

    """
    attack = random.choice(_ATTACK_VARIANTS)

    try:
        if attack == "empty_isotope":
            item = Dataset()
            item.Radiopharmaceutical = ""
            item.RadiopharmaceuticalRoute = "IV"
            dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
        elif attack == "negative_volume_activity":
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
        elif attack == "zero_half_life":
            seq = getattr(dataset, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                seq[0].RadionuclideHalfLife = "0.0"
            else:
                item = Dataset()
                item.Radiopharmaceutical = "Tc-99m MIBI"
                item.RadionuclideHalfLife = "0.0"
                dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
        elif attack == "negative_total_dose":
            seq = getattr(dataset, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                seq[0].RadionuclideTotalDose = "-370000000.0"
            else:
                item = Dataset()
                item.Radiopharmaceutical = "Tc-99m MIBI"
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
        elif attack == "stop_before_start":
            seq = getattr(dataset, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                seq[0].RadiopharmaceuticalStartDateTime = "20240101120000.000000"
                seq[0].RadiopharmaceuticalStopDateTime = "20240101060000.000000"
            else:
                item = Dataset()
                item.RadiopharmaceuticalStartDateTime = "20240101120000.000000"
                item.RadiopharmaceuticalStopDateTime = "20240101060000.000000"
                dataset.RadiopharmaceuticalInformationSequence = Sequence([item])
    except Exception as e:
        logger.debug("Radiopharmaceutical attack failed: %s", e)

    return dataset


__all__ = ["radiopharmaceutical_attacks", "_ATTACK_VARIANTS"]
