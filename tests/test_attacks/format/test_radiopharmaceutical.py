"""Tests for shared radiopharmaceutical_attacks helper."""

from __future__ import annotations

import copy
import random

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format._radiopharmaceutical import (
    _ATTACK_VARIANTS,
    radiopharmaceutical_attacks,
)


@pytest.fixture
def pharma_dataset() -> Dataset:
    """Dataset with a populated RadiopharmaceuticalInformationSequence."""
    ds = Dataset()
    rp = Dataset()
    rp.Radiopharmaceutical = "Tc-99m MIBI"
    rp.RadiopharmaceuticalRoute = "IV"
    rp.RadiopharmaceuticalVolume = "5.0"
    rp.RadiopharmaceuticalSpecificActivity = "740.0"
    rp.RadiopharmaceuticalStartTime = "100000.000"
    rp.RadiopharmaceuticalStopTime = "100030.000"
    rp.RadiopharmaceuticalStartDateTime = "20240101080000.000000"
    rp.RadiopharmaceuticalStopDateTime = "20240101080100.000000"
    rp.RadionuclideHalfLife = "6586.2"
    rp.RadionuclideTotalDose = "370000000.0"
    rp.RadionuclidePositronFraction = "0.9686"
    nuclide = Dataset()
    nuclide.CodeValue = "C-163A8"
    nuclide.CodingSchemeDesignator = "SRT"
    nuclide.CodeMeaning = "Tc-99m"
    rp.RadionuclideCodeSequence = Sequence([nuclide])
    ds.RadiopharmaceuticalInformationSequence = Sequence([rp])
    return ds


# ---------------------------------------------------------------------------
# Individual variant coverage
# ---------------------------------------------------------------------------


class TestEmptyIsotope:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                name = getattr(seq[0], "Radiopharmaceutical", None)
                if name == "":
                    return
        pytest.fail("empty_isotope attack never triggered")


class TestNegativeVolumeActivity:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                vol = getattr(seq[0], "RadiopharmaceuticalVolume", None)
                if vol and float(vol) < 0:
                    return
        pytest.fail("negative_volume_activity attack never triggered")


class TestTimeReversal:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                start = getattr(seq[0], "RadiopharmaceuticalStartTime", None)
                stop = getattr(seq[0], "RadiopharmaceuticalStopTime", None)
                if start and stop and str(stop) < str(start):
                    return
        pytest.fail("time_reversal attack never triggered")


class TestInvalidRoute:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        valid_routes = {"IV", "ORAL", "INHALATION"}
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                route = getattr(seq[0], "RadiopharmaceuticalRoute", None)
                if route is not None and route not in valid_routes:
                    return
        pytest.fail("invalid_route attack never triggered")


class TestRemoveNuclide:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                if not hasattr(seq[0], "RadionuclideCodeSequence"):
                    return
        pytest.fail("remove_nuclide attack never triggered")


class TestZeroHalfLife:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                hl = getattr(seq[0], "RadionuclideHalfLife", None)
                if hl is not None and float(hl) == 0.0:
                    return
        pytest.fail("zero_half_life attack never triggered")


class TestNegativeTotalDose:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                dose = getattr(seq[0], "RadionuclideTotalDose", None)
                if dose is not None and float(dose) < 0:
                    return
        pytest.fail("negative_total_dose attack never triggered")


class TestFutureStartTime:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                dt = getattr(seq[0], "RadiopharmaceuticalStartDateTime", None)
                if dt is not None and str(dt).startswith("2999"):
                    return
        pytest.fail("future_start_time attack never triggered")


class TestZeroPositronFraction:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                pf = getattr(seq[0], "RadionuclidePositronFraction", None)
                if pf is not None and float(pf) == 0.0:
                    return
        pytest.fail("zero_positron_fraction attack never triggered")


class TestRemoveSequence:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            if "RadiopharmaceuticalInformationSequence" not in result:
                return
        pytest.fail("remove_sequence attack never triggered")


class TestStopBeforeStart:
    def test_triggers(self, pharma_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            result = radiopharmaceutical_attacks(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                start = getattr(seq[0], "RadiopharmaceuticalStartDateTime", None)
                stop = getattr(seq[0], "RadiopharmaceuticalStopDateTime", None)
                if start is not None and stop is not None and str(stop) < str(start):
                    return
        pytest.fail("stop_before_start attack never triggered")


# ---------------------------------------------------------------------------
# General properties
# ---------------------------------------------------------------------------


class TestRadiopharmaceuticalAttacksGeneral:
    def test_returns_dataset(self, pharma_dataset: Dataset) -> None:
        result = radiopharmaceutical_attacks(copy.deepcopy(pharma_dataset))
        assert isinstance(result, Dataset)

    def test_does_not_raise(self, pharma_dataset: Dataset) -> None:
        for i in range(30):
            random.seed(i)
            radiopharmaceutical_attacks(copy.deepcopy(pharma_dataset))

    def test_handles_empty_dataset(self) -> None:
        ds = Dataset()
        for i in range(30):
            random.seed(i)
            result = radiopharmaceutical_attacks(copy.deepcopy(ds))
            assert isinstance(result, Dataset)

    def test_all_variants_listed(self) -> None:
        assert len(_ATTACK_VARIANTS) == 11

    def test_modifies_dataset(self, pharma_dataset: Dataset) -> None:
        modified = False
        for i in range(30):
            random.seed(i)
            ds = copy.deepcopy(pharma_dataset)
            original = copy.deepcopy(ds)
            result = radiopharmaceutical_attacks(ds)
            if result != original:
                modified = True
                break
        assert modified, "radiopharmaceutical_attacks() never modified the dataset"
