"""Tests for PetFuzzer -- PET-specific DICOM mutations.

Covers all 4 attack strategies:
- SUV calibration chain corruption
- Radiopharmaceutical decay parameter manipulation
- Temporal parameter corruption
- CorrectedImage flag combinations
"""

from __future__ import annotations

import copy
import random

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.pet_fuzzer import _PET_SOP_CLASS_UID, PetFuzzer


@pytest.fixture
def fuzzer() -> PetFuzzer:
    return PetFuzzer()


@pytest.fixture
def pet_dataset() -> Dataset:
    """Realistic PET dataset with SUV calibration chain."""
    ds = Dataset()
    ds.SOPClassUID = _PET_SOP_CLASS_UID
    ds.Modality = "PT"

    # SUV calibration chain
    ds.Units = "BQML"
    ds.DecayCorrection = "START"
    ds.SUVType = "BW"
    ds.PatientWeight = "70.0"
    ds.PatientSize = "1.75"

    # Radiopharmaceutical sequence (F-18 FDG)
    pharma_item = Dataset()
    pharma_item.Radiopharmaceutical = "Fluorodeoxyglucose F^18^"
    pharma_item.RadionuclideHalfLife = "6586.2"
    pharma_item.RadionuclideTotalDose = "370000000.0"
    pharma_item.RadionuclidePositronFraction = "0.9686"
    pharma_item.RadiopharmaceuticalStartDateTime = "20240101080000.000000"
    pharma_item.RadiopharmaceuticalStopDateTime = "20240101080100.000000"
    ds.RadiopharmaceuticalInformationSequence = Sequence([pharma_item])

    # Temporal parameters
    ds.DecayFactor = "1.0"
    ds.FrameReferenceTime = "0.0"
    ds.ActualFrameDuration = "180000"
    ds.DecayCorrectionDateTime = "20240101090000.000000"

    # Corrected image flags
    ds.CorrectedImage = ["ATTN", "DECAY", "SCAT", "RAN"]
    ds.AttenuationCorrectionMethod = "CT"

    ds.NumberOfFrames = 1

    return ds


class TestCanMutate:
    def test_accepts_pet_sop(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        assert fuzzer.can_mutate(pet_dataset) is True

    def test_rejects_ct_sop(self, fuzzer: PetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_rejects_missing_sop(self, fuzzer: PetFuzzer) -> None:
        ds = Dataset()
        assert fuzzer.can_mutate(ds) is False


class TestSuvCalibrationChainAttack:
    def test_invalid_units(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._suv_calibration_chain_attack(ds)
            units = getattr(result, "Units", None)
            if units is not None and str(units) != "BQML":
                return
        pytest.fail("invalid_units attack never triggered")

    def test_missing_weight(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._suv_calibration_chain_attack(ds)
            if not hasattr(result, "PatientWeight"):
                return
        pytest.fail("missing_weight attack never triggered")

    def test_zero_weight(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._suv_calibration_chain_attack(ds)
            weight = getattr(result, "PatientWeight", None)
            if weight is not None and float(weight) <= 0.0:
                return
        pytest.fail("zero_weight attack never triggered")

    def test_conflicting_suv_type(
        self, fuzzer: PetFuzzer, pet_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._suv_calibration_chain_attack(ds)
            units = getattr(result, "Units", None)
            suv_type = getattr(result, "SUVType", None)
            if (
                units is not None
                and str(units) == "CNTS"
                and suv_type is not None
                and str(suv_type) == "BW"
            ):
                return
        pytest.fail("conflicting_suv_type attack never triggered")

    def test_remove_units(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._suv_calibration_chain_attack(ds)
            if "Units" not in result:
                return
        pytest.fail("remove_units attack never triggered")

    def test_handles_missing_tags(self, fuzzer: PetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _PET_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._suv_calibration_chain_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestRadiopharmaceuticalDecayAttack:
    def test_zero_half_life(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._radiopharmaceutical_decay_attack(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                hl = getattr(seq[0], "RadionuclideHalfLife", None)
                if hl is not None and float(hl) == 0.0:
                    return
        pytest.fail("zero_half_life attack never triggered")

    def test_negative_dose(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._radiopharmaceutical_decay_attack(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                dose = getattr(seq[0], "RadionuclideTotalDose", None)
                if dose is not None and float(dose) < 0:
                    return
        pytest.fail("negative_dose attack never triggered")

    def test_future_start_time(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._radiopharmaceutical_decay_attack(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                dt = getattr(seq[0], "RadiopharmaceuticalStartDateTime", None)
                if dt is not None and str(dt).startswith("2999"):
                    return
        pytest.fail("future_start_time attack never triggered")

    def test_zero_positron_fraction(
        self, fuzzer: PetFuzzer, pet_dataset: Dataset
    ) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._radiopharmaceutical_decay_attack(ds)
            seq = getattr(result, "RadiopharmaceuticalInformationSequence", None)
            if seq and len(seq) > 0:
                pf = getattr(seq[0], "RadionuclidePositronFraction", None)
                if pf is not None and float(pf) == 0.0:
                    return
        pytest.fail("zero_positron_fraction attack never triggered")

    def test_remove_sequence(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._radiopharmaceutical_decay_attack(ds)
            if "RadiopharmaceuticalInformationSequence" not in result:
                return
        pytest.fail("remove_sequence attack never triggered")

    def test_handles_missing_sequence(self, fuzzer: PetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _PET_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._radiopharmaceutical_decay_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestTemporalParameterCorruption:
    def test_zero_decay_factor(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._temporal_parameter_corruption(ds)
            df = getattr(result, "DecayFactor", None)
            if df is not None and float(df) == 0.0:
                return
        pytest.fail("zero_decay_factor attack never triggered")

    def test_negative_frame_time(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._temporal_parameter_corruption(ds)
            ft = getattr(result, "FrameReferenceTime", None)
            if ft is not None and float(ft) < 0:
                return
        pytest.fail("negative_frame_time attack never triggered")

    def test_duration_mismatch(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._temporal_parameter_corruption(ds)
            duration = getattr(result, "ActualFrameDuration", None)
            frames = getattr(result, "NumberOfFrames", None)
            if (
                duration is not None
                and frames is not None
                and int(duration) == 1
                and int(frames) == 999999
            ):
                return
        pytest.fail("duration_mismatch attack never triggered")

    def test_invalid_datetime(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._temporal_parameter_corruption(ds)
            dt = getattr(result, "DecayCorrectionDateTime", None)
            if dt is not None and str(dt) != "20240101090000.000000":
                return
        pytest.fail("invalid_datetime attack never triggered")

    def test_remove_timing(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._temporal_parameter_corruption(ds)
            if "DecayFactor" not in result:
                return
        pytest.fail("remove_timing attack never triggered")

    def test_handles_missing_tags(self, fuzzer: PetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _PET_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._temporal_parameter_corruption(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestCorrectedImageFlagAttack:
    def test_contradictory_flags(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._corrected_image_flag_attack(ds)
            ci = getattr(result, "CorrectedImage", None)
            if ci is not None and "ATTN" in ci:
                if "AttenuationCorrectionMethod" not in result:
                    return
        pytest.fail("contradictory_flags attack never triggered")

    def test_empty_flags(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._corrected_image_flag_attack(ds)
            ci = getattr(result, "CorrectedImage", None)
            if ci is not None and len(ci) == 0:
                return
        pytest.fail("empty_flags attack never triggered")

    def test_invalid_flags(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._corrected_image_flag_attack(ds)
            ci = getattr(result, "CorrectedImage", None)
            if ci is not None and len(ci) > 0:
                first = str(ci[0]) if hasattr(ci, "__getitem__") else str(ci)
                if first not in ("ATTN", "DECAY", "SCAT", "RAN", "NORM"):
                    return
        pytest.fail("invalid_flags attack never triggered")

    def test_missing_attenuation(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._corrected_image_flag_attack(ds)
            ci = getattr(result, "CorrectedImage", None)
            acm = getattr(result, "AttenuationCorrectionMethod", None)
            if ci is not None and acm is not None:
                ci_list = list(ci) if hasattr(ci, "__iter__") else [str(ci)]
                if "ATTN" not in ci_list and str(acm) == "CT":
                    return
        pytest.fail("missing_attenuation attack never triggered")

    def test_remove_corrected(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for i in range(50):
            random.seed(i)
            ds = copy.deepcopy(pet_dataset)
            result = fuzzer._corrected_image_flag_attack(ds)
            if "CorrectedImage" not in result:
                return
        pytest.fail("remove_corrected attack never triggered")

    def test_handles_missing_tags(self, fuzzer: PetFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _PET_SOP_CLASS_UID
        for i in range(20):
            random.seed(i)
            result = fuzzer._corrected_image_flag_attack(copy.deepcopy(ds))
            assert isinstance(result, Dataset)


class TestMutateIntegration:
    def test_returns_dataset(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        result = fuzzer.mutate(copy.deepcopy(pet_dataset))
        assert isinstance(result, Dataset)

    def test_does_not_raise(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        for _ in range(10):
            fuzzer.mutate(copy.deepcopy(pet_dataset))

    def test_modifies_dataset(self, fuzzer: PetFuzzer, pet_dataset: Dataset) -> None:
        original = copy.deepcopy(pet_dataset)
        for _ in range(10):
            result = fuzzer.mutate(copy.deepcopy(pet_dataset))
            if result != original:
                return
        pytest.fail("mutate() never modified the dataset")

    def test_handles_empty_dataset(self, fuzzer: PetFuzzer) -> None:
        ds = Dataset()
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)
