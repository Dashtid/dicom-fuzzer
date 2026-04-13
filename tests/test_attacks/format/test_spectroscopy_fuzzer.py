"""Tests for SpectroscopyFuzzer.

Verifies all 12 MR Spectroscopy attack sub-strategies plus can_mutate()
and DicomMutator registration.
"""

import math

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.spectroscopy_fuzzer import SpectroscopyFuzzer

_MRS_SOP = "1.2.840.10008.5.1.4.1.1.4.2"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mrs_dataset() -> Dataset:
    """Return a minimal well-formed MR Spectroscopy dataset."""
    from dicom_fuzzer.attacks.format.spectroscopy_fuzzer import (
        _MINIMAL_SPECTROSCOPY_DATA,
    )

    ds = Dataset()
    ds.SOPClassUID = _MRS_SOP
    ds.Modality = "MR"
    ds.Rows = 1
    ds.Columns = 1
    ds.DataPointRows = 1
    ds.DataPointColumns = 4
    ds.SpectralWidth = 2000.0
    ds.TransmitterFrequency = 63.87
    ds.EchoTime = 30.0
    ds.RepetitionTime = 2000.0
    ds.FlipAngle = 90.0
    ds.EchoTrainLength = 1
    ds.SpectroscopyAcquisitionPhaseRows = 1
    ds.SpectroscopyAcquisitionPhaseColumns = 1
    ds.SpectroscopyData = _MINIMAL_SPECTROSCOPY_DATA

    ref = Dataset()
    ref.NucleusResonanceFrequency = 63.87
    ref.ChemicalShiftReference = 4.7
    ds.ChemicalShiftSequence = Sequence([ref])
    return ds


def _bare_dataset() -> Dataset:
    ds = Dataset()
    ds.PatientName = "FUZZER^TEST"
    return ds


# ---------------------------------------------------------------------------
# can_mutate()
# ---------------------------------------------------------------------------


class TestCanMutate:
    @pytest.fixture
    def fuzzer(self) -> SpectroscopyFuzzer:
        return SpectroscopyFuzzer()

    def test_true_for_mrs_sop_class(self, fuzzer: SpectroscopyFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _MRS_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_spectroscopy_data(
        self, fuzzer: SpectroscopyFuzzer
    ) -> None:
        ds = Dataset()
        ds.SpectroscopyData = b"\x00" * 32
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_spectral_width(
        self, fuzzer: SpectroscopyFuzzer
    ) -> None:
        ds = Dataset()
        ds.SpectralWidth = 2000.0
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_dataset(self, fuzzer: SpectroscopyFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: SpectroscopyFuzzer) -> None:
        assert fuzzer.can_mutate(Dataset()) is False


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


def test_strategy_name() -> None:
    assert SpectroscopyFuzzer().strategy_name == "spectroscopy"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    @pytest.fixture
    def fuzzer(self) -> SpectroscopyFuzzer:
        return SpectroscopyFuzzer()

    def test_returns_dataset(self, fuzzer: SpectroscopyFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_mrs_dataset()), Dataset)

    def test_sets_last_variant(self, fuzzer: SpectroscopyFuzzer) -> None:
        fuzzer.mutate(_mrs_dataset())
        assert isinstance(fuzzer.last_variant, str)

    def test_bare_dataset_does_not_raise(self, fuzzer: SpectroscopyFuzzer) -> None:
        assert isinstance(fuzzer.mutate(_bare_dataset()), Dataset)

    def test_multiple_variants_covered(self, fuzzer: SpectroscopyFuzzer) -> None:
        variants = set()
        for _ in range(48):
            fuzzer.mutate(_mrs_dataset())
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 4


# ---------------------------------------------------------------------------
# Individual attacks
# ---------------------------------------------------------------------------


class TestDataPointMismatch:
    def test_data_points_declared_much_larger_than_data(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._data_point_mismatch(ds)
        # 1024*1024 complex pairs * 8 bytes each >> 32 bytes actual
        declared_bytes = ds.DataPointRows * ds.DataPointColumns * 8
        assert len(ds.SpectroscopyData) < declared_bytes


class TestSpectralWidthZero:
    def test_spectral_width_zero(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._spectral_width_zero(ds)
        assert ds.SpectralWidth == 0.0


class TestTransmitterFreqZero:
    def test_transmitter_freq_zero(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._transmitter_freq_zero(ds)
        assert ds.TransmitterFrequency == 0.0


class TestChemicalShiftNan:
    def test_chemical_shift_reference_is_nan(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._chemical_shift_nan(ds)
        ref = ds.ChemicalShiftSequence[0]
        assert math.isnan(ref.ChemicalShiftReference)
        assert math.isnan(ref.NucleusResonanceFrequency)


class TestNoSpectroscopyData:
    def test_spectroscopy_data_removed(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._no_spectroscopy_data(ds)
        assert not hasattr(ds, "SpectroscopyData")

    def test_sop_class_is_mrs(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _bare_dataset()
        fuzzer._no_spectroscopy_data(ds)
        assert str(ds.SOPClassUID) == _MRS_SOP

    def test_large_data_point_dimensions_declared(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _bare_dataset()
        fuzzer._no_spectroscopy_data(ds)
        assert ds.DataPointRows == 512
        assert ds.DataPointColumns == 512


class TestOddComplexCount:
    def test_spectroscopy_data_not_multiple_of_eight(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._odd_complex_count(ds)
        assert len(ds.SpectroscopyData) % 8 != 0


class TestAcquisitionMatrixZero:
    def test_acquisition_phase_rows_zero(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._acquisition_matrix_zero(ds)
        assert ds.SpectroscopyAcquisitionPhaseRows == 0
        assert ds.SpectroscopyAcquisitionPhaseColumns == 0


class TestEchoTrainOverflow:
    def test_echo_train_length_max(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._echo_train_overflow(ds)
        assert ds.EchoTrainLength == 65535


class TestFlipAngleOverflow:
    def test_flip_angle_out_of_range(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._flip_angle_overflow(ds)
        assert ds.FlipAngle > 360


class TestEchoTimeNegative:
    def test_echo_time_negative(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._echo_time_negative(ds)
        assert ds.EchoTime < 0


class TestRepetitionTimeZero:
    def test_repetition_time_zero(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._repetition_time_zero(ds)
        assert ds.RepetitionTime == 0.0


class TestNumberOfFramesMismatch:
    def test_number_of_frames_large(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._number_of_frames_mismatch(ds)
        assert ds.NumberOfFrames == 0xFFFF

    def test_spectroscopy_data_far_shorter_than_frames(self) -> None:
        fuzzer = SpectroscopyFuzzer()
        ds = _mrs_dataset()
        fuzzer._number_of_frames_mismatch(ds)
        # 65535 frames with any spectral data >> 32 bytes
        assert len(ds.SpectroscopyData) < ds.NumberOfFrames * 8


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_spectroscopy_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        names = [s.strategy_name for s in DicomMutator().strategies]
        assert "spectroscopy" in names

    def test_strategy_count_includes_spectroscopy(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        assert len(DicomMutator().strategies) >= 39
