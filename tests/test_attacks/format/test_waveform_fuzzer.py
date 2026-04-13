"""Tests for WaveformFuzzer.

Verifies all 14 waveform attack sub-strategies plus can_mutate() and
DicomMutator registration.
"""

import pytest
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.attacks.format.waveform_fuzzer import WaveformFuzzer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WAVEFORM_SOP = "1.2.840.10008.5.1.4.1.1.9.1.1"  # 12-lead ECG


def _waveform_dataset() -> Dataset:
    """Return a minimal dataset with a well-formed WaveformSequence."""
    ds = Dataset()
    ds.SOPClassUID = _WAVEFORM_SOP
    ds.file_meta = Dataset()
    ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.1"

    item = Dataset()
    item.NumberOfWaveformChannels = 12
    item.NumberOfWaveformSamples = 500
    item.SamplingFrequency = "500"
    item.WaveformBitsAllocated = 16
    n_bytes = 12 * 500 * 2
    item.WaveformData = b"\x00" * n_bytes

    ch = Dataset()
    ch.ChannelSensitivity = "1.0"
    ch.ChannelSensitivityUnitsSequence = Sequence([])
    item.ChannelDefinitionSequence = Sequence([ch])

    ds.WaveformSequence = Sequence([item])
    return ds


def _bare_dataset() -> Dataset:
    """Return a dataset with no waveform tags (should gain them via mutate)."""
    ds = Dataset()
    ds.PatientName = "FUZZER^TEST"
    return ds


# ---------------------------------------------------------------------------
# can_mutate()
# ---------------------------------------------------------------------------


class TestCanMutate:
    """Tests for WaveformFuzzer.can_mutate()."""

    @pytest.fixture
    def fuzzer(self) -> WaveformFuzzer:
        return WaveformFuzzer()

    def test_true_for_waveform_sop_class(self, fuzzer: WaveformFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = _WAVEFORM_SOP
        assert fuzzer.can_mutate(ds) is True

    def test_true_for_dataset_with_waveform_sequence(
        self, fuzzer: WaveformFuzzer
    ) -> None:
        ds = Dataset()
        ds.WaveformSequence = Sequence([])
        assert fuzzer.can_mutate(ds) is True

    def test_false_for_ct_dataset_without_waveform(
        self, fuzzer: WaveformFuzzer
    ) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
        assert fuzzer.can_mutate(ds) is False

    def test_false_for_empty_dataset(self, fuzzer: WaveformFuzzer) -> None:
        ds = Dataset()
        assert fuzzer.can_mutate(ds) is False

    def test_true_for_hemodynamic_waveform(self, fuzzer: WaveformFuzzer) -> None:
        ds = Dataset()
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.9.2.1"
        assert fuzzer.can_mutate(ds) is True


# ---------------------------------------------------------------------------
# strategy_name
# ---------------------------------------------------------------------------


class TestStrategyName:
    def test_strategy_name(self) -> None:
        assert WaveformFuzzer().strategy_name == "waveform"


# ---------------------------------------------------------------------------
# mutate() -- general
# ---------------------------------------------------------------------------


class TestMutateGeneral:
    """General mutate() tests."""

    @pytest.fixture
    def fuzzer(self) -> WaveformFuzzer:
        return WaveformFuzzer()

    def test_returns_dataset(self, fuzzer: WaveformFuzzer) -> None:
        ds = _waveform_dataset()
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)

    def test_sets_last_variant(self, fuzzer: WaveformFuzzer) -> None:
        ds = _waveform_dataset()
        fuzzer.mutate(ds)
        assert fuzzer.last_variant is not None
        assert isinstance(fuzzer.last_variant, str)

    def test_mutate_bare_dataset_does_not_raise(self, fuzzer: WaveformFuzzer) -> None:
        """Attacks must handle datasets with no prior waveform data."""
        ds = _bare_dataset()
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)

    def test_repeated_mutations_cover_multiple_variants(
        self, fuzzer: WaveformFuzzer
    ) -> None:
        """Run 40 mutations; should see at least 3 distinct variants."""
        variants = set()
        for _ in range(40):
            ds = _waveform_dataset()
            fuzzer.mutate(ds)
            variants.add(fuzzer.last_variant)
        assert len(variants) >= 3


# ---------------------------------------------------------------------------
# Individual attack sub-strategies
# ---------------------------------------------------------------------------


class TestChannelCountZero:
    def test_sets_channel_count_zero(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._channel_count_zero(ds)
        assert ds.WaveformSequence[0].NumberOfWaveformChannels == 0

    def test_waveform_data_empty(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._channel_count_zero(ds)
        assert ds.WaveformSequence[0].WaveformData == b""


class TestChannelCountOverflow:
    def test_sets_overflow_values(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._channel_count_overflow(ds)
        item = ds.WaveformSequence[0]
        assert item.NumberOfWaveformChannels == 65535
        assert item.NumberOfWaveformSamples == 65536

    def test_waveform_data_far_smaller_than_declared(self) -> None:
        """WaveformData is 4 bytes while channels*samples*2 would be ~8.5GB."""
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._channel_count_overflow(ds)
        item = ds.WaveformSequence[0]
        declared = item.NumberOfWaveformChannels * item.NumberOfWaveformSamples * 2
        assert len(item.WaveformData) < declared


class TestSampleCountMax:
    def test_sets_max_sample_count(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._sample_count_max(ds)
        assert ds.WaveformSequence[0].NumberOfWaveformSamples == 0xFFFFFF


class TestDataTruncated:
    def test_data_one_byte_short(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._data_truncated(ds)
        item = ds.WaveformSequence[0]
        declared = item.NumberOfWaveformChannels * item.NumberOfWaveformSamples * 2
        assert len(item.WaveformData) == declared - 1


class TestBitsInvalid:
    def test_bits_allocated_outside_standard(self) -> None:
        fuzzer = WaveformFuzzer()
        valid_bits = {8, 16}
        for _ in range(20):
            ds = _waveform_dataset()
            fuzzer._bits_invalid(ds)
            assert ds.WaveformSequence[0].WaveformBitsAllocated not in valid_bits


class TestSamplingFreqZero:
    def test_sampling_freq_zero(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._sampling_freq_zero(ds)
        assert ds.WaveformSequence[0].SamplingFrequency == "0"


class TestSamplingFreqNegative:
    def test_sampling_freq_negative(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._sampling_freq_negative(ds)
        assert ds.WaveformSequence[0].SamplingFrequency == "-1"


class TestChannelSensitivityNan:
    def test_sets_nan_sensitivity(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._channel_sensitivity_nan(ds)
        item = ds.WaveformSequence[0]
        assert hasattr(item, "ChannelDefinitionSequence")
        for ch in item.ChannelDefinitionSequence:
            assert ch.ChannelSensitivity == "NaN"

    def test_creates_channel_definition_if_missing(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        del ds.WaveformSequence[0].ChannelDefinitionSequence
        fuzzer._channel_sensitivity_nan(ds)
        item = ds.WaveformSequence[0]
        assert hasattr(item, "ChannelDefinitionSequence")
        assert item.ChannelDefinitionSequence[0].ChannelSensitivity == "NaN"


class TestChannelSensitivityInf:
    def test_sets_inf_sensitivity(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._channel_sensitivity_inf(ds)
        item = ds.WaveformSequence[0]
        for ch in item.ChannelDefinitionSequence:
            assert ch.ChannelSensitivity == "Inf"


class TestWaveformDataNull:
    def test_data_null_with_mismatch(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._waveform_data_null(ds)
        item = ds.WaveformSequence[0]
        declared = item.NumberOfWaveformChannels * item.NumberOfWaveformSamples * 2
        assert len(item.WaveformData) < declared
        assert item.WaveformData == b"\x00" * 24


class TestNoWaveformSequence:
    def test_removes_waveform_sequence(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        assert hasattr(ds, "WaveformSequence")
        fuzzer._no_waveform_sequence(ds)
        assert not hasattr(ds, "WaveformSequence")

    def test_sets_waveform_sop_class(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._no_waveform_sequence(ds)
        assert ds.SOPClassUID == _WAVEFORM_SOP

    def test_works_on_dataset_without_waveform_seq(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _bare_dataset()
        fuzzer._no_waveform_sequence(ds)  # should not raise


class TestEmptyWaveformSequence:
    def test_sequence_has_zero_items(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._empty_waveform_sequence(ds)
        assert len(ds.WaveformSequence) == 0


class TestChannelDefinitionMissing:
    def test_no_channel_definition_in_item(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._channel_definition_missing(ds)
        item = ds.WaveformSequence[0]
        assert not hasattr(item, "ChannelDefinitionSequence")


class TestChannelDefinitionEmpty:
    def test_channel_definition_empty_with_declared_channels(self) -> None:
        fuzzer = WaveformFuzzer()
        ds = _waveform_dataset()
        fuzzer._channel_definition_empty(ds)
        item = ds.WaveformSequence[0]
        assert item.NumberOfWaveformChannels == 12
        assert len(item.ChannelDefinitionSequence) == 0


# ---------------------------------------------------------------------------
# DicomMutator registration
# ---------------------------------------------------------------------------


class TestDicomMutatorRegistration:
    def test_waveform_strategy_registered(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        mutator = DicomMutator()
        names = [s.strategy_name for s in mutator.strategies]
        assert "waveform" in names

    def test_strategy_count_includes_waveform(self) -> None:
        from dicom_fuzzer.core.mutation.mutator import DicomMutator

        mutator = DicomMutator()
        names = [s.strategy_name for s in mutator.strategies]
        # At least the known count (33 before this addition)
        assert len(names) >= 34
