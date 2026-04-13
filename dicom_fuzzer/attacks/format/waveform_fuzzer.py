"""Waveform Fuzzer - DICOM Waveform/ECG Data Mutations.

Category: structural

Targets waveform DICOM objects (12-lead ECG, ambulatory ECG, hemodynamic
waveforms) with attacks on the channel/sample count arithmetic and the
WaveformData buffer boundary.

Attack surface rationale:
  PACS viewers render waveform objects by iterating over channels and
  samples. When NumberOfWaveformChannels * NumberOfWaveformSamples
  overflows int32, or when WaveformData is shorter than the declared
  channel * sample * bytes count, parsers read past the buffer.

Dataset-level attacks:
- channel_count_zero: NumberOfWaveformChannels = 0 (NULL deref on channel info)
- channel_count_overflow: channels * samples > INT32_MAX (allocation overflow)
- sample_count_max: NumberOfWaveformSamples = 0xFFFFFFFF (uint32 max)
- data_truncated: WaveformData shorter than declared size by 1 byte
- bits_invalid: WaveformBitsAllocated outside {8, 16} (32 or 255)
- sampling_freq_zero: SamplingFrequency = 0 (divide-by-zero in timeline calc)
- sampling_freq_negative: SamplingFrequency = -1 (sign error in timeline)
- channel_sensitivity_nan: ChannelSensitivity = "NaN" (float parse -> NaN)
- channel_sensitivity_inf: ChannelSensitivity = "Inf" (float parse -> Inf)
- waveform_data_null: WaveformData all-zeros with mismatched byte count
- no_waveform_sequence: remove WaveformSequence entirely (NULL deref guard)
- empty_waveform_sequence: WaveformSequence with zero items
- channel_definition_missing: WaveformSequence item with no ChannelDefinitionSequence
- channel_definition_empty: ChannelDefinitionSequence with zero channel items
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Waveform SOP Class UIDs (for can_mutate check)
_WAVEFORM_SOP_CLASSES = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.9.1.1",  # 12-lead ECG
        "1.2.840.10008.5.1.4.1.1.9.1.2",  # General ECG
        "1.2.840.10008.5.1.4.1.1.9.1.3",  # Ambulatory ECG
        "1.2.840.10008.5.1.4.1.1.9.2.1",  # Hemodynamic Waveform
        "1.2.840.10008.5.1.4.1.1.9.3.1",  # Cardiac Electrophysiology
        "1.2.840.10008.5.1.4.1.1.9.4.1",  # Basic Voice Audio
    }
)


def _build_minimal_waveform_item(
    n_channels: int = 12,
    n_samples: int = 5000,
    bits: int = 16,
    data: bytes | None = None,
) -> Dataset:
    """Build a minimal WaveformSequence item (PS3.3 C.10.9)."""
    item = Dataset()
    item.NumberOfWaveformChannels = n_channels
    item.NumberOfWaveformSamples = n_samples
    item.SamplingFrequency = "500"
    item.WaveformBitsAllocated = bits

    bytes_per_sample = bits // 8
    expected_bytes = n_channels * n_samples * bytes_per_sample
    if data is None:
        data = b"\x00" * min(expected_bytes, 4096)  # cap at 4K for tests
    item.WaveformData = data

    # Minimal ChannelDefinitionSequence (1 channel descriptor per channel)
    ch_defs = []
    for _ in range(min(n_channels, 3)):  # 3 channels enough for structure
        ch = Dataset()
        ch.ChannelSensitivity = "1.0"
        ch.ChannelSensitivityUnitsSequence = Sequence([])
        ch_defs.append(ch)
    item.ChannelDefinitionSequence = Sequence(ch_defs)

    return item


class WaveformFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM waveform/ECG objects.

    Targets channel count/sample count arithmetic, WaveformData
    buffer boundaries, and SamplingFrequency parsing.

    Focuses on 12-lead ECG and other waveform SOP classes; can_mutate()
    returns True for any dataset with a WaveformSequence tag.
    """

    def __init__(self) -> None:
        """Initialize waveform fuzzer."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "waveform"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True if dataset has waveform data or is a waveform SOP class."""
        has_waveform_seq = hasattr(dataset, "WaveformSequence")
        sop_class = str(getattr(dataset, "SOPClassUID", ""))
        return has_waveform_seq or sop_class in _WAVEFORM_SOP_CLASSES

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply waveform mutation to the dataset.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        attacks = [
            self._channel_count_zero,
            self._channel_count_overflow,
            self._sample_count_max,
            self._data_truncated,
            self._bits_invalid,
            self._sampling_freq_zero,
            self._sampling_freq_negative,
            self._channel_sensitivity_nan,
            self._channel_sensitivity_inf,
            self._waveform_data_null,
            self._no_waveform_sequence,
            self._empty_waveform_sequence,
            self._channel_definition_missing,
            self._channel_definition_empty,
        ]

        attack = random.choice(attacks)
        try:
            attack(dataset)
            self.last_variant = attack.__name__.lstrip("_")
        except Exception:
            self.last_variant = "fallback"
            self._no_waveform_sequence(dataset)

        return dataset

    # ------------------------------------------------------------------
    # Private attack helpers
    # ------------------------------------------------------------------

    def _ensure_waveform_seq(self, dataset: Dataset) -> None:
        """Ensure dataset has a WaveformSequence with at least one item."""
        if not hasattr(dataset, "WaveformSequence") or not dataset.WaveformSequence:
            dataset.WaveformSequence = Sequence([_build_minimal_waveform_item()])

    def _channel_count_zero(self, dataset: Dataset) -> None:
        """Set NumberOfWaveformChannels = 0 (NULL deref on channel info lookup)."""
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        item.NumberOfWaveformChannels = 0
        item.WaveformData = b""

    def _channel_count_overflow(self, dataset: Dataset) -> None:
        """Set channels * samples > 2^31 (allocation math overflow).

        channels=65535, samples=65536 -> 65535*65536*2 = ~8.5GB declared.
        Parser allocates declared size -> integer overflow or OOM.
        """
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        item.NumberOfWaveformChannels = 65535
        item.NumberOfWaveformSamples = 65536
        item.WaveformBitsAllocated = 16
        item.WaveformData = b"\x00" * 4  # Far less than declared 8.5GB

    def _sample_count_max(self, dataset: Dataset) -> None:
        """Set NumberOfWaveformSamples = 0xFFFFFF (uint32 max-ish).

        Forces length calculation: channels * max_samples * bytes -> overflow.
        """
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        item.NumberOfWaveformChannels = 12
        item.NumberOfWaveformSamples = 0xFFFFFF  # ~16M samples
        item.WaveformBitsAllocated = 16
        item.WaveformData = b"\x00" * 24  # 2 bytes per sample * 12 channels * 1 sample

    def _data_truncated(self, dataset: Dataset) -> None:
        """WaveformData 1 byte shorter than declared channel*sample*bytes.

        Causes OOB read on last sample of last channel.
        """
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        n_channels = 12
        n_samples = 500
        bits = 16
        expected = n_channels * n_samples * (bits // 8)
        item.NumberOfWaveformChannels = n_channels
        item.NumberOfWaveformSamples = n_samples
        item.WaveformBitsAllocated = bits
        item.WaveformData = b"\x00" * (expected - 1)  # 1 byte short

    def _bits_invalid(self, dataset: Dataset) -> None:
        """WaveformBitsAllocated outside {8, 16} -> decode fallback or crash."""
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        item.WaveformBitsAllocated = random.choice([0, 4, 32, 64, 255])
        item.WaveformData = b"\x00" * 24

    def _sampling_freq_zero(self, dataset: Dataset) -> None:
        """SamplingFrequency = 0 (divide-by-zero in waveform timeline calculation)."""
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        item.SamplingFrequency = "0"

    def _sampling_freq_negative(self, dataset: Dataset) -> None:
        """SamplingFrequency = -1 (sign error in duration calculation)."""
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        item.SamplingFrequency = "-1"

    def _channel_sensitivity_nan(self, dataset: Dataset) -> None:
        """ChannelSensitivity = 'NaN' (float parse returns NaN, propagates to render)."""
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        if (
            hasattr(item, "ChannelDefinitionSequence")
            and item.ChannelDefinitionSequence
        ):
            for ch in item.ChannelDefinitionSequence:
                ch.ChannelSensitivity = "NaN"
        else:
            ch = Dataset()
            ch.ChannelSensitivity = "NaN"
            item.ChannelDefinitionSequence = Sequence([ch])

    def _channel_sensitivity_inf(self, dataset: Dataset) -> None:
        """ChannelSensitivity = 'Inf' (infinity propagates through render pipeline)."""
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        if (
            hasattr(item, "ChannelDefinitionSequence")
            and item.ChannelDefinitionSequence
        ):
            for ch in item.ChannelDefinitionSequence:
                ch.ChannelSensitivity = "Inf"
        else:
            ch = Dataset()
            ch.ChannelSensitivity = "Inf"
            item.ChannelDefinitionSequence = Sequence([ch])

    def _waveform_data_null(self, dataset: Dataset) -> None:
        """WaveformData all-zeros with channel*sample mismatch (OOB read at boundary)."""
        self._ensure_waveform_seq(dataset)
        item = dataset.WaveformSequence[0]
        item.NumberOfWaveformChannels = 12
        item.NumberOfWaveformSamples = 5000
        item.WaveformBitsAllocated = 16
        # All-zeros but 100x shorter than declared -> OOB at decode
        item.WaveformData = b"\x00" * 24

    def _no_waveform_sequence(self, dataset: Dataset) -> None:
        """Remove WaveformSequence entirely (NULL deref if parser doesn't guard)."""
        if hasattr(dataset, "WaveformSequence"):
            del dataset.WaveformSequence
        # Also strip SOPClassUID so parsers don't skip non-waveform objects
        dataset.SOPClassUID = "1.2.840.10008.5.1.4.1.1.9.1.1"

    def _empty_waveform_sequence(self, dataset: Dataset) -> None:
        """WaveformSequence with zero items (parser assumes at least 1)."""
        dataset.WaveformSequence = Sequence([])

    def _channel_definition_missing(self, dataset: Dataset) -> None:
        """WaveformSequence item with no ChannelDefinitionSequence tag."""
        item = _build_minimal_waveform_item()
        if hasattr(item, "ChannelDefinitionSequence"):
            del item.ChannelDefinitionSequence
        dataset.WaveformSequence = Sequence([item])

    def _channel_definition_empty(self, dataset: Dataset) -> None:
        """ChannelDefinitionSequence with zero channel items.

        NumberOfWaveformChannels=12 but ChannelDefinitionSequence has 0 items ->
        index-out-of-bounds when parser looks up channel[i].
        """
        item = _build_minimal_waveform_item(n_channels=12)
        item.ChannelDefinitionSequence = Sequence([])
        dataset.WaveformSequence = Sequence([item])
