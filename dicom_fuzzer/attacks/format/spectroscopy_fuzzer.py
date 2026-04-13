"""Spectroscopy Fuzzer - DICOM MR Spectroscopy Data Mutations.

Category: structural

Targets MR Spectroscopy (MRS) DICOM objects by corrupting the spectral
data array size declarations, frequency axis parameters, and voxel
geometry metadata.

Attack surface rationale:
  MRS parsers reconstruct spectra by iterating over DataPointRows *
  DataPointColumns complex float pairs in SpectroscopyData. When the
  declared data point count does not match the actual SpectroscopyData
  byte length, or when TransmitterFrequency/SpectralWidth are zero or
  NaN, parsers that trust these fields are vulnerable to OOB reads,
  divide-by-zero, and NaN propagation through ppm axis calculations.

Dataset-level attacks:
- data_point_mismatch: DataPointRows * DataPointColumns >> actual SpectroscopyData bytes
- spectral_width_zero: SpectralWidth = 0 (divide-by-zero in ppm axis calculation)
- transmitter_freq_zero: TransmitterFrequency = 0 (divide-by-zero in chemical shift)
- chemical_shift_nan: ChemicalShiftReference sequence with NaN value
- no_spectroscopy_data: MRS SOPClassUID declared but SpectroscopyData absent
- odd_complex_count: SpectroscopyData length not a multiple of 8 (broken complex pairs)
- acquisition_matrix_zero: SpectroscopyAcquisitionPhaseRows = 0 (deref first row)
- echo_train_overflow: EchoTrainLength = 65535 (overflow in sequence planning)
- flip_angle_overflow: FlipAngle = 999.0 (out of 0..180 range)
- echo_time_negative: EchoTime = -1.0 (sign error in T2 decay calculation)
- repetition_time_zero: RepetitionTime = 0 (divide-by-zero in T1 recovery calculation)
- number_of_frames_mismatch: NumberOfFrames >> SpectroscopyData size
"""

from __future__ import annotations

import random
import struct

from pydicom.dataset import Dataset
from pydicom.sequence import Sequence

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# MR Spectroscopy SOP Class UID
_MRS_SOP_CLASS = "1.2.840.10008.5.1.4.1.1.4.2"

_MRS_SOP_CLASSES = frozenset(
    {
        "1.2.840.10008.5.1.4.1.1.4.2",  # MR Spectroscopy Storage
    }
)

# 4 complex float32 pairs (8 floats = 32 bytes) -- minimal spectroscopy data
_MINIMAL_SPECTROSCOPY_DATA = struct.pack("<8f", 1.0, 0.0, 2.0, 0.0, 3.0, 0.0, 4.0, 0.0)


def _build_minimal_mrs_dataset() -> Dataset:
    """Return a minimal well-formed MR Spectroscopy dataset."""
    ds = Dataset()
    ds.SOPClassUID = _MRS_SOP_CLASS
    ds.Modality = "MR"
    ds.Rows = 1
    ds.Columns = 1
    ds.DataPointRows = 1
    ds.DataPointColumns = 4  # 4 complex points
    ds.SpectralWidth = 2000.0  # Hz
    ds.TransmitterFrequency = 63.87  # MHz (1.5T proton)
    ds.EchoTime = 30.0  # ms
    ds.RepetitionTime = 2000.0  # ms
    ds.FlipAngle = 90.0
    ds.EchoTrainLength = 1
    ds.SpectroscopyAcquisitionPhaseRows = 1
    ds.SpectroscopyAcquisitionPhaseColumns = 1
    ds.SpectroscopyAcquisitionOutOfPlanePhaseSteps = 1
    ds.SpectroscopyData = _MINIMAL_SPECTROSCOPY_DATA

    # ChemicalShiftReference sequence (at least one item required)
    ref = Dataset()
    ref.NucleusResonanceFrequency = 63.87
    ref.ChemicalShiftReference = 4.7  # ppm (water reference)
    ds.ChemicalShiftSequence = Sequence([ref])
    return ds


class SpectroscopyFuzzer(FormatFuzzerBase):
    """Fuzzes DICOM MR Spectroscopy objects.

    Targets MRS parsers through spectral data array size mismatches,
    frequency axis divide-by-zero, NaN propagation, and voxel geometry
    violations.
    """

    def __init__(self) -> None:
        """Initialize MRS fuzzer."""
        super().__init__()

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "spectroscopy"

    def can_mutate(self, dataset: Dataset) -> bool:
        """Return True for MR Spectroscopy datasets."""
        sop_class = str(getattr(dataset, "SOPClassUID", ""))
        if sop_class in _MRS_SOP_CLASSES:
            return True
        return hasattr(dataset, "SpectroscopyData") or hasattr(dataset, "SpectralWidth")

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply MRS mutation.

        Args:
            dataset: DICOM dataset to mutate.

        Returns:
            Mutated dataset.

        """
        attacks = [
            self._data_point_mismatch,
            self._spectral_width_zero,
            self._transmitter_freq_zero,
            self._chemical_shift_nan,
            self._no_spectroscopy_data,
            self._odd_complex_count,
            self._acquisition_matrix_zero,
            self._echo_train_overflow,
            self._flip_angle_overflow,
            self._echo_time_negative,
            self._repetition_time_zero,
            self._number_of_frames_mismatch,
        ]

        attack = random.choice(attacks)
        try:
            attack(dataset)
            self.last_variant = attack.__name__.lstrip("_")
        except Exception:
            self.last_variant = "fallback"
            self._no_spectroscopy_data(dataset)

        return dataset

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _ensure_mrs_root(self, dataset: Dataset) -> None:
        """Ensure dataset has MRS SOPClassUID and minimal attributes."""
        if not getattr(dataset, "SOPClassUID", None):
            dataset.SOPClassUID = _MRS_SOP_CLASS
        if not hasattr(dataset, "DataPointRows"):
            dataset.DataPointRows = 1
            dataset.DataPointColumns = 4
        if not hasattr(dataset, "SpectroscopyData"):
            dataset.SpectroscopyData = _MINIMAL_SPECTROSCOPY_DATA
        if not hasattr(dataset, "SpectralWidth"):
            dataset.SpectralWidth = 2000.0
        if not hasattr(dataset, "TransmitterFrequency"):
            dataset.TransmitterFrequency = 63.87

    # ------------------------------------------------------------------
    # Attacks
    # ------------------------------------------------------------------

    def _data_point_mismatch(self, dataset: Dataset) -> None:
        """DataPointRows * DataPointColumns >> SpectroscopyData bytes (OOB read)."""
        self._ensure_mrs_root(dataset)
        # Declare 1024 * 1024 complex points; keep actual data tiny (32 bytes)
        dataset.DataPointRows = 1024
        dataset.DataPointColumns = 1024
        dataset.SpectroscopyData = _MINIMAL_SPECTROSCOPY_DATA  # far less than declared

    def _spectral_width_zero(self, dataset: Dataset) -> None:
        """SpectralWidth = 0 (divide-by-zero in Hz-to-ppm axis calculation)."""
        self._ensure_mrs_root(dataset)
        dataset.SpectralWidth = 0.0

    def _transmitter_freq_zero(self, dataset: Dataset) -> None:
        """TransmitterFrequency = 0 (divide-by-zero in chemical shift ppm calc)."""
        self._ensure_mrs_root(dataset)
        dataset.TransmitterFrequency = 0.0

    def _chemical_shift_nan(self, dataset: Dataset) -> None:
        """ChemicalShiftReference = NaN (NaN propagation in ppm scale)."""
        self._ensure_mrs_root(dataset)
        ref = Dataset()
        ref.NucleusResonanceFrequency = float("nan")
        ref.ChemicalShiftReference = float("nan")
        dataset.ChemicalShiftSequence = Sequence([ref])

    def _no_spectroscopy_data(self, dataset: Dataset) -> None:
        """MRS SOPClassUID declared but SpectroscopyData absent (NULL deref)."""
        dataset.SOPClassUID = _MRS_SOP_CLASS
        dataset.Modality = "MR"
        dataset.DataPointRows = 512
        dataset.DataPointColumns = 512
        dataset.SpectralWidth = 2000.0
        if hasattr(dataset, "SpectroscopyData"):
            del dataset.SpectroscopyData

    def _odd_complex_count(self, dataset: Dataset) -> None:
        """SpectroscopyData length not a multiple of 8 (broken complex float32 pairs)."""
        self._ensure_mrs_root(dataset)
        # 5 bytes: cannot be divided into 8-byte complex float pairs
        dataset.SpectroscopyData = b"\x00\x01\x02\x03\x04"

    def _acquisition_matrix_zero(self, dataset: Dataset) -> None:
        """SpectroscopyAcquisitionPhaseRows = 0 (deref first row without guard)."""
        self._ensure_mrs_root(dataset)
        dataset.SpectroscopyAcquisitionPhaseRows = 0
        dataset.SpectroscopyAcquisitionPhaseColumns = 0

    def _echo_train_overflow(self, dataset: Dataset) -> None:
        """EchoTrainLength = 65535 (overflow in sequence planning loop)."""
        self._ensure_mrs_root(dataset)
        dataset.EchoTrainLength = 65535

    def _flip_angle_overflow(self, dataset: Dataset) -> None:
        """FlipAngle = 999.0 (out of valid 0..180 range)."""
        self._ensure_mrs_root(dataset)
        dataset.FlipAngle = 999.0

    def _echo_time_negative(self, dataset: Dataset) -> None:
        """EchoTime = -1.0 (sign error in T2 decay calculation: e^(-TE/T2))."""
        self._ensure_mrs_root(dataset)
        dataset.EchoTime = -1.0

    def _repetition_time_zero(self, dataset: Dataset) -> None:
        """RepetitionTime = 0 (divide-by-zero in T1 recovery calculation)."""
        self._ensure_mrs_root(dataset)
        dataset.RepetitionTime = 0.0

    def _number_of_frames_mismatch(self, dataset: Dataset) -> None:
        """NumberOfFrames >> SpectroscopyData size (OOB in per-frame spectral iterator)."""
        self._ensure_mrs_root(dataset)
        dataset.NumberOfFrames = 0xFFFF  # 65535 declared spectral frames
        dataset.SpectroscopyData = _MINIMAL_SPECTROSCOPY_DATA  # 32 bytes only
