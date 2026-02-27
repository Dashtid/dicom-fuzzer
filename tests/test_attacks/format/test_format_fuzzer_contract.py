"""Cross-fuzzer contract tests for all format fuzzers.

Verifies that every FormatFuzzerBase subclass honors the interface contract:
- strategy_name is a non-empty string
- mutate() accepts a Dataset and returns a Dataset
- mutate() does not raise unhandled exceptions
- mutate() produces output different from a deep copy of the input
"""

import copy

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.attacks.format import (
    CalibrationFuzzer,
    CompressedPixelFuzzer,
    ConformanceFuzzer,
    DictionaryFuzzer,
    EncapsulatedPdfFuzzer,
    EncodingFuzzer,
    HeaderFuzzer,
    MetadataFuzzer,
    NuclearMedicineFuzzer,
    PetFuzzer,
    PixelFuzzer,
    PrivateTagFuzzer,
    ReferenceFuzzer,
    RTDoseFuzzer,
    RTStructureSetFuzzer,
    SegmentationFuzzer,
    SequenceFuzzer,
    StructureFuzzer,
)
from dicom_fuzzer.attacks.format.base import FormatFuzzerBase

# All format fuzzers, instantiated with default args
ALL_FUZZERS = [
    CalibrationFuzzer(),
    CompressedPixelFuzzer(),
    ConformanceFuzzer(),
    DictionaryFuzzer(),
    EncapsulatedPdfFuzzer(),
    EncodingFuzzer(),
    SegmentationFuzzer(),
    HeaderFuzzer(),
    MetadataFuzzer(),
    NuclearMedicineFuzzer(),
    PetFuzzer(),
    PixelFuzzer(),
    PrivateTagFuzzer(),
    RTDoseFuzzer(),
    RTStructureSetFuzzer(),
    ReferenceFuzzer(),
    SequenceFuzzer(),
    StructureFuzzer(),
]

FUZZER_IDS = [type(f).__name__ for f in ALL_FUZZERS]


@pytest.fixture
def rich_dataset() -> Dataset:
    """Dataset with file meta, pixel data, and common tags.

    Rich enough that every fuzzer has something to mutate.
    """
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Contract^Test"
    ds.PatientID = "CTR001"
    ds.PatientBirthDate = "19800101"
    ds.PatientSex = "O"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.Manufacturer = "ContractTest"
    ds.InstitutionName = "Test Hospital"
    ds.StudyDescription = "Contract Test Study"
    ds.SeriesNumber = 1
    ds.InstanceNumber = 1
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)
    ds.SliceThickness = 1.0
    ds.PixelSpacing = [0.5, 0.5]
    ds.RescaleIntercept = -1024.0
    ds.RescaleSlope = 1.0
    ds.WindowCenter = 40.0
    ds.WindowWidth = 400.0
    ds.SpecificCharacterSet = "ISO_IR 100"

    return ds


class TestFormatFuzzerContract:
    """Every format fuzzer must honor the FormatFuzzerBase contract."""

    @pytest.mark.parametrize("fuzzer", ALL_FUZZERS, ids=FUZZER_IDS)
    def test_is_format_fuzzer_subclass(self, fuzzer):
        """All fuzzers inherit from FormatFuzzerBase."""
        assert isinstance(fuzzer, FormatFuzzerBase)

    @pytest.mark.parametrize("fuzzer", ALL_FUZZERS, ids=FUZZER_IDS)
    def test_strategy_name_is_nonempty_string(self, fuzzer):
        """strategy_name must be a non-empty string."""
        name = fuzzer.strategy_name
        assert isinstance(name, str)
        assert len(name) > 0

    @pytest.mark.parametrize("fuzzer", ALL_FUZZERS, ids=FUZZER_IDS)
    def test_mutate_returns_dataset(self, fuzzer, rich_dataset):
        """mutate() must return a Dataset."""
        result = fuzzer.mutate(copy.deepcopy(rich_dataset))
        assert isinstance(result, Dataset)

    @pytest.mark.parametrize("fuzzer", ALL_FUZZERS, ids=FUZZER_IDS)
    def test_mutate_does_not_raise(self, fuzzer, rich_dataset):
        """mutate() must not raise unhandled exceptions."""
        # Run 5 times -- mutations are random, catch intermittent failures
        for _ in range(5):
            fuzzer.mutate(copy.deepcopy(rich_dataset))

    @pytest.mark.parametrize("fuzzer", ALL_FUZZERS, ids=FUZZER_IDS)
    def test_mutate_modifies_dataset(self, fuzzer, rich_dataset):
        """mutate() should produce output different from input.

        Run 10 attempts -- some strategies are random and may occasionally
        pick a no-op path, but at least one run should differ.
        """
        original = copy.deepcopy(rich_dataset)
        any_changed = False
        for _ in range(10):
            mutated = fuzzer.mutate(copy.deepcopy(rich_dataset))
            if mutated != original:
                any_changed = True
                break
        assert any_changed, (
            f"{type(fuzzer).__name__}.mutate() never modified the dataset"
        )

    @pytest.mark.parametrize("fuzzer", ALL_FUZZERS, ids=FUZZER_IDS)
    def test_mutate_handles_minimal_dataset(self, fuzzer):
        """mutate() must not crash on a near-empty dataset."""
        ds = Dataset()
        ds.PatientName = "Minimal^Test"
        ds.PatientID = "MIN001"
        # Should not raise
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)
