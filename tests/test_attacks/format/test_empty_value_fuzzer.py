"""Tests for EmptyValueFuzzer - Present-but-empty DICOM tag mutations."""

from __future__ import annotations

import io

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.filewriter import dcmwrite
from pydicom.sequence import Sequence
from pydicom.tag import Tag
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.attacks.format.empty_value_fuzzer import EmptyValueFuzzer


@pytest.fixture
def sample_dataset() -> Dataset:
    """Minimal Dataset with file meta, suitable for serialization roundtrip."""
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "Empty^Test"
    ds.PatientID = "EMP001"
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    # A known DS value for _comma_decimal_string to find:
    ds.SliceThickness = 5.0
    ds.PixelSpacing = [0.5, 0.5]
    return ds


class TestEmptyValueFuzzer:
    """Fuzzer initialization and contract surface."""

    def test_strategy_name(self):
        assert EmptyValueFuzzer().strategy_name == "empty_value"

    def test_can_mutate_returns_true_for_any_dataset(self):
        """EmptyValueFuzzer works on any dataset because it adds tags."""
        fuzzer = EmptyValueFuzzer()
        assert fuzzer.can_mutate(Dataset()) is True

    def test_initial_state(self):
        """Binary-mutation state starts cleared."""
        fuzzer = EmptyValueFuzzer()
        assert fuzzer._comma_target_tag is None
        assert fuzzer._applied_binary_mutations == []
        assert fuzzer.last_variant is None


# Per-attack tests: each verifies the target tag ends up present with
# the expected empty/zero value. Every attack maps to a fixed fo-dicom
# issue referenced in the docstring.


class TestEmptyPixelSpacing:
    """fo-dicom #2043 -- empty PixelSpacing."""

    def test_tag_present_and_empty(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer._empty_pixel_spacing(sample_dataset)
        assert Tag(0x0028, 0x0030) in result
        assert result[0x0028, 0x0030].VM == 0
        assert result[0x0028, 0x0030].value in ("", None, [])


class TestEmptyVoiLutFunction:
    """fo-dicom #1891 -- empty VOILUTFunction."""

    def test_tag_present_and_empty(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer._empty_voi_lut_function(sample_dataset)
        assert Tag(0x0028, 0x1056) in result
        assert result[0x0028, 0x1056].VM == 0


class TestEmptySpecificCharset:
    """fo-dicom #1879 -- empty SpecificCharacterSet."""

    def test_tag_present_and_empty(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer._empty_specific_charset(sample_dataset)
        assert Tag(0x0008, 0x0005) in result
        assert result[0x0008, 0x0005].VM == 0


class TestEmptyImagePosition:
    """fo-dicom #2067 -- empty ImagePositionPatient."""

    def test_tag_present_and_empty(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer._empty_image_position(sample_dataset)
        assert Tag(0x0020, 0x0032) in result
        assert result[0x0020, 0x0032].VM == 0


class TestEmptyImageOrientation:
    """fo-dicom #2067 -- empty ImageOrientationPatient."""

    def test_tag_present_and_empty(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer._empty_image_orientation(sample_dataset)
        assert Tag(0x0020, 0x0037) in result
        assert result[0x0020, 0x0037].VM == 0


class TestZeroWindowWidth:
    """fo-dicom #1905 -- zero / near-zero / negative WindowWidth."""

    def test_tag_present_with_zero_or_negative_value(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer._zero_window_width(sample_dataset)
        assert Tag(0x0028, 0x1051) in result
        # DS stored as float; "0", "0.001", or "-1" are all <= 0.001
        width = float(result[0x0028, 0x1051].value)
        assert width <= 0.001


class TestCommaDecimalString:
    """fo-dicom #1296 -- locale-specific DS parsing (binary-level patch)."""

    def test_sets_comma_target_tag(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        assert fuzzer._comma_target_tag is None
        fuzzer._comma_decimal_string(sample_dataset)
        assert fuzzer._comma_target_tag is not None
        # Target must be one of the three DS candidates
        assert fuzzer._comma_target_tag in (
            Tag(0x0018, 0x0050),
            Tag(0x0028, 0x0030),
            Tag(0x0020, 0x1041),
        )

    def test_mutate_bytes_substitutes_period_with_comma(self, sample_dataset):
        """Full mutate() -> serialize -> mutate_bytes() pipeline."""
        fuzzer = EmptyValueFuzzer()
        # Force the comma attack by calling it directly
        result = fuzzer._comma_decimal_string(sample_dataset)
        buf = io.BytesIO()
        dcmwrite(buf, result, enforce_file_format=False)
        raw = buf.getvalue()
        mutated = fuzzer.mutate_bytes(raw)
        assert len(mutated) == len(raw), "1:1 substitution must preserve length"
        assert fuzzer._applied_binary_mutations == ["_comma_decimal_string"]
        assert fuzzer._comma_target_tag is None, "target tag must be consumed"

    def test_mutate_bytes_is_noop_without_target(self, sample_dataset):
        """mutate_bytes() returns bytes unchanged when no comma target is pending."""
        fuzzer = EmptyValueFuzzer()
        buf = io.BytesIO()
        dcmwrite(buf, sample_dataset, enforce_file_format=False)
        raw = buf.getvalue()
        assert fuzzer.mutate_bytes(raw) == raw


class TestEmptySharedFunctionalGroup:
    """fo-dicom #1884 -- empty SharedFunctionalGroupsSequence."""

    def test_tag_present_and_empty_sequence(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer._empty_shared_functional_group(sample_dataset)
        assert Tag(0x5200, 0x9229) in result
        value = result[0x5200, 0x9229].value
        assert isinstance(value, Sequence)
        assert len(value) == 0


class TestEmptyWindowCenter:
    """Null deref in LUT pipeline -- empty WindowCenter."""

    def test_tag_present_and_empty(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer._empty_window_center(sample_dataset)
        assert Tag(0x0028, 0x1050) in result
        assert result[0x0028, 0x1050].VM == 0


# Full mutate() interface


class TestMutateInterface:
    """Interface conformance for the public mutate() entry point."""

    def test_mutate_returns_dataset(self, sample_dataset):
        fuzzer = EmptyValueFuzzer()
        result = fuzzer.mutate(sample_dataset)
        assert isinstance(result, pydicom.Dataset)

    def test_mutate_sets_last_variant(self, sample_dataset):
        """mutate() must record which sub-attacks ran for campaign telemetry."""
        fuzzer = EmptyValueFuzzer()
        # Run multiple times to avoid the rare case where every attack raises.
        variants_seen = set()
        for _ in range(20):
            fuzzer.mutate(Dataset())
            if fuzzer.last_variant:
                variants_seen.update(fuzzer.last_variant.split(","))
        assert len(variants_seen) >= 2, (
            "mutate() should exercise multiple distinct attacks over 20 runs"
        )

    def test_mutate_minimal_dataset_does_not_raise(self):
        """mutate() must not crash on a near-empty Dataset."""
        fuzzer = EmptyValueFuzzer()
        ds = Dataset()
        ds.PatientName = "Minimal^Test"
        result = fuzzer.mutate(ds)
        assert isinstance(result, Dataset)

    def test_mutate_then_serialize_roundtrip(self, sample_dataset):
        """mutate() output must survive pydicom serialization."""
        fuzzer = EmptyValueFuzzer()
        # Run 10x to cover random attack selection
        for _ in range(10):
            ds = Dataset()
            ds.file_meta = sample_dataset.file_meta
            ds.PatientName = "Roundtrip^Test"
            ds.PatientID = "RT001"
            ds.SOPInstanceUID = sample_dataset.SOPInstanceUID
            ds.SOPClassUID = sample_dataset.SOPClassUID
            ds.SliceThickness = 5.0
            ds.PixelSpacing = [0.5, 0.5]
            result = fuzzer.mutate(ds)
            buf = io.BytesIO()
            dcmwrite(buf, result, enforce_file_format=False)
            # Also run binary-level post-processing
            _ = fuzzer.mutate_bytes(buf.getvalue())
