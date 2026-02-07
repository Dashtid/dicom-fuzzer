"""Mutation verification tests for format fuzzer strategies.

Verifies that each strategy method actually produces the specific defect it
claims to -- not just "did it run" (contract tests) but "did it create a
dimension mismatch / invalid bit depth / corrupted pixel data / etc."

Tests call strategy methods directly (not via mutate()) and assert semantic
properties of the output.

Phase 1a: PixelFuzzer (6 strategies)
"""

import copy

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer


@pytest.fixture
def fuzzer() -> PixelFuzzer:
    """PixelFuzzer instance."""
    return PixelFuzzer()


@pytest.fixture
def pixel_dataset() -> Dataset:
    """Dataset with valid, self-consistent pixel data.

    Rows=64, Columns=64, 16-bit grayscale, all-zero pixels.
    Configured so pixel_array is decodable by pydicom.
    """
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    ds.PatientName = "Pixel^Test"
    ds.PatientID = "PIX001"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    return ds


# ---------------------------------------------------------------------------
# 1. _noise_injection
# ---------------------------------------------------------------------------
class TestNoiseInjection:
    """Verify _noise_injection modifies pixel data bytes."""

    def test_pixel_data_bytes_differ(self, fuzzer, pixel_dataset):
        """Injected noise must produce different pixel bytes."""
        original_pixels = pixel_dataset.PixelData
        any_changed = False
        for _ in range(20):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._noise_injection(ds)
            if result.PixelData != original_pixels:
                any_changed = True
                break
        assert any_changed, "_noise_injection never modified pixel data bytes"

    def test_pixel_data_length_preserved(self, fuzzer, pixel_dataset):
        """Noise injection must not change pixel data length."""
        ds = copy.deepcopy(pixel_dataset)
        original_length = len(ds.PixelData)
        result = fuzzer._noise_injection(ds)
        assert len(result.PixelData) == original_length

    def test_no_pixel_data_returns_unchanged(self, fuzzer):
        """Without PixelData, dataset returned unchanged."""
        ds = Dataset()
        ds.PatientName = "NoPixels"
        original = copy.deepcopy(ds)
        result = fuzzer._noise_injection(ds)
        assert result == original


# ---------------------------------------------------------------------------
# 2. _dimension_mismatch
# ---------------------------------------------------------------------------
class TestDimensionMismatch:
    """Verify _dimension_mismatch breaks Rows*Columns vs PixelData size."""

    def test_dimensions_no_longer_match_pixel_data(self, fuzzer, pixel_dataset):
        """Declared dimensions must not match actual pixel data size."""
        any_mismatched = False
        for _ in range(30):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._dimension_mismatch(ds)
            rows = getattr(result, "Rows", 0)
            cols = getattr(result, "Columns", 0)
            bytes_per_pixel = max(getattr(result, "BitsAllocated", 16) // 8, 1)
            spp = getattr(result, "SamplesPerPixel", 1)
            expected_size = rows * cols * bytes_per_pixel * spp
            actual_size = len(result.PixelData)
            if expected_size != actual_size:
                any_mismatched = True
                break
        assert any_mismatched, (
            "_dimension_mismatch never created a dimension/pixel-data size mismatch"
        )

    def test_pixel_data_not_modified(self, fuzzer, pixel_dataset):
        """Dimension mismatch changes dimensions, not pixel data."""
        ds = copy.deepcopy(pixel_dataset)
        original_pixels = ds.PixelData
        result = fuzzer._dimension_mismatch(ds)
        assert result.PixelData == original_pixels

    def test_no_pixel_data_returns_unchanged(self, fuzzer):
        """Without PixelData, dataset returned unchanged."""
        ds = Dataset()
        ds.Rows = 64
        ds.Columns = 64
        original = copy.deepcopy(ds)
        result = fuzzer._dimension_mismatch(ds)
        assert result == original

    def test_multiple_attack_paths(self, fuzzer, pixel_dataset):
        """Multiple dimension attack variants should be exercised."""
        seen = set()
        for _ in range(200):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._dimension_mismatch(ds)
            r, c = result.Rows, result.Columns
            if r == 0:
                seen.add("rows_zero")
            elif c == 0:
                seen.add("columns_zero")
            elif r > 64 and c > 64:
                seen.add("both_larger")
            elif r > 64:
                seen.add("rows_larger")
            elif c > 64:
                seen.add("columns_larger")
            elif r > 60000 or c > 60000:
                seen.add("extreme")
        assert len(seen) >= 3, f"Only {len(seen)} attack paths hit: {seen}"


# ---------------------------------------------------------------------------
# 3. _bit_depth_attack
# ---------------------------------------------------------------------------
class TestBitDepthAttack:
    """Verify _bit_depth_attack creates invalid bit depth relationships."""

    def test_bit_depth_invariant_violated(self, fuzzer, pixel_dataset):
        """At least one DICOM bit depth rule must be broken."""
        # Valid state: BitsAllocated=16, BitsStored=12, HighBit=11
        any_violated = False
        for _ in range(30):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._bit_depth_attack(ds)
            ba = result.BitsAllocated
            bs = result.BitsStored
            hb = result.HighBit
            # Original valid state: ba=16, bs=12, hb=11
            violated = (
                bs > ba
                or hb != bs - 1
                or ba == 0
                or bs == 0
                or ba not in (8, 16, 32)
                or (ba != 16 or bs != 12 or hb != 11)
            )
            if violated:
                any_violated = True
                break
        assert any_violated, "_bit_depth_attack never violated bit depth rules"

    def test_multiple_attack_paths(self, fuzzer, pixel_dataset):
        """Multiple bit depth attack variants should be exercised."""
        seen = set()
        for _ in range(200):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._bit_depth_attack(ds)
            ba = result.BitsAllocated
            bs = result.BitsStored
            hb = result.HighBit
            if bs > ba:
                seen.add("bits_stored_greater")
            if hb > 20:
                seen.add("high_bit_invalid")
            if ba != 16 and bs == 12:
                seen.add("bits_allocated_mismatch")
            if ba == 0:
                seen.add("zero_bits")
            if ba in (1, 64, 128, 255):
                seen.add("extreme_bits")
        assert len(seen) >= 3, f"Only {len(seen)} attack paths hit: {seen}"


# ---------------------------------------------------------------------------
# 4. _photometric_confusion
# ---------------------------------------------------------------------------
class TestPhotometricConfusion:
    """Verify _photometric_confusion changes PhotometricInterpretation."""

    def test_photometric_changed(self, fuzzer, pixel_dataset):
        """PhotometricInterpretation must differ from original."""
        original = pixel_dataset.PhotometricInterpretation
        any_changed = False
        for _ in range(10):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._photometric_confusion(ds)
            if result.PhotometricInterpretation != original:
                any_changed = True
                break
        assert any_changed, (
            "_photometric_confusion never changed PhotometricInterpretation"
        )

    def test_value_is_invalid_or_mismatched(self, fuzzer, pixel_dataset):
        """New value should be invalid or mismatched for grayscale data."""
        valid_for_mono = {"MONOCHROME1", "MONOCHROME2"}
        any_invalid = False
        for _ in range(20):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._photometric_confusion(ds)
            if result.PhotometricInterpretation not in valid_for_mono:
                any_invalid = True
                break
        assert any_invalid, (
            "_photometric_confusion never produced invalid photometric for grayscale"
        )


# ---------------------------------------------------------------------------
# 5. _samples_per_pixel_attack
# ---------------------------------------------------------------------------
class TestSamplesPerPixelAttack:
    """Verify _samples_per_pixel_attack creates SamplesPerPixel inconsistency."""

    def test_samples_per_pixel_changed(self, fuzzer, pixel_dataset):
        """SamplesPerPixel must differ from original (1)."""
        any_changed = False
        for _ in range(10):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._samples_per_pixel_attack(ds)
            if result.SamplesPerPixel != 1:
                any_changed = True
                break
        assert any_changed, "_samples_per_pixel_attack never changed SamplesPerPixel"

    def test_samples_inconsistent_with_pixel_data(self, fuzzer, pixel_dataset):
        """SamplesPerPixel * dimensions should not match pixel data size."""
        original_size = len(pixel_dataset.PixelData)
        rows = pixel_dataset.Rows
        cols = pixel_dataset.Columns
        bytes_pp = pixel_dataset.BitsAllocated // 8
        any_inconsistent = False
        for _ in range(20):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._samples_per_pixel_attack(ds)
            expected = rows * cols * bytes_pp * result.SamplesPerPixel
            if expected != original_size:
                any_inconsistent = True
                break
        assert any_inconsistent, (
            "_samples_per_pixel_attack never made SamplesPerPixel "
            "inconsistent with pixel data size"
        )

    def test_produces_invalid_values(self, fuzzer, pixel_dataset):
        """Should produce values outside the valid set {1, 3, 4}."""
        valid = {1, 3, 4}
        any_invalid = False
        for _ in range(50):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._samples_per_pixel_attack(ds)
            if result.SamplesPerPixel not in valid:
                any_invalid = True
                break
        assert any_invalid, (
            "_samples_per_pixel_attack never produced invalid SamplesPerPixel"
        )


# ---------------------------------------------------------------------------
# 6. _planar_configuration_attack
# ---------------------------------------------------------------------------
class TestPlanarConfigurationAttack:
    """Verify _planar_configuration_attack sets PlanarConfiguration incorrectly."""

    def test_planar_config_set(self, fuzzer, pixel_dataset):
        """PlanarConfiguration must be added or changed."""
        any_set = False
        for _ in range(10):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._planar_configuration_attack(ds)
            if hasattr(result, "PlanarConfiguration"):
                any_set = True
                break
        assert any_set, "_planar_configuration_attack never set PlanarConfiguration"

    def test_planar_config_on_grayscale(self, fuzzer, pixel_dataset):
        """Should set PlanarConfiguration when SamplesPerPixel=1 (invalid)."""
        any_on_grayscale = False
        for _ in range(20):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._planar_configuration_attack(ds)
            spp = getattr(result, "SamplesPerPixel", 1)
            pc = getattr(result, "PlanarConfiguration", None)
            if spp == 1 and pc is not None:
                any_on_grayscale = True
                break
        assert any_on_grayscale, (
            "_planar_configuration_attack never set PlanarConfiguration "
            "on grayscale image"
        )

    def test_invalid_planar_values(self, fuzzer, pixel_dataset):
        """Should produce PlanarConfiguration values other than 0 or 1."""
        any_invalid = False
        for _ in range(50):
            ds = copy.deepcopy(pixel_dataset)
            result = fuzzer._planar_configuration_attack(ds)
            pc = getattr(result, "PlanarConfiguration", None)
            if pc is not None and pc not in (0, 1):
                any_invalid = True
                break
        assert any_invalid, (
            "_planar_configuration_attack never produced invalid "
            "PlanarConfiguration value"
        )
