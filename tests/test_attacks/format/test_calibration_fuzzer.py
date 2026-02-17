"""Tests for CalibrationFuzzer - Measurement and Calibration Fuzzing."""

import math

import pydicom
import pytest

from dicom_fuzzer.attacks.format.calibration_fuzzer import CalibrationFuzzer


class TestCalibrationFuzzer:
    """Test CalibrationFuzzer initialization and configuration."""

    def test_init_default(self):
        """Test default initialization."""
        fuzzer = CalibrationFuzzer()
        assert fuzzer.strategy_name == "calibration"


class TestPixelSpacingFuzzing:
    """Test PixelSpacing fuzzing attacks."""

    @pytest.fixture
    def sample_dataset(self):
        """Create a sample dataset with calibration tags."""
        ds = pydicom.Dataset()
        ds.PixelSpacing = [0.5, 0.5]
        ds.ImagerPixelSpacing = [0.5, 0.5]
        ds.PixelSpacingCalibrationType = "GEOMETRY"
        return ds

    def test_pixel_spacing_mismatch(self, sample_dataset):
        """Test PixelSpacing vs ImagerPixelSpacing mismatch."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="mismatch")
        assert ds.PixelSpacing != ds.ImagerPixelSpacing

    def test_pixel_spacing_zero(self, sample_dataset):
        """Test zero PixelSpacing (divide by zero)."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="zero")
        assert ds.PixelSpacing == [0.0, 0.0]

    def test_pixel_spacing_negative(self, sample_dataset):
        """Test negative PixelSpacing."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="negative")
        assert ds.PixelSpacing == [-1.0, -1.0]

    def test_pixel_spacing_extreme_small(self, sample_dataset):
        """Test extremely small PixelSpacing."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="extreme_small")
        assert ds.PixelSpacing[0] < 1e-5

    def test_pixel_spacing_extreme_large(self, sample_dataset):
        """Test extremely large PixelSpacing."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="extreme_large")
        assert ds.PixelSpacing[0] > 1e5

    def test_pixel_spacing_nan(self, sample_dataset):
        """Test NaN PixelSpacing."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="nan")
        assert math.isnan(ds.PixelSpacing[0])

    def test_pixel_spacing_inconsistent(self, sample_dataset):
        """Test inconsistent X/Y PixelSpacing (1000:1 ratio)."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="inconsistent")
        ratio = ds.PixelSpacing[1] / ds.PixelSpacing[0]
        assert ratio == pytest.approx(1000.0)


class TestHounsfieldRescaleFuzzing:
    """Test RescaleSlope/RescaleIntercept fuzzing."""

    @pytest.fixture
    def ct_dataset(self):
        """Create a CT dataset with rescale parameters."""
        ds = pydicom.Dataset()
        ds.RescaleSlope = 1.0
        ds.RescaleIntercept = -1024.0
        ds.Modality = "CT"
        return ds

    def test_zero_slope(self, ct_dataset):
        """Test zero RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_hounsfield_rescale(ct_dataset, attack_type="zero_slope")
        assert ds.RescaleSlope == 0.0

    def test_negative_slope(self, ct_dataset):
        """Test negative RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_hounsfield_rescale(ct_dataset, attack_type="negative_slope")
        assert ds.RescaleSlope == -1.0

    def test_extreme_slope(self, ct_dataset):
        """Test extreme RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_hounsfield_rescale(ct_dataset, attack_type="extreme_slope")
        assert ds.RescaleSlope == 1e15

    def test_nan_slope(self, ct_dataset):
        """Test NaN RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_hounsfield_rescale(ct_dataset, attack_type="nan_slope")
        assert math.isnan(ds.RescaleSlope)

    def test_inf_slope(self, ct_dataset):
        """Test infinity RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_hounsfield_rescale(ct_dataset, attack_type="inf_slope")
        assert math.isinf(ds.RescaleSlope)

    def test_hu_overflow(self, ct_dataset):
        """Test HU overflow combination."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_hounsfield_rescale(ct_dataset, attack_type="hu_overflow")
        assert ds.RescaleSlope == 1e6
        assert ds.RescaleIntercept == 1e10


class TestWindowLevelFuzzing:
    """Test WindowCenter/WindowWidth fuzzing."""

    @pytest.fixture
    def windowed_dataset(self):
        """Create a dataset with window/level settings."""
        ds = pydicom.Dataset()
        ds.WindowCenter = 40
        ds.WindowWidth = 400
        return ds

    def test_zero_width(self, windowed_dataset):
        """Test zero WindowWidth (divide by zero)."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_window_level(windowed_dataset, attack_type="zero_width")
        assert ds.WindowWidth == 0

    def test_negative_width(self, windowed_dataset):
        """Test negative WindowWidth."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_window_level(windowed_dataset, attack_type="negative_width")
        assert ds.WindowWidth == -100

    def test_extreme_width_small(self, windowed_dataset):
        """Test very small WindowWidth."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="extreme_width_small"
        )
        assert ds.WindowWidth == 0.0001

    def test_extreme_width_large(self, windowed_dataset):
        """Test very large WindowWidth."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="extreme_width_large"
        )
        assert ds.WindowWidth == 1e10

    def test_nan_values(self, windowed_dataset):
        """Test NaN window/level values."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_window_level(windowed_dataset, attack_type="nan_values")
        assert math.isnan(ds.WindowCenter)
        assert math.isnan(ds.WindowWidth)

    def test_multiple_windows_conflict(self, windowed_dataset):
        """Test multiple conflicting window presets."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="multiple_windows_conflict"
        )
        assert len(ds.WindowCenter) == 3
        assert len(ds.WindowWidth) == 3


class TestSliceThicknessFuzzing:
    """Test SliceThickness fuzzing."""

    @pytest.fixture
    def volumetric_dataset(self):
        """Create a dataset with slice thickness."""
        ds = pydicom.Dataset()
        ds.SliceThickness = 5.0
        ds.SpacingBetweenSlices = 5.0
        return ds

    def test_zero_thickness(self, volumetric_dataset):
        """Test zero SliceThickness."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_slice_thickness(volumetric_dataset, attack_type="zero")
        assert ds.SliceThickness == 0.0

    def test_negative_thickness(self, volumetric_dataset):
        """Test negative SliceThickness."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_slice_thickness(volumetric_dataset, attack_type="negative")
        assert ds.SliceThickness == -5.0

    def test_thickness_spacing_mismatch(self, volumetric_dataset):
        """Test SliceThickness != SpacingBetweenSlices."""
        fuzzer = CalibrationFuzzer()
        ds = fuzzer.fuzz_slice_thickness(volumetric_dataset, attack_type="mismatch")
        assert ds.SliceThickness != ds.SpacingBetweenSlices


class TestMutate:
    """Test mutate (FormatFuzzerBase interface)."""

    def test_mutate_returns_dataset(self):
        """Test mutate returns a dataset."""
        ds = pydicom.Dataset()
        ds.PixelSpacing = [0.5, 0.5]
        ds.RescaleSlope = 1.0
        ds.RescaleIntercept = -1024.0
        ds.WindowCenter = 40
        ds.WindowWidth = 400
        ds.SliceThickness = 5.0

        fuzzer = CalibrationFuzzer()
        result = fuzzer.mutate(ds)
        assert isinstance(result, pydicom.Dataset)
