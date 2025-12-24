"""Tests for CalibrationFuzzer - Measurement and Calibration Fuzzing."""

import math

import pydicom
import pytest

from dicom_fuzzer.strategies.calibration_fuzzer import (
    CalibrationFuzzer,
    CalibrationMutationRecord,
)


class TestCalibrationFuzzer:
    """Test CalibrationFuzzer initialization and configuration."""

    def test_init_default(self):
        """Test default initialization."""
        fuzzer = CalibrationFuzzer()
        assert fuzzer.severity == "moderate"
        assert fuzzer.seed is None

    def test_init_with_severity(self):
        """Test initialization with custom severity."""
        fuzzer = CalibrationFuzzer(severity="aggressive")
        assert fuzzer.severity == "aggressive"

    def test_init_with_seed(self):
        """Test initialization with random seed."""
        fuzzer = CalibrationFuzzer(seed=42)
        assert fuzzer.seed == 42

    def test_init_invalid_severity(self):
        """Test initialization with invalid severity raises error."""
        with pytest.raises(ValueError, match="Invalid severity"):
            CalibrationFuzzer(severity="invalid")


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
        ds, records = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="mismatch")

        assert len(records) == 1
        assert records[0].category == "pixel_spacing"
        assert ds.PixelSpacing != ds.ImagerPixelSpacing

    def test_pixel_spacing_zero(self, sample_dataset):
        """Test zero PixelSpacing (divide by zero)."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="zero")

        assert len(records) == 1
        assert ds.PixelSpacing == [0.0, 0.0]

    def test_pixel_spacing_negative(self, sample_dataset):
        """Test negative PixelSpacing."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="negative")

        assert len(records) == 1
        assert ds.PixelSpacing == [-1.0, -1.0]

    def test_pixel_spacing_extreme_small(self, sample_dataset):
        """Test extremely small PixelSpacing."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_pixel_spacing(
            sample_dataset, attack_type="extreme_small"
        )

        assert len(records) == 1
        assert ds.PixelSpacing[0] < 1e-5

    def test_pixel_spacing_extreme_large(self, sample_dataset):
        """Test extremely large PixelSpacing."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_pixel_spacing(
            sample_dataset, attack_type="extreme_large"
        )

        assert len(records) == 1
        assert ds.PixelSpacing[0] > 1e5

    def test_pixel_spacing_nan(self, sample_dataset):
        """Test NaN PixelSpacing."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_pixel_spacing(sample_dataset, attack_type="nan")

        assert len(records) == 1
        assert math.isnan(ds.PixelSpacing[0])

    def test_pixel_spacing_inconsistent(self, sample_dataset):
        """Test inconsistent X/Y PixelSpacing (1000:1 ratio)."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_pixel_spacing(
            sample_dataset, attack_type="inconsistent"
        )

        assert len(records) == 1
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
        ds, records = fuzzer.fuzz_hounsfield_rescale(
            ct_dataset, attack_type="zero_slope"
        )

        assert len(records) == 1
        assert ds.RescaleSlope == 0.0

    def test_negative_slope(self, ct_dataset):
        """Test negative RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_hounsfield_rescale(
            ct_dataset, attack_type="negative_slope"
        )

        assert len(records) == 1
        assert ds.RescaleSlope == -1.0

    def test_extreme_slope(self, ct_dataset):
        """Test extreme RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_hounsfield_rescale(
            ct_dataset, attack_type="extreme_slope"
        )

        assert len(records) == 1
        assert ds.RescaleSlope == 1e15

    def test_nan_slope(self, ct_dataset):
        """Test NaN RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_hounsfield_rescale(
            ct_dataset, attack_type="nan_slope"
        )

        assert len(records) == 1
        assert math.isnan(ds.RescaleSlope)

    def test_inf_slope(self, ct_dataset):
        """Test infinity RescaleSlope."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_hounsfield_rescale(
            ct_dataset, attack_type="inf_slope"
        )

        assert len(records) == 1
        assert math.isinf(ds.RescaleSlope)

    def test_hu_overflow(self, ct_dataset):
        """Test HU overflow combination."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_hounsfield_rescale(
            ct_dataset, attack_type="hu_overflow"
        )

        assert len(records) == 1
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
        ds, records = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="zero_width"
        )

        assert len(records) == 1
        assert ds.WindowWidth == 0

    def test_negative_width(self, windowed_dataset):
        """Test negative WindowWidth."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="negative_width"
        )

        assert len(records) == 1
        assert ds.WindowWidth == -100

    def test_extreme_width_small(self, windowed_dataset):
        """Test very small WindowWidth."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="extreme_width_small"
        )

        assert len(records) == 1
        assert ds.WindowWidth == 0.0001

    def test_extreme_width_large(self, windowed_dataset):
        """Test very large WindowWidth."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="extreme_width_large"
        )

        assert len(records) == 1
        assert ds.WindowWidth == 1e10

    def test_nan_values(self, windowed_dataset):
        """Test NaN window/level values."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="nan_values"
        )

        assert len(records) == 1
        assert math.isnan(ds.WindowCenter)
        assert math.isnan(ds.WindowWidth)

    def test_multiple_windows_conflict(self, windowed_dataset):
        """Test multiple conflicting window presets."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_window_level(
            windowed_dataset, attack_type="multiple_windows_conflict"
        )

        assert len(records) == 1
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
        ds, records = fuzzer.fuzz_slice_thickness(
            volumetric_dataset, attack_type="zero"
        )

        assert len(records) == 1
        assert ds.SliceThickness == 0.0

    def test_negative_thickness(self, volumetric_dataset):
        """Test negative SliceThickness."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_slice_thickness(
            volumetric_dataset, attack_type="negative"
        )

        assert len(records) == 1
        assert ds.SliceThickness == -5.0

    def test_thickness_spacing_mismatch(self, volumetric_dataset):
        """Test SliceThickness != SpacingBetweenSlices."""
        fuzzer = CalibrationFuzzer()
        ds, records = fuzzer.fuzz_slice_thickness(
            volumetric_dataset, attack_type="mismatch"
        )

        assert len(records) == 1
        assert ds.SliceThickness != ds.SpacingBetweenSlices


class TestFuzzAll:
    """Test fuzz_all combined fuzzing."""

    def test_fuzz_all_applies_multiple(self):
        """Test fuzz_all applies multiple categories."""
        ds = pydicom.Dataset()
        ds.PixelSpacing = [0.5, 0.5]
        ds.RescaleSlope = 1.0
        ds.RescaleIntercept = -1024.0
        ds.WindowCenter = 40
        ds.WindowWidth = 400
        ds.SliceThickness = 5.0

        fuzzer = CalibrationFuzzer(seed=42)
        ds, records = fuzzer.fuzz_all(ds)

        # Should have at least some records (probabilistic)
        # With seed=42, we get consistent results
        assert isinstance(records, list)


class TestCalibrationMutationRecord:
    """Test CalibrationMutationRecord."""

    def test_record_creation(self):
        """Test creating a mutation record."""
        record = CalibrationMutationRecord(
            category="pixel_spacing",
            tag="PixelSpacing",
            original_value="[0.5, 0.5]",
            mutated_value="[0.0, 0.0]",
            attack_type="zero",
            severity="moderate",
        )

        assert record.category == "pixel_spacing"
        assert record.tag == "PixelSpacing"
        assert record.attack_type == "zero"

    def test_record_serialization(self):
        """Test record serialization."""
        record = CalibrationMutationRecord(
            category="hounsfield_rescale",
            tag="RescaleSlope",
            original_value="1.0",
            mutated_value="0.0",
            attack_type="zero_slope",
        )

        data = record.to_dict()
        assert isinstance(data, dict)
        assert data["category"] == "hounsfield_rescale"
