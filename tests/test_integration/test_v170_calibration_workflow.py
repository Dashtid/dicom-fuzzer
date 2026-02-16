"""Integration Tests for v1.7.0 Calibration Fuzzing Workflows

Tests the CalibrationFuzzer integration with DICOM datasets containing
calibration tags for pixel spacing, Hounsfield units, and window/level.
"""

import tempfile
from pathlib import Path

import pytest
from pydicom.dataset import FileDataset, FileMetaDataset
from pydicom.uid import generate_uid


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def create_ct_dicom(temp_dir: Path, filename: str = "ct_slice.dcm") -> Path:
    """Create a CT DICOM file with full calibration tags."""
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
    file_meta.ImplementationClassUID = generate_uid()

    ds = FileDataset(
        str(temp_dir / filename), {}, file_meta=file_meta, preamble=b"\x00" * 128
    )

    # Patient/Study info
    ds.PatientName = "CALIBRATION^TEST"
    ds.PatientID = "CAL001"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.InstanceNumber = 1
    ds.Modality = "CT"

    # Image dimensions
    ds.Rows = 128
    ds.Columns = 128
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.PixelRepresentation = 1  # Signed for CT
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"

    # Calibration tags
    ds.PixelSpacing = [0.5, 0.5]
    ds.ImagerPixelSpacing = [0.5, 0.5]
    ds.SliceThickness = 2.0
    ds.SpacingBetweenSlices = 2.0

    # Hounsfield unit rescaling
    ds.RescaleIntercept = -1024.0
    ds.RescaleSlope = 1.0
    ds.RescaleType = "HU"

    # Window/Level presets
    ds.WindowCenter = [40, 400]
    ds.WindowWidth = [400, 1500]
    ds.WindowCenterWidthExplanation = ["Soft Tissue", "Bone"]

    # Geometry
    ds.ImagePositionPatient = [0, 0, 0]
    ds.ImageOrientationPatient = [1, 0, 0, 0, 1, 0]
    ds.SliceLocation = 0.0

    ds.PixelData = b"\x00" * (128 * 128 * 2)

    file_path = temp_dir / filename
    ds.save_as(str(file_path), write_like_original=False)
    return file_path


@pytest.fixture
def ct_dicom_file(temp_dir):
    """Create a CT DICOM file for testing."""
    return create_ct_dicom(temp_dir)


@pytest.fixture
def ct_series(temp_dir):
    """Create a CT series with multiple slices."""
    series_dir = temp_dir / "ct_series"
    series_dir.mkdir()
    files = []
    for i in range(5):
        f = create_ct_dicom(series_dir, f"slice_{i:03d}.dcm")
        files.append(f)
    return {"dir": series_dir, "files": files}


class TestCalibrationFuzzerIntegration:
    """Integration tests for CalibrationFuzzer workflows."""

    def test_pixel_spacing_fuzz_workflow(self, ct_dicom_file):
        """Test pixel spacing fuzzing workflow."""
        import pydicom

        from dicom_fuzzer.attacks.format.calibration_fuzzer import (
            CalibrationFuzzer,
        )

        ds = pydicom.dcmread(str(ct_dicom_file))
        fuzzer = CalibrationFuzzer()
        fuzzed_ds = fuzzer.fuzz_pixel_spacing(ds)
        assert fuzzed_ds is not None

    def test_hounsfield_rescale_fuzz_workflow(self, ct_dicom_file):
        """Test Hounsfield unit rescale fuzzing workflow."""
        import pydicom

        from dicom_fuzzer.attacks.format.calibration_fuzzer import (
            CalibrationFuzzer,
        )

        ds = pydicom.dcmread(str(ct_dicom_file))
        fuzzer = CalibrationFuzzer()
        fuzzed_ds = fuzzer.fuzz_hounsfield_rescale(ds)
        assert fuzzed_ds is not None

    def test_window_level_fuzz_workflow(self, ct_dicom_file):
        """Test window/level parameter fuzzing workflow."""
        import pydicom

        from dicom_fuzzer.attacks.format.calibration_fuzzer import (
            CalibrationFuzzer,
        )

        ds = pydicom.dcmread(str(ct_dicom_file))
        fuzzer = CalibrationFuzzer()
        fuzzed_ds = fuzzer.fuzz_window_level(ds)
        assert fuzzed_ds is not None

    def test_slice_thickness_fuzz_workflow(self, ct_dicom_file):
        """Test slice thickness fuzzing workflow."""
        import pydicom

        from dicom_fuzzer.attacks.format.calibration_fuzzer import (
            CalibrationFuzzer,
        )

        ds = pydicom.dcmread(str(ct_dicom_file))
        fuzzer = CalibrationFuzzer()
        fuzzed_ds = fuzzer.fuzz_slice_thickness(ds)
        assert fuzzed_ds is not None

    def test_combined_calibration_attacks(self, ct_dicom_file, temp_dir):
        """Test applying multiple calibration attacks to same file."""
        import pydicom

        from dicom_fuzzer.attacks.format.calibration_fuzzer import (
            CalibrationFuzzer,
        )

        ds = pydicom.dcmread(str(ct_dicom_file))
        fuzzer = CalibrationFuzzer()

        # Apply all calibration attacks
        ds = fuzzer.fuzz_pixel_spacing(ds)
        ds = fuzzer.fuzz_hounsfield_rescale(ds)
        ds = fuzzer.fuzz_window_level(ds)

        # Save and verify file is still readable
        output_file = temp_dir / "multi_fuzzed.dcm"
        pydicom.dcmwrite(str(output_file), ds)

        reloaded = pydicom.dcmread(str(output_file))
        assert reloaded is not None


class TestCalibrationAttackTypes:
    """Test specific attack types for each calibration category."""

    @pytest.mark.parametrize(
        "attack_type",
        ["mismatch", "zero", "negative", "extreme_small", "inconsistent"],
    )
    def test_pixel_spacing_attack_types(self, ct_dicom_file, attack_type):
        """Test various pixel spacing attack types."""
        import pydicom

        from dicom_fuzzer.attacks.format.calibration_fuzzer import (
            CalibrationFuzzer,
        )

        ds = pydicom.dcmread(str(ct_dicom_file))
        fuzzer = CalibrationFuzzer()
        fuzzed_ds = fuzzer.fuzz_pixel_spacing(ds, attack_type=attack_type)
        assert fuzzed_ds is not None

    @pytest.mark.parametrize(
        "attack_type",
        ["zero_slope", "negative_slope", "extreme_slope", "hu_overflow"],
    )
    def test_hounsfield_attack_types(self, ct_dicom_file, attack_type):
        """Test various Hounsfield rescale attack types."""
        import pydicom

        from dicom_fuzzer.attacks.format.calibration_fuzzer import (
            CalibrationFuzzer,
        )

        ds = pydicom.dcmread(str(ct_dicom_file))
        fuzzer = CalibrationFuzzer()
        fuzzed_ds = fuzzer.fuzz_hounsfield_rescale(ds, attack_type=attack_type)
        assert fuzzed_ds is not None


class TestCalibrationSeedReproducibility:
    """Test seed-based reproducibility."""

    def test_seed_reproducibility(self, ct_dicom_file):
        """Test that seed parameter enables reproducible mutations."""
        import pydicom

        from dicom_fuzzer.attacks.format.calibration_fuzzer import (
            CalibrationFuzzer,
        )

        ds1 = pydicom.dcmread(str(ct_dicom_file))
        ds2 = pydicom.dcmread(str(ct_dicom_file))

        fuzzer1 = CalibrationFuzzer(seed=12345)
        fuzzer2 = CalibrationFuzzer(seed=12345)

        result1 = fuzzer1.fuzz_pixel_spacing(ds1, attack_type="mismatch")
        result2 = fuzzer2.fuzz_pixel_spacing(ds2, attack_type="mismatch")

        # Same attack type should produce same mutations
        assert list(result1.PixelSpacing) == list(result2.PixelSpacing)
        assert list(result1.ImagerPixelSpacing) == list(result2.ImagerPixelSpacing)
