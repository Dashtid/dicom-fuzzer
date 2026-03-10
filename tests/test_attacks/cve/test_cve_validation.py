"""Tests for CVE post-generation validation."""

import io

import pydicom
import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.cli.commands.cve import cmd_validate_generated
from dicom_fuzzer.cve import CVEFile, CVEGenerator, CVEInfo
from dicom_fuzzer.cve.registry import CVECategory


# =============================================================================
# Fixtures
# =============================================================================
@pytest.fixture
def template_bytes(tmp_path) -> bytes:
    """Create a DICOM template with tags that CVE mutations target."""
    file_meta = FileMetaDataset()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.ImplementationClassUID = generate_uid()

    ds = Dataset()
    ds.file_meta = file_meta
    ds.PatientName = "CVE^Template"
    ds.PatientID = "CVE001"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.Manufacturer = "TestManufacturer"
    ds.InstitutionAddress = "http://example.com"
    ds.StationName = "STATION01"
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    path = tmp_path / "template.dcm"
    ds.save_as(path, enforce_file_format=True)
    return path.read_bytes()


@pytest.fixture
def sample_cve_info() -> CVEInfo:
    """Create a sample CVEInfo for test CVEFile objects."""
    return CVEInfo(
        cve_id="CVE-TEST-0001",
        description="Test CVE",
        category=CVECategory.HEAP_OVERFLOW,
        severity="high",
        cvss_score=9.8,
        affected_product="TestProduct",
        affected_versions="1.0",
        target_component="pixel_data",
        references=[],
        variants=1,
    )


# =============================================================================
# Tests
# =============================================================================
class TestValidateGenerated:
    """Tests for cmd_validate_generated."""

    def test_valid_mutated_file_passes(
        self, template_bytes: bytes, sample_cve_info: CVEInfo
    ) -> None:
        """Mutated file that preserves structure passes validation."""
        # Mutate a single byte in the pixel data area
        mutated = bytearray(template_bytes)
        mutated[-10] = 0xFF
        cve_file = CVEFile(
            cve_id="CVE-TEST-0001",
            variant="test_variant",
            data=bytes(mutated),
            info=sample_cve_info,
        )
        rc = cmd_validate_generated([cve_file], template_bytes)
        assert rc == 0

    def test_identical_to_template_fails(
        self, template_bytes: bytes, sample_cve_info: CVEInfo
    ) -> None:
        """File identical to template fails (mutation had no effect)."""
        cve_file = CVEFile(
            cve_id="CVE-TEST-0001",
            variant="no_mutation",
            data=template_bytes,
            info=sample_cve_info,
        )
        rc = cmd_validate_generated([cve_file], template_bytes)
        assert rc == 1

    def test_unparseable_file_warns_not_fails(
        self, template_bytes: bytes, sample_cve_info: CVEInfo
    ) -> None:
        """Unparseable file is a warning, not a failure.

        Some CVE exploits intentionally break DICOM structure.
        """
        cve_file = CVEFile(
            cve_id="CVE-TEST-0001",
            variant="garbage",
            data=b"\xff" * 10,  # Not identical to template, but unparseable
            info=sample_cve_info,
        )
        rc = cmd_validate_generated([cve_file], template_bytes)
        assert rc == 0  # Warning only, not failure

    def test_sop_class_uid_change_warns(
        self, template_bytes: bytes, sample_cve_info: CVEInfo
    ) -> None:
        """SOPClassUID change produces warning but not failure."""
        # Create a valid DICOM with different SOPClassUID
        ds = pydicom.dcmread(io.BytesIO(template_bytes), force=True)
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.4"  # MR instead of CT
        buf = io.BytesIO()
        ds.save_as(buf, enforce_file_format=True)
        changed_bytes = buf.getvalue()

        cve_file = CVEFile(
            cve_id="CVE-TEST-0001",
            variant="sop_changed",
            data=changed_bytes,
            info=sample_cve_info,
        )
        # SOPClassUID mismatch is a warning, not a failure
        rc = cmd_validate_generated([cve_file], template_bytes)
        assert rc == 0

    def test_multiple_files_mixed_results(
        self, template_bytes: bytes, sample_cve_info: CVEInfo
    ) -> None:
        """Mix of passing and failing files returns failure."""
        mutated = bytearray(template_bytes)
        mutated[-10] = 0xFF
        good_file = CVEFile(
            cve_id="CVE-TEST-0001",
            variant="good",
            data=bytes(mutated),
            info=sample_cve_info,
        )
        bad_file = CVEFile(
            cve_id="CVE-TEST-0001",
            variant="bad",
            data=template_bytes,  # identical = fail
            info=sample_cve_info,
        )
        rc = cmd_validate_generated([good_file, bad_file], template_bytes)
        assert rc == 1

    def test_real_cve_files_pass_validation(self, template_bytes: bytes) -> None:
        """Real CVE-generated files pass validation."""
        generator = CVEGenerator()
        files = generator.generate("CVE-2025-5943", template_bytes)
        assert len(files) > 0

        rc = cmd_validate_generated(files, template_bytes)
        assert rc == 0

    def test_all_cves_pass_validation(self, template_bytes: bytes) -> None:
        """All CVE generators produce files that pass validation."""
        generator = CVEGenerator()
        all_files = []
        for cve_id in generator.available_cves:
            files = generator.generate(cve_id, template_bytes)
            all_files.extend(files)

        assert len(all_files) > 0
        rc = cmd_validate_generated(all_files, template_bytes)
        assert rc == 0
