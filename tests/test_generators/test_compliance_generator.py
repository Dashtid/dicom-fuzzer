"""Tests for compliance_violations/generator.py - DICOM Compliance Violation Generator.

Tests cover sample generation for invalid VR, oversized values, missing elements,
and encoding errors.
"""

from unittest.mock import patch

from dicom_fuzzer.generators.compliance_violations.generator import (
    ComplianceViolationGenerator,
    main,
)


class TestComplianceViolationGeneratorInit:
    """Test ComplianceViolationGenerator initialization."""

    def test_init_with_output_dir(self, tmp_path):
        """Test initialization with output directory."""
        generator = ComplianceViolationGenerator(tmp_path)
        assert generator.output_dir == tmp_path

    def test_init_with_string_path(self, tmp_path):
        """Test initialization with string path."""
        generator = ComplianceViolationGenerator(str(tmp_path))
        assert generator.output_dir == tmp_path


class TestCreateBaseDicom:
    """Test create_base_dicom method."""

    def test_create_base_dicom_returns_dataset(self, tmp_path):
        """Test that create_base_dicom returns a valid dataset."""
        generator = ComplianceViolationGenerator(tmp_path)
        ds = generator.create_base_dicom()

        assert ds.PatientName == "COMPLIANCE^TEST"
        assert ds.PatientID == "COMPLIANCE-001"
        assert ds.Modality == "OT"
        assert ds.Rows == 8
        assert ds.Columns == 8

    def test_create_base_dicom_has_file_meta(self, tmp_path):
        """Test that dataset has file meta information."""
        generator = ComplianceViolationGenerator(tmp_path)
        ds = generator.create_base_dicom()

        assert hasattr(ds, "file_meta")
        assert ds.file_meta.MediaStorageSOPClassUID is not None


class TestGenerateInvalidVRSamples:
    """Test generate_invalid_vr_samples method."""

    def test_generates_samples(self, tmp_path):
        """Test that invalid VR samples are generated."""
        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_invalid_vr_samples()

        assert "integer_as_string" in results
        assert "date_malformed" in results
        assert "uid_invalid_chars" in results
        assert "string_as_sequence" in results

    def test_creates_output_directory(self, tmp_path):
        """Test that output directory is created."""
        generator = ComplianceViolationGenerator(tmp_path)
        generator.generate_invalid_vr_samples()

        assert (tmp_path / "invalid_vr").exists()

    def test_files_are_created(self, tmp_path):
        """Test that sample files are created."""
        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_invalid_vr_samples()

        for name, path in results.items():
            assert path.exists(), f"File not created: {name}"


class TestGenerateOversizedSamples:
    """Test generate_oversized_samples method."""

    def test_generates_samples(self, tmp_path):
        """Test that oversized samples are generated."""
        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_oversized_samples()

        assert "ui_oversized" in results
        assert "lo_oversized" in results
        assert "sh_oversized" in results
        assert "ae_oversized" in results

    def test_creates_output_directory(self, tmp_path):
        """Test that output directory is created."""
        generator = ComplianceViolationGenerator(tmp_path)
        generator.generate_oversized_samples()

        assert (tmp_path / "oversized_values").exists()


class TestGenerateMissingRequiredSamples:
    """Test generate_missing_required_samples method."""

    def test_generates_samples(self, tmp_path):
        """Test that missing required samples are generated."""
        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_missing_required_samples()

        assert "no_sop_class" in results
        assert "no_sop_instance" in results
        assert "no_patient_id" in results
        assert "no_study_instance" in results

    def test_creates_output_directory(self, tmp_path):
        """Test that output directory is created."""
        generator = ComplianceViolationGenerator(tmp_path)
        generator.generate_missing_required_samples()

        assert (tmp_path / "missing_required").exists()


class TestGenerateEncodingErrorSamples:
    """Test generate_encoding_error_samples method."""

    def test_generates_samples(self, tmp_path):
        """Test that encoding error samples are generated."""
        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_encoding_error_samples()

        assert "invalid_utf8" in results
        assert "wrong_charset" in results
        assert "null_in_string" in results
        assert "mixed_encoding" in results

    def test_creates_output_directory(self, tmp_path):
        """Test that output directory is created."""
        generator = ComplianceViolationGenerator(tmp_path)
        generator.generate_encoding_error_samples()

        assert (tmp_path / "encoding_errors").exists()


class TestGenerateAll:
    """Test generate_all method."""

    def test_generates_all_categories(self, tmp_path):
        """Test that all categories are generated."""
        generator = ComplianceViolationGenerator(tmp_path)
        results = generator.generate_all()

        assert "invalid_vr" in results
        assert "oversized_values" in results
        assert "missing_required" in results
        assert "encoding_errors" in results


class TestMain:
    """Test main CLI function."""

    def test_main_default_category(self, tmp_path, capsys):
        """Test main with default category (all)."""
        with patch("sys.argv", ["generator", "--output-dir", str(tmp_path)]):
            main()

        # Should create all category directories
        assert (tmp_path / "invalid_vr").exists()
        assert (tmp_path / "oversized_values").exists()

    def test_main_specific_category(self, tmp_path, capsys):
        """Test main with specific category."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--category", "invalid_vr"],
        ):
            main()

        assert (tmp_path / "invalid_vr").exists()

    def test_main_oversized_category(self, tmp_path):
        """Test main with oversized category."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--category", "oversized"],
        ):
            main()

        assert (tmp_path / "oversized_values").exists()

    def test_main_missing_category(self, tmp_path):
        """Test main with missing category."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--category", "missing"],
        ):
            main()

        assert (tmp_path / "missing_required").exists()

    def test_main_encoding_category(self, tmp_path):
        """Test main with encoding category."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--category", "encoding"],
        ):
            main()

        assert (tmp_path / "encoding_errors").exists()
