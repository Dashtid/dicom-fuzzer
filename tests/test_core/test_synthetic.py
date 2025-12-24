"""
Tests for Synthetic DICOM File Generator Module.

Tests generation of synthetic DICOM files with fabricated patient data.
"""

import pytest

from dicom_fuzzer.core.synthetic import (
    FIRST_NAMES,
    LAST_NAMES,
    PHOTOMETRIC_INTERPRETATION,
    SOP_CLASS_UIDS,
    SyntheticDataGenerator,
    SyntheticDicomGenerator,
    SyntheticPatient,
    SyntheticSeries,
    SyntheticStudy,
)

# ============================================================================
# Test Constants
# ============================================================================


class TestConstants:
    """Test module constants."""

    def test_sop_class_uids_defined(self):
        """Test SOP_CLASS_UIDS has expected modalities."""
        expected_modalities = [
            "CT",
            "MR",
            "US",
            "CR",
            "DX",
            "PT",
            "NM",
            "XA",
            "RF",
            "SC",
        ]
        for modality in expected_modalities:
            assert modality in SOP_CLASS_UIDS
            assert SOP_CLASS_UIDS[modality].startswith("1.2.840.10008")

    def test_photometric_interpretation_defined(self):
        """Test PHOTOMETRIC_INTERPRETATION has entries for all modalities."""
        for modality in SOP_CLASS_UIDS:
            assert modality in PHOTOMETRIC_INTERPRETATION

    def test_name_lists_populated(self):
        """Test name lists have entries."""
        assert len(FIRST_NAMES) > 0
        assert len(LAST_NAMES) > 0


# ============================================================================
# Test Data Classes
# ============================================================================


class TestSyntheticPatient:
    """Test SyntheticPatient dataclass."""

    def test_patient_creation(self):
        """Test creating a SyntheticPatient."""
        patient = SyntheticPatient(
            name="Doe^John",
            patient_id="12345678",
            birth_date="19800101",
            sex="M",
            age="044Y",
        )

        assert patient.name == "Doe^John"
        assert patient.patient_id == "12345678"
        assert patient.birth_date == "19800101"
        assert patient.sex == "M"
        assert patient.age == "044Y"


class TestSyntheticStudy:
    """Test SyntheticStudy dataclass."""

    def test_study_creation(self):
        """Test creating a SyntheticStudy."""
        study = SyntheticStudy(
            study_instance_uid="1.2.3.4.5",
            study_date="20230101",
            study_time="120000",
            study_description="Test Study",
            accession_number="ACC12345",
            referring_physician="Smith^J",
        )

        assert study.study_instance_uid == "1.2.3.4.5"
        assert study.study_date == "20230101"
        assert study.study_time == "120000"
        assert study.study_description == "Test Study"
        assert study.accession_number == "ACC12345"
        assert study.referring_physician == "Smith^J"


class TestSyntheticSeries:
    """Test SyntheticSeries dataclass."""

    def test_series_creation(self):
        """Test creating a SyntheticSeries."""
        series = SyntheticSeries(
            series_instance_uid="1.2.3.4.5.6",
            series_number=1,
            series_description="Axial",
            modality="CT",
            body_part="HEAD",
            patient_position="HFS",
        )

        assert series.series_instance_uid == "1.2.3.4.5.6"
        assert series.series_number == 1
        assert series.series_description == "Axial"
        assert series.modality == "CT"
        assert series.body_part == "HEAD"
        assert series.patient_position == "HFS"


# ============================================================================
# Test SyntheticDataGenerator
# ============================================================================


class TestSyntheticDataGenerator:
    """Test SyntheticDataGenerator class."""

    def test_initialization_without_seed(self):
        """Test initialization without seed."""
        gen = SyntheticDataGenerator()
        assert gen is not None

    def test_initialization_with_seed(self):
        """Test initialization with seed."""
        gen = SyntheticDataGenerator(seed=42)
        patient = gen.generate_patient()
        # With seed, generation should work
        assert patient is not None
        assert patient.name != ""

    def test_generate_patient(self):
        """Test generating a synthetic patient."""
        gen = SyntheticDataGenerator(seed=42)
        patient = gen.generate_patient()

        assert patient is not None
        assert "^" in patient.name  # Format: LastName^FirstName
        assert len(patient.patient_id) == 8
        assert patient.patient_id.isdigit()
        assert len(patient.birth_date) == 8
        assert patient.sex in ["M", "F", "O"]
        assert patient.age.endswith("Y")

    def test_generate_patient_name_format(self):
        """Test patient name has correct DICOM format."""
        gen = SyntheticDataGenerator(seed=123)
        patient = gen.generate_patient()

        parts = patient.name.split("^")
        assert len(parts) == 2
        assert parts[0] in LAST_NAMES
        assert parts[1] in FIRST_NAMES

    def test_generate_study(self):
        """Test generating a synthetic study."""
        gen = SyntheticDataGenerator(seed=42)
        study = gen.generate_study()

        assert study is not None
        assert study.study_instance_uid.startswith("1.2.826")  # pydicom generated UID
        assert len(study.study_date) == 8
        assert len(study.study_time) == 6
        assert study.study_description != ""
        assert study.accession_number != ""
        assert "^" in study.referring_physician

    def test_generate_study_date_format(self):
        """Test study date is valid DICOM format."""
        gen = SyntheticDataGenerator(seed=42)
        study = gen.generate_study()

        # Validate date format YYYYMMDD
        year = int(study.study_date[:4])
        month = int(study.study_date[4:6])
        day = int(study.study_date[6:8])

        assert 2000 <= year <= 2100
        assert 1 <= month <= 12
        assert 1 <= day <= 31

    def test_generate_series(self):
        """Test generating a synthetic series."""
        gen = SyntheticDataGenerator(seed=42)
        series = gen.generate_series()

        assert series is not None
        assert series.series_instance_uid.startswith("1.2.826")
        assert series.series_number >= 1
        assert series.modality in SOP_CLASS_UIDS
        assert series.body_part != ""
        assert series.patient_position in [
            "HFS",
            "HFP",
            "FFS",
            "FFP",
            "HFDR",
            "HFDL",
            "FFDR",
            "FFDL",
        ]

    def test_generate_series_with_specific_modality(self):
        """Test generating series with specific modality."""
        gen = SyntheticDataGenerator(seed=42)

        for modality in ["CT", "MR", "US"]:
            series = gen.generate_series(modality=modality)
            assert series.modality == modality

    def test_generate_series_random_modality(self):
        """Test generating series with random modality."""
        gen = SyntheticDataGenerator(seed=42)
        series = gen.generate_series(modality=None)

        assert series.modality in SOP_CLASS_UIDS

    def test_different_seeds_vary(self):
        """Test that different seeds produce different results over many iterations."""
        gen1 = SyntheticDataGenerator(seed=1)
        gen2 = SyntheticDataGenerator(seed=9999)

        # Generate multiple patients to check for variation
        patients1 = [gen1.generate_patient() for _ in range(5)]
        patients2 = [gen2.generate_patient() for _ in range(5)]

        # At least some variation expected between different seeds
        names1 = {p.name for p in patients1}
        names2 = {p.name for p in patients2}

        # Combined set should have variation (not all identical)
        all_names = names1 | names2
        assert len(all_names) >= 2


# ============================================================================
# Test SyntheticDicomGenerator
# ============================================================================


class TestSyntheticDicomGenerator:
    """Test SyntheticDicomGenerator class."""

    @pytest.fixture
    def output_dir(self, tmp_path):
        """Create temporary output directory."""
        return tmp_path / "synthetic_output"

    @pytest.fixture
    def generator(self, output_dir):
        """Create a SyntheticDicomGenerator."""
        return SyntheticDicomGenerator(output_dir=output_dir, seed=42)

    def test_initialization(self, output_dir):
        """Test initialization creates output directory."""
        gen = SyntheticDicomGenerator(output_dir=output_dir)
        assert output_dir.exists()

    def test_initialization_with_seed(self, output_dir):
        """Test initialization with seed."""
        gen = SyntheticDicomGenerator(output_dir=output_dir, seed=42)
        assert gen.data_gen is not None

    def test_generate_file_creates_dcm(self, generator, output_dir):
        """Test generate_file creates a DICOM file."""
        filepath = generator.generate_file(modality="CT", rows=64, columns=64)

        assert filepath is not None
        assert filepath.exists()
        assert filepath.suffix == ".dcm"

    def test_generate_file_with_custom_filename(self, generator, output_dir):
        """Test generate_file with custom filename."""
        filepath = generator.generate_file(
            modality="CT",
            rows=64,
            columns=64,
            filename="custom_test.dcm",
        )

        assert filepath.name == "custom_test.dcm"
        assert filepath.exists()

    def test_generate_file_different_modalities(self, generator):
        """Test generating files for different modalities."""
        for modality in ["CT", "MR", "US", "CR"]:
            filepath = generator.generate_file(modality=modality, rows=32, columns=32)
            assert filepath.exists()

    def test_generate_file_with_patient(self, generator):
        """Test generate_file with custom patient data."""
        patient = SyntheticPatient(
            name="Test^Patient",
            patient_id="99999999",
            birth_date="19900101",
            sex="M",
            age="034Y",
        )

        filepath = generator.generate_file(
            modality="CT",
            rows=32,
            columns=32,
            patient=patient,
        )

        assert filepath.exists()

    def test_generate_file_with_study(self, generator):
        """Test generate_file with custom study data."""
        study = SyntheticStudy(
            study_instance_uid="1.2.3.4.5.6.7",
            study_date="20231215",
            study_time="140000",
            study_description="Custom Study",
            accession_number="CUSTOM123",
            referring_physician="Custom^Doctor",
        )

        filepath = generator.generate_file(
            modality="CT",
            rows=32,
            columns=32,
            study=study,
        )

        assert filepath.exists()

    def test_generate_file_with_series(self, generator):
        """Test generate_file with custom series data."""
        series = SyntheticSeries(
            series_instance_uid="1.2.3.4.5.6.7.8",
            series_number=5,
            series_description="Custom Series",
            modality="CT",
            body_part="CUSTOM",
            patient_position="HFS",
        )

        filepath = generator.generate_file(
            modality="CT",
            rows=32,
            columns=32,
            series=series,
        )

        assert filepath.exists()

    def test_generate_file_creates_valid_dicom(self, generator):
        """Test generated file is valid DICOM."""
        import pydicom

        filepath = generator.generate_file(modality="CT", rows=64, columns=64)

        # Should be readable as DICOM
        ds = pydicom.dcmread(filepath)
        assert ds.Modality == "CT"
        assert ds.Rows == 64
        assert ds.Columns == 64
        assert hasattr(ds, "PatientName")
        assert hasattr(ds, "PatientID")
        assert hasattr(ds, "PixelData")

    def test_generate_multiple_files(self, generator):
        """Test generating multiple files for different series."""
        files = []
        for i in range(3):
            filepath = generator.generate_file(
                modality="CT",
                rows=32,
                columns=32,
                filename=f"test_{i}.dcm",
            )
            files.append(filepath)

        assert len(files) == 3
        for f in files:
            assert f.exists()


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_generate_patient_multiple_times(self):
        """Test generating multiple different patients."""
        gen = SyntheticDataGenerator()
        patients = [gen.generate_patient() for _ in range(10)]

        # Names should vary (with high probability)
        names = {p.name for p in patients}
        # At least some variation expected
        assert len(names) >= 2

    def test_generate_study_multiple_times(self):
        """Test generating multiple different studies."""
        gen = SyntheticDataGenerator()
        studies = [gen.generate_study() for _ in range(10)]

        # UIDs should all be unique
        uids = {s.study_instance_uid for s in studies}
        assert len(uids) == 10

    def test_small_image_generation(self, tmp_path):
        """Test generating very small images."""
        gen = SyntheticDicomGenerator(output_dir=tmp_path, seed=42)
        filepath = gen.generate_file(modality="CT", rows=1, columns=1)
        assert filepath.exists()

    def test_large_image_generation(self, tmp_path):
        """Test generating larger images."""
        gen = SyntheticDicomGenerator(output_dir=tmp_path, seed=42)
        filepath = gen.generate_file(modality="CT", rows=128, columns=128)
        assert filepath.exists()

    def test_all_modalities_supported(self, tmp_path):
        """Test all defined modalities can generate files."""
        gen = SyntheticDicomGenerator(output_dir=tmp_path, seed=42)

        for modality in SOP_CLASS_UIDS:
            filepath = gen.generate_file(modality=modality, rows=16, columns=16)
            assert filepath.exists(), f"Failed to generate {modality}"
