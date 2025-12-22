"""Integration Tests for v1.7.0 Study-Level Mutation Workflows

Tests the StudyMutator integration with multi-series DICOM studies,
validating cross-series mutations and study-wide consistency attacks.
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


def create_dicom_slice(
    temp_dir: Path,
    filename: str,
    series_uid: str,
    study_uid: str,
    patient_id: str,
    patient_name: str,
    modality: str = "CT",
    instance_number: int = 1,
    slice_location: float = 0.0,
) -> Path:
    """Create a single DICOM slice with specified parameters."""
    file_meta = FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
    file_meta.ImplementationClassUID = generate_uid()

    ds = FileDataset(
        str(temp_dir / filename), {}, file_meta=file_meta, preamble=b"\x00" * 128
    )

    ds.PatientName = patient_name
    ds.PatientID = patient_id
    ds.StudyInstanceUID = study_uid
    ds.SeriesInstanceUID = series_uid
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.InstanceNumber = instance_number
    ds.Modality = modality
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.PixelRepresentation = 0
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.SliceThickness = 1.0
    ds.SliceLocation = slice_location
    ds.ImagePositionPatient = [0, 0, slice_location]
    ds.ImageOrientationPatient = [1, 0, 0, 0, 1, 0]
    ds.PixelSpacing = [1.0, 1.0]
    ds.PixelData = b"\x00" * (64 * 64 * 2)

    file_path = temp_dir / filename
    ds.save_as(str(file_path), write_like_original=False)
    return file_path


@pytest.fixture
def multi_series_study(temp_dir):
    """Create a DICOM study with 2 series (CT and MR)."""
    study_uid = generate_uid()
    patient_id = "STUDY001"
    patient_name = "TEST^STUDY"

    # Series 1: CT with 3 slices
    ct_series_uid = generate_uid()
    ct_dir = temp_dir / "series_ct"
    ct_dir.mkdir()
    ct_files = []
    for i in range(3):
        f = create_dicom_slice(
            ct_dir,
            f"ct_{i:03d}.dcm",
            ct_series_uid,
            study_uid,
            patient_id,
            patient_name,
            modality="CT",
            instance_number=i + 1,
            slice_location=float(i),
        )
        ct_files.append(f)

    # Series 2: MR with 3 slices
    mr_series_uid = generate_uid()
    mr_dir = temp_dir / "series_mr"
    mr_dir.mkdir()
    mr_files = []
    for i in range(3):
        f = create_dicom_slice(
            mr_dir,
            f"mr_{i:03d}.dcm",
            mr_series_uid,
            study_uid,
            patient_id,
            patient_name,
            modality="MR",
            instance_number=i + 1,
            slice_location=float(i),
        )
        mr_files.append(f)

    return {
        "study_dir": temp_dir,
        "study_uid": study_uid,
        "patient_id": patient_id,
        "ct_series_uid": ct_series_uid,
        "mr_series_uid": mr_series_uid,
        "ct_files": ct_files,
        "mr_files": mr_files,
    }


class TestStudyMutatorIntegration:
    """Integration tests for StudyMutator workflows."""

    def test_load_study_detects_multiple_series(self, multi_series_study):
        """Test that StudyMutator correctly loads a multi-series study."""
        from dicom_fuzzer.strategies.study_mutator import StudyMutator

        mutator = StudyMutator(severity="moderate")
        study = mutator.load_study(multi_series_study["study_dir"])

        assert study is not None
        assert study.series_count == 2
        assert study.study_uid == multi_series_study["study_uid"]

    def test_cross_series_reference_mutation(self, multi_series_study, temp_dir):
        """Test cross-series reference attack workflow."""
        from dicom_fuzzer.strategies.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        mutator = StudyMutator(severity="aggressive")
        study = mutator.load_study(multi_series_study["study_dir"])

        fuzzed_study, records = mutator.mutate_study(
            study,
            strategy=StudyMutationStrategy.CROSS_SERIES_REFERENCE,
            mutation_count=3,
        )

        assert fuzzed_study is not None
        assert len(records) > 0

        # Verify records have expected fields
        for record in records:
            assert record.strategy == "cross_series_reference"
            assert record.severity == "aggressive"

    def test_patient_consistency_mutation(self, multi_series_study):
        """Test patient consistency attack across series."""
        from dicom_fuzzer.strategies.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        mutator = StudyMutator(severity="moderate")
        study = mutator.load_study(multi_series_study["study_dir"])

        fuzzed_study, records = mutator.mutate_study(
            study, strategy=StudyMutationStrategy.PATIENT_CONSISTENCY, mutation_count=2
        )

        assert fuzzed_study is not None
        assert len(records) > 0

        # Check for patient consistency attack records
        patient_records = [r for r in records if "patient" in r.strategy.lower()]
        assert len(patient_records) > 0

    def test_frame_of_reference_mutation(self, multi_series_study):
        """Test frame of reference attacks for registration corruption."""
        from dicom_fuzzer.strategies.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        mutator = StudyMutator(severity="extreme")
        study = mutator.load_study(multi_series_study["study_dir"])

        fuzzed_study, records = mutator.mutate_study(
            study, strategy=StudyMutationStrategy.FRAME_OF_REFERENCE, mutation_count=2
        )

        assert fuzzed_study is not None
        assert len(records) > 0

    def test_mutated_study_can_be_saved_manually(self, multi_series_study, temp_dir):
        """Test that mutated study datasets can be saved and reloaded."""
        import pydicom

        from dicom_fuzzer.strategies.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        mutator = StudyMutator(severity="moderate")
        study = mutator.load_study(multi_series_study["study_dir"])

        # mutate_study returns (list[list[Dataset]], list[records])
        fuzzed_series_list, _ = mutator.mutate_study(
            study, strategy=StudyMutationStrategy.STUDY_METADATA, mutation_count=1
        )

        # Save mutated study manually by iterating series
        output_dir = temp_dir / "mutated_study"
        output_dir.mkdir()

        file_count = 0
        for series_idx, series_datasets in enumerate(fuzzed_series_list):
            for slice_idx, ds in enumerate(series_datasets):
                output_file = output_dir / f"series_{series_idx}_{slice_idx:03d}.dcm"
                pydicom.dcmwrite(str(output_file), ds)
                file_count += 1

        # Verify files were created
        dcm_files = list(output_dir.glob("*.dcm"))
        assert len(dcm_files) == file_count
        assert file_count > 0

        # Reload and verify
        reloaded = mutator.load_study(output_dir)
        assert reloaded is not None

    def test_mixed_modality_study_mutation(self, multi_series_study):
        """Test mixed modality study mutation strategy."""
        from dicom_fuzzer.strategies.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        mutator = StudyMutator(severity="aggressive")
        study = mutator.load_study(multi_series_study["study_dir"])

        fuzzed_study, records = mutator.mutate_study(
            study, strategy=StudyMutationStrategy.MIXED_MODALITY_STUDY, mutation_count=2
        )

        assert fuzzed_study is not None
        assert len(records) > 0


class TestStudyMutationRecordSerialization:
    """Test serialization of study mutation records."""

    def test_mutation_record_to_dict(self, multi_series_study):
        """Test that mutation records can be serialized to dict."""
        from dicom_fuzzer.strategies.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        mutator = StudyMutator(severity="moderate")
        study = mutator.load_study(multi_series_study["study_dir"])

        _, records = mutator.mutate_study(
            study,
            strategy=StudyMutationStrategy.CROSS_SERIES_REFERENCE,
            mutation_count=1,
        )

        assert len(records) > 0
        record_dict = records[0].to_dict()

        assert "strategy" in record_dict
        assert "severity" in record_dict
        assert record_dict["severity"] == "moderate"

    def test_mutation_record_json_serializable(self, multi_series_study):
        """Test that mutation records can be serialized to JSON."""
        import json

        from dicom_fuzzer.strategies.study_mutator import (
            StudyMutationStrategy,
            StudyMutator,
        )

        mutator = StudyMutator(severity="moderate")
        study = mutator.load_study(multi_series_study["study_dir"])

        _, records = mutator.mutate_study(
            study, strategy=StudyMutationStrategy.PATIENT_CONSISTENCY, mutation_count=1
        )

        # Should not raise
        for record in records:
            json_str = json.dumps(record.to_dict())
            assert json_str is not None
            parsed = json.loads(json_str)
            assert parsed["strategy"] is not None


class TestStudyMutatorSeverityLevels:
    """Test different severity levels produce different mutation intensities."""

    @pytest.mark.parametrize(
        "severity", ["minimal", "moderate", "aggressive", "extreme"]
    )
    def test_severity_levels_accepted(self, multi_series_study, severity):
        """Test that all severity levels are accepted."""
        from dicom_fuzzer.strategies.study_mutator import StudyMutator

        mutator = StudyMutator(severity=severity)
        study = mutator.load_study(multi_series_study["study_dir"])

        assert study is not None
        assert mutator.severity == severity

    def test_invalid_severity_rejected(self):
        """Test that invalid severity levels are rejected."""
        from dicom_fuzzer.strategies.study_mutator import StudyMutator

        with pytest.raises(ValueError):
            StudyMutator(severity="invalid")
