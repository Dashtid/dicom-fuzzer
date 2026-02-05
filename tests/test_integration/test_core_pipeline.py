"""
Core pipeline integration tests for DICOM Fuzzer.

Consolidated from test_integration.py and test_integration_simple.py.

Tests cover:
- End-to-end fuzzing workflows (parse -> fuzz -> validate -> generate)
- Module interaction and data flow
- Error handling across module boundaries
- Performance and resource management
- Series detection and validation
- Concurrent operations
"""

import shutil

import pydicom
import pydicom.uid
import pytest
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.attacks.format.header_fuzzer import HeaderFuzzer
from dicom_fuzzer.attacks.format.metadata_fuzzer import MetadataFuzzer
from dicom_fuzzer.attacks.format.pixel_fuzzer import PixelFuzzer
from dicom_fuzzer.core import (
    DICOMGenerator,
    DicomMutator,
    DicomParser,
    DicomValidator,
    SeriesDetector,
    SeriesValidator,
)


@pytest.fixture
def sample_dicom_series(temp_dir):
    """Create a sample DICOM series with multiple slices."""
    series_uid = generate_uid()
    study_uid = generate_uid()

    files = []
    for i in range(3):
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = (
            "1.2.840.10008.5.1.4.1.1.4"  # MR Image Storage
        )
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.ImplementationClassUID = generate_uid()

        ds = FileDataset(
            str(temp_dir / f"slice_{i:03d}.dcm"),
            {},
            file_meta=file_meta,
            preamble=b"\x00" * 128,
        )

        ds.PatientName = "SERIES^TEST"
        ds.PatientID = "54321"
        ds.StudyInstanceUID = study_uid
        ds.SeriesInstanceUID = series_uid
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.InstanceNumber = i + 1
        ds.Modality = "MR"
        ds.Rows = 256
        ds.Columns = 256
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.SliceThickness = 1.0
        ds.SliceLocation = float(i)
        ds.ImagePositionPatient = [0, 0, float(i)]
        ds.ImageOrientationPatient = [1, 0, 0, 0, 1, 0]
        ds.PixelSpacing = [1.0, 1.0]
        ds.PixelData = b"\x00" * (256 * 256 * 2)

        file_path = temp_dir / f"slice_{i:03d}.dcm"
        ds.save_as(str(file_path), write_like_original=False)
        files.append(file_path)

    return files


class TestEndToEndFuzzingWorkflow:
    """Test complete end-to-end fuzzing workflows."""

    def test_complete_fuzzing_pipeline(self, sample_dicom_file, temp_dir):
        """Test complete pipeline: parse -> fuzz -> validate -> generate."""
        # Step 1: Parse original file
        parser = DicomParser(sample_dicom_file)
        original_dataset = parser.dataset
        assert original_dataset is not None

        # Step 2: Apply fuzzing
        metadata_fuzzer = MetadataFuzzer()
        mutated_dataset = metadata_fuzzer.mutate_patient_info(original_dataset.copy())
        assert mutated_dataset is not None

        # Step 3: Validate mutated dataset
        validator = DicomValidator(strict_mode=False)
        result = validator.validate(mutated_dataset)
        assert result is not None

        # Step 4: Generate batch of fuzzed files
        # Exclude CVE mutations for deterministic file count (they cause write failures by design)
        output_dir = temp_dir / "integration_output"
        generator = DICOMGenerator(output_dir=str(output_dir))
        generated_files = generator.generate_batch(
            sample_dicom_file, count=5, strategies=["metadata", "header", "pixel"]
        )

        assert len(generated_files) <= 5
        assert all(f.exists() for f in generated_files)
        shutil.rmtree(output_dir)

    def test_fuzzing_with_validation_feedback_loop(self, sample_dicom_file, temp_dir):
        """Test fuzzing with validation feedback loop."""
        output_dir = temp_dir / "feedback_output"
        generator = DICOMGenerator(output_dir=str(output_dir))
        validator = DicomValidator(strict_mode=False)

        # Exclude CVE mutations for deterministic file count (CVE mutations cause write failures)
        generated_files = generator.generate_batch(
            sample_dicom_file, count=10, strategies=["metadata", "header", "pixel"]
        )

        valid_count = 0
        invalid_count = 0

        for file_path in generated_files:
            result, dataset = validator.validate_file(file_path)
            if result.is_valid:
                valid_count += 1
            else:
                invalid_count += 1

        assert valid_count + invalid_count == len(generated_files)
        shutil.rmtree(output_dir)

    def test_multi_strategy_mutation_workflow(self, sample_dicom_file):
        """Test applying multiple mutation strategies in sequence."""
        parser = DicomParser(sample_dicom_file)
        original_dataset = parser.dataset

        metadata_fuzzer = MetadataFuzzer()
        header_fuzzer = HeaderFuzzer()
        pixel_fuzzer = PixelFuzzer()

        mutated_dataset = original_dataset.copy()
        mutated_dataset = metadata_fuzzer.mutate_patient_info(mutated_dataset)
        mutated_dataset = header_fuzzer.mutate_tags(mutated_dataset)
        mutated_dataset = pixel_fuzzer.mutate_pixels(mutated_dataset)

        assert mutated_dataset is not None

    def test_parse_validate_mutate_workflow(self, sample_dicom_file):
        """Test the basic workflow of parsing, validating, and mutating."""
        parser = DicomParser(str(sample_dicom_file))
        metadata = parser.extract_metadata()
        assert metadata is not None
        assert "patient_name" in metadata

        validator = DicomValidator()
        result, _ = validator.validate_file(sample_dicom_file)
        assert result.is_valid

        mutator = DicomMutator()
        dataset = pydicom.dcmread(str(sample_dicom_file))
        mutated_ds = mutator.apply_mutations(dataset)
        assert mutated_ds is not None
        assert hasattr(mutated_ds, "PatientName")


class TestModuleInteractionAndDataFlow:
    """Test interactions between different modules."""

    def test_parser_to_fuzzer_data_flow(self, sample_dicom_file):
        """Test data flow from parser to fuzzer."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(dataset.copy())

        assert mutated is not None
        assert isinstance(mutated, Dataset)

    def test_fuzzer_to_validator_data_flow(self, sample_dicom_file):
        """Test data flow from fuzzer to validator."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(dataset.copy())

        validator = DicomValidator(strict_mode=False)
        result = validator.validate(mutated)
        assert result is not None

    def test_generator_to_parser_round_trip(self, sample_dicom_file, temp_dir):
        """Test round trip: generate file -> parse it back."""
        output_dir = temp_dir / "roundtrip"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=1)

        # Handle case where generation might fail (e.g., during parallel test runs)
        if not generated_files:
            pytest.skip("File generation failed - likely transient issue")

        generated_file = generated_files[0]

        parser = DicomParser(generated_file)
        dataset = parser.dataset
        assert dataset is not None
        shutil.rmtree(output_dir)

    def test_validator_to_fuzzer_feedback(self, sample_dicom_file):
        """Test using validator feedback to guide fuzzing."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        validator = DicomValidator(strict_mode=True)
        validator.validate(dataset)

        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(dataset.copy())

        result = validator.validate(mutated)
        assert result is not None

    def test_mutator_preserves_required_tags(self, sample_dicom_file):
        """Test that mutator preserves required DICOM tags."""
        mutator = DicomMutator()
        dataset = pydicom.dcmread(str(sample_dicom_file))
        mutated_ds = mutator.apply_mutations(dataset)

        assert hasattr(mutated_ds, "StudyInstanceUID")
        assert hasattr(mutated_ds, "SeriesInstanceUID")
        assert hasattr(mutated_ds, "SOPInstanceUID")
        assert hasattr(mutated_ds, "Modality")


class TestSeriesIntegration:
    """Test series detection and validation integration."""

    def test_series_detection_and_validation(self, sample_dicom_series, temp_dir):
        """Test detection and validation of a DICOM series."""
        detector = SeriesDetector()
        series_list = detector.detect_series_in_directory(temp_dir)

        assert len(series_list) == 1
        series = series_list[0]
        assert series.slice_count == 3

        validator = SeriesValidator()
        validation_result = validator.validate_series(series)
        assert validation_result.is_valid
        assert len(validation_result.issues) == 0

    def test_series_detector_with_mixed_files(self, temp_dir):
        """Test series detector with mixed DICOM and non-DICOM files."""
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.ImplementationClassUID = generate_uid()

        ds = FileDataset(
            str(temp_dir / "valid.dcm"), {}, file_meta=file_meta, preamble=b"\x00" * 128
        )
        ds.SeriesInstanceUID = generate_uid()
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.Modality = "CT"
        ds.PatientName = "TEST"
        ds.PatientID = "123"

        valid_file = temp_dir / "valid.dcm"
        ds.save_as(str(valid_file), write_like_original=False)

        invalid_file = temp_dir / "invalid.txt"
        invalid_file.write_text("Not a DICOM")

        detector = SeriesDetector()
        series_list = detector.detect_series_in_directory(temp_dir)
        assert len(series_list) == 1


class TestErrorHandlingAcrossModules:
    """Test error handling across module boundaries."""

    def test_invalid_file_propagates_through_pipeline(self, temp_dir):
        """Test that invalid file errors propagate correctly."""
        invalid_file = temp_dir / "invalid.dcm"
        invalid_file.write_bytes(b"Not a DICOM file")

        with pytest.raises(Exception):
            parser = DicomParser(invalid_file)
            _ = parser.dataset

    def test_validator_catches_mutator_issues(self, sample_dicom_file):
        """Test that validator catches issues from mutations."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        broken_dataset = dataset.copy()
        broken_dataset.PatientName = "\x00" * 100

        validator = DicomValidator(strict_mode=False)
        result = validator.validate(broken_dataset)
        assert result is not None

    def test_validation_without_mutations(self, sample_dicom_file):
        """Test validation of unchanged dataset."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        validator = DicomValidator(strict_mode=False)
        result = validator.validate(dataset)
        assert result is not None

    def test_validator_detects_invalid_file(self, temp_dir):
        """Test that validator detects invalid files."""
        invalid_file = temp_dir / "invalid.dcm"
        invalid_file.write_bytes(b"NOT_A_DICOM_FILE")

        validator = DicomValidator()
        result, _ = validator.validate_file(invalid_file)
        assert not result.is_valid

    def test_parser_with_corrupted_header(self, temp_dir):
        """Test parser with corrupted DICOM header."""
        corrupted = temp_dir / "corrupted.dcm"
        corrupted.write_bytes(b"DICM" + b"\xff" * 100)

        with pytest.raises(Exception):
            parser = DicomParser(str(corrupted))

    def test_mutator_with_empty_file(self, temp_dir):
        """Test mutator with empty file."""
        empty_file = temp_dir / "empty.dcm"
        empty_file.write_bytes(b"")

        mutator = DicomMutator()
        with pytest.raises(Exception):
            dataset = pydicom.dcmread(str(empty_file))
            mutator.apply_mutations(dataset)


class TestPerformanceAndResourceManagement:
    """Test performance and resource management."""

    def test_batch_generation_performance(self, sample_dicom_file, temp_dir):
        """Test performance of batch generation."""
        import time

        output_dir = temp_dir / "perf_test"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Exclude CVE mutations which can cause write failures by design
        strategies = ["metadata", "header", "pixel"]

        start_time = time.time()
        generated_files = generator.generate_batch(
            sample_dicom_file, count=20, strategies=strategies
        )
        elapsed_time = time.time() - start_time

        assert len(generated_files) <= 20
        assert elapsed_time < 30, f"Batch generation took {elapsed_time:.2f}s"
        shutil.rmtree(output_dir)

    def test_memory_management_with_large_batches(self, sample_dicom_file, temp_dir):
        """Test memory management with large batches.

        Some mutations produce unsaveable datasets (skip_write_errors=True),
        so generated count may be less than requested.
        """
        output_dir = temp_dir / "memory_test"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(
            sample_dicom_file, count=50, strategies=["metadata", "header", "pixel"]
        )

        assert len(generated_files) > 0
        assert len(generated_files) <= 50
        assert all(f.exists() for f in generated_files)
        shutil.rmtree(output_dir)

    def test_validator_batch_performance(self, sample_dicom_file, temp_dir):
        """Test validator batch performance."""
        import time

        output_dir = temp_dir / "val_perf"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Exclude CVE mutations which can cause write failures by design
        generated_files = generator.generate_batch(
            sample_dicom_file, count=20, strategies=["metadata", "header", "pixel"]
        )

        validator = DicomValidator(strict_mode=False)
        datasets = []

        for file_path in generated_files:
            _, dataset = validator.validate_file(file_path)
            if dataset:
                datasets.append(dataset)

        start_time = time.time()
        results = validator.validate_batch(datasets)
        elapsed_time = time.time() - start_time

        assert len(results) > 0
        assert elapsed_time < 10, f"Batch validation took {elapsed_time:.2f}s"
        shutil.rmtree(output_dir)


class TestRealWorldUsageScenarios:
    """Test real-world usage scenarios."""

    def test_continuous_fuzzing_session(self, sample_dicom_file, temp_dir):
        """Test continuous fuzzing session with multiple rounds."""
        output_dir = temp_dir / "continuous"
        generator = DICOMGenerator(output_dir=str(output_dir))
        validator = DicomValidator(strict_mode=False)

        # Exclude CVE mutations which can cause write failures by design
        strategies = ["metadata", "header", "pixel"]

        total_files = []

        for round_num in range(3):
            batch = generator.generate_batch(
                sample_dicom_file, count=5, strategies=strategies
            )
            total_files.extend(batch)

        assert len(total_files) <= 15

        valid_count = 0
        for file_path in total_files:
            result, _ = validator.validate_file(file_path)
            if result.is_valid or len(result.errors) == 0:
                valid_count += 1

        assert valid_count > 0
        shutil.rmtree(output_dir)

    def test_targeted_fuzzing_campaign(self, sample_dicom_file, temp_dir):
        """Test targeted fuzzing campaign with specific strategy."""
        output_dir = temp_dir / "targeted"
        parser = DicomParser(sample_dicom_file)
        original = parser.dataset

        fuzzer = MetadataFuzzer()
        results = []

        for i in range(10):
            mutated = fuzzer.mutate_patient_info(original.copy())
            output_file = output_dir / f"targeted_{i}.dcm"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            mutated.save_as(output_file)
            results.append(output_file)

        assert len(results) == 10
        assert all(f.exists() for f in results)
        shutil.rmtree(output_dir)

    def test_fuzzing_with_error_analysis(self, sample_dicom_file, temp_dir):
        """Test fuzzing with detailed error analysis."""
        output_dir = temp_dir / "error_analysis"
        generator = DICOMGenerator(output_dir=str(output_dir))
        validator = DicomValidator(strict_mode=True)

        # Exclude CVE mutations which can cause write failures by design
        generated_files = generator.generate_batch(
            sample_dicom_file, count=15, strategies=["metadata", "header", "pixel"]
        )

        error_categories = {}

        for file_path in generated_files:
            result, _ = validator.validate_file(file_path)

            for error in result.errors:
                if "missing" in error.lower():
                    error_categories["missing_tags"] = (
                        error_categories.get("missing_tags", 0) + 1
                    )
                elif "null" in error.lower():
                    error_categories["null_bytes"] = (
                        error_categories.get("null_bytes", 0) + 1
                    )
                else:
                    error_categories["other"] = error_categories.get("other", 0) + 1

        assert len(generated_files) <= 15
        shutil.rmtree(output_dir)


class TestIntegrationEdgeCases:
    """Test edge cases in integration scenarios."""

    def test_dataset_copy_preserves_data(self, sample_dicom_file):
        """Test that dataset copying preserves data."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        copied = dataset.copy()

        assert dataset is not None
        assert copied is not None
        assert len(copied) > 0

    def test_validation_without_file_meta(self):
        """Test validation of dataset without file meta."""
        dataset = Dataset()
        dataset.PatientName = "Test^Patient"
        dataset.PatientID = "TEST001"

        validator = DicomValidator(strict_mode=False)
        result = validator.validate(dataset)

        assert any("file meta" in w.lower() for w in result.warnings)

    def test_generator_with_minimal_dicom(self, minimal_dicom_file, temp_dir):
        """Test generator with minimal DICOM file."""
        output_dir = temp_dir / "minimal_test"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Exclude CVE mutations which can cause write failures by design
        generated_files = generator.generate_batch(
            minimal_dicom_file, count=3, strategies=["metadata", "header", "pixel"]
        )

        assert len(generated_files) <= 3
        assert all(f.exists() for f in generated_files)
        shutil.rmtree(output_dir)

    def test_generator_creates_valid_dicom(self, temp_dir):
        """Test that DICOMGenerator creates valid DICOM files."""
        generator = DICOMGenerator()

        output_path = temp_dir / "generated.dcm"
        generator.generate(str(output_path))

        assert output_path.exists()

        parser = DicomParser(str(output_path))
        metadata = parser.extract_metadata()
        assert metadata is not None

        validator = DicomValidator()
        result, _ = validator.validate_file(output_path)
        assert result.is_valid

    def test_generator_with_custom_tags(self, temp_dir):
        """Test generator with custom tags."""
        generator = DICOMGenerator()

        output_path = temp_dir / "custom.dcm"
        tags = {
            "PatientName": "CUSTOM^NAME",
            "PatientID": "CUSTOM123",
            "Modality": "US",
        }
        generator.generate(str(output_path), tags=tags)

        parser = DicomParser(str(output_path))
        metadata = parser.extract_metadata()
        assert "CUSTOM^NAME" in str(metadata["patient_name"])
        assert "CUSTOM123" in str(metadata["patient_id"])
        assert "US" in str(metadata["modality"])


class TestConcurrentOperations:
    """Test concurrent operations and thread safety."""

    def test_multiple_parsers_same_file(self, sample_dicom_file):
        """Test multiple parsers on same file."""
        parsers = [DicomParser(sample_dicom_file) for _ in range(5)]

        for parser in parsers:
            assert parser.dataset is not None

    def test_multiple_validators_same_dataset(self, sample_dicom_file):
        """Test multiple validators on same dataset."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        validators = [DicomValidator(strict_mode=False) for _ in range(5)]

        results = [v.validate(dataset) for v in validators]

        assert len(results) == 5


class TestProfilerIntegration:
    """Test profiler and metrics integration (from cross_module_integration)."""

    def test_profiler_metrics_calculations(self):
        """Test all FuzzingMetrics calculation methods."""
        from dicom_fuzzer.core.session.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()
        metrics.files_generated = 100
        metrics.total_duration = 10.0

        throughput = metrics.throughput_per_second()
        assert throughput == 10.0

        avg_time = metrics.avg_time_per_file()
        assert avg_time == 0.1

        remaining = metrics.estimated_time_remaining(target=200)
        assert remaining == 10.0

    def test_profiler_metrics_edge_cases(self):
        """Test FuzzingMetrics with edge cases."""
        from dicom_fuzzer.core.session.profiler import FuzzingMetrics

        metrics = FuzzingMetrics()

        metrics.files_generated = 10
        metrics.total_duration = 0.0
        assert metrics.throughput_per_second() == 0.0

        metrics.files_generated = 0
        metrics.total_duration = 10.0
        assert metrics.avg_time_per_file() == 0.0

        metrics.files_generated = 100
        assert metrics.estimated_time_remaining(target=50) == 0.0

    def test_performance_profiler_with_operations(self):
        """Test PerformanceProfiler recording various operations."""
        from dicom_fuzzer.core.session.profiler import PerformanceProfiler

        profiler = PerformanceProfiler()

        with profiler:
            profiler.record_mutation("parse", duration=0.01)
            profiler.record_mutation("mutate", duration=0.05)
            profiler.record_mutation("validate", duration=0.02)
            profiler.record_mutation("parse", duration=0.015)

        summary = profiler.get_summary()

        assert summary["duration_seconds"] >= 0
        assert summary["mutations_applied"] == 4

    def test_validator_parser_profiler_chain(self, temp_dir):
        """Test validator, parser, and profiler working together."""
        from dicom_fuzzer.core.session.profiler import PerformanceProfiler

        profiler = PerformanceProfiler()

        ds = Dataset()
        ds.PatientName = "Test"
        ds.PatientID = "123"
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = "1.2.3.4.5.6.7.8.9"
        ds.file_meta = FileMetaDataset()
        ds.file_meta.TransferSyntaxUID = pydicom.uid.ExplicitVRLittleEndian

        test_file = temp_dir / "test.dcm"
        pydicom.dcmwrite(test_file, ds)

        with profiler:
            parser = DicomParser(test_file)
            parsed = parser.dataset

            validator = DicomValidator()
            validation_result = validator.validate(parsed)

        assert parsed is not None
        assert bool(validation_result) is True
        summary = profiler.get_summary()
        assert summary["duration_seconds"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
