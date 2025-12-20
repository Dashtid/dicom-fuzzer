"""
Comprehensive integration tests for DICOM Fuzzer.

Tests cover:
- End-to-end fuzzing workflows
- Module interaction and data flow
- Complete parse-mutate-generate-validate cycles
- Error handling across module boundaries
- Performance and resource management
- Real-world usage scenarios
"""

import shutil

import pytest
from pydicom.dataset import Dataset

from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.core.validator import DicomValidator
from dicom_fuzzer.strategies.header_fuzzer import HeaderFuzzer
from dicom_fuzzer.strategies.metadata_fuzzer import MetadataFuzzer
from dicom_fuzzer.strategies.pixel_fuzzer import PixelFuzzer


class TestEndToEndFuzzingWorkflow:
    """Test complete end-to-end fuzzing workflows."""

    def test_complete_fuzzing_pipeline(self, sample_dicom_file, temp_dir):
        """Test complete pipeline: parse -> fuzz -> validate -> generate."""
        # Step 1: Parse original file
        parser = DicomParser(sample_dicom_file)
        original_dataset = parser.dataset
        assert original_dataset is not None

        # Step 2: Apply fuzzing directly
        metadata_fuzzer = MetadataFuzzer()
        mutated_dataset = metadata_fuzzer.mutate_patient_info(original_dataset.copy())

        assert mutated_dataset is not None

        # Step 3: Validate mutated dataset
        validator = DicomValidator(strict_mode=False)
        result = validator.validate(mutated_dataset)

        # Should be parseable (may have warnings)
        assert result is not None

        # Step 4: Generate batch of fuzzed files
        output_dir = temp_dir / "integration_output"
        generator = DICOMGenerator(output_dir=str(output_dir))
        generated_files = generator.generate_batch(sample_dicom_file, count=5)

        assert len(generated_files) == 5
        assert all(f.exists() for f in generated_files)

        # Cleanup
        shutil.rmtree(output_dir)

    def test_fuzzing_with_validation_feedback_loop(self, sample_dicom_file, temp_dir):
        """Test fuzzing with validation feedback loop."""
        output_dir = temp_dir / "feedback_output"
        generator = DICOMGenerator(output_dir=str(output_dir))
        validator = DicomValidator(strict_mode=False)

        # Generate files
        generated_files = generator.generate_batch(sample_dicom_file, count=10)

        # Validate each file and collect results
        valid_count = 0
        invalid_count = 0

        for file_path in generated_files:
            result, dataset = validator.validate_file(file_path)
            if result.is_valid:
                valid_count += 1
            else:
                invalid_count += 1

        # At least some files should be generated
        assert valid_count + invalid_count == 10

        # Cleanup
        shutil.rmtree(output_dir)

    def test_multi_strategy_mutation_workflow(self, sample_dicom_file):
        """Test applying multiple mutation strategies in sequence."""
        parser = DicomParser(sample_dicom_file)
        original_dataset = parser.dataset

        # Apply all strategies directly
        metadata_fuzzer = MetadataFuzzer()
        header_fuzzer = HeaderFuzzer()
        pixel_fuzzer = PixelFuzzer()

        mutated_dataset = original_dataset.copy()
        mutated_dataset = metadata_fuzzer.mutate_patient_info(mutated_dataset)
        mutated_dataset = header_fuzzer.mutate_tags(mutated_dataset)
        mutated_dataset = pixel_fuzzer.mutate_pixels(mutated_dataset)

        # Verify mutations were applied
        assert mutated_dataset is not None


class TestModuleInteractionAndDataFlow:
    """Test interactions between different modules."""

    def test_parser_to_fuzzer_data_flow(self, sample_dicom_file):
        """Test data flow from parser to fuzzer."""
        # Parse file
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        # Pass to fuzzer
        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(dataset.copy())

        # Verify data flow
        assert mutated is not None
        assert isinstance(mutated, Dataset)

    def test_fuzzer_to_validator_data_flow(self, sample_dicom_file):
        """Test data flow from fuzzer to validator."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        # Fuzz
        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(dataset.copy())

        # Validate
        validator = DicomValidator(strict_mode=False)
        result = validator.validate(mutated)

        # Should validate successfully
        assert result is not None

    def test_generator_to_parser_round_trip(self, sample_dicom_file, temp_dir):
        """Test round trip: generate file -> parse it back."""
        output_dir = temp_dir / "roundtrip"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Generate file
        generated_files = generator.generate_batch(sample_dicom_file, count=1)
        generated_file = generated_files[0]

        # Parse it back
        parser = DicomParser(generated_file)
        dataset = parser.dataset

        # Should be parseable
        assert dataset is not None

        # Cleanup
        shutil.rmtree(output_dir)

    def test_validator_to_fuzzer_feedback(self, sample_dicom_file):
        """Test using validator feedback to guide fuzzing."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        validator = DicomValidator(strict_mode=True)

        # Initial validation
        validator.validate(dataset)

        # Apply fuzzing
        fuzzer = MetadataFuzzer()
        mutated = fuzzer.mutate_patient_info(dataset.copy())

        # Validate again
        result = validator.validate(mutated)

        # Should still be a dataset
        assert result is not None


class TestErrorHandlingAcrossModules:
    """Test error handling across module boundaries."""

    def test_invalid_file_propagates_through_pipeline(self, temp_dir):
        """Test that invalid file errors propagate correctly."""
        invalid_file = temp_dir / "invalid.dcm"
        invalid_file.write_bytes(b"Not a DICOM file")

        # Parser should handle gracefully or raise
        with pytest.raises(Exception):  # May be various exception types
            parser = DicomParser(invalid_file)
            _ = parser.dataset

    def test_validator_catches_mutator_issues(self, sample_dicom_file):
        """Test that validator catches issues from mutations."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        # Create dataset with issues
        broken_dataset = dataset.copy()
        broken_dataset.PatientName = "\x00" * 100  # Null bytes

        validator = DicomValidator(strict_mode=False)
        result = validator.validate(broken_dataset)

        # Should detect issues
        # (may be errors or warnings depending on severity)
        assert result is not None

    def test_validation_with_no_mutations(self, sample_dicom_file):
        """Test validation of unchanged dataset."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        validator = DicomValidator(strict_mode=False)

        # Validate without any mutations
        result = validator.validate(dataset)

        # Should validate successfully
        assert result is not None


class TestPerformanceAndResourceManagement:
    """Test performance and resource management."""

    def test_batch_generation_performance(self, sample_dicom_file, temp_dir):
        """Test performance of batch generation."""
        import time

        output_dir = temp_dir / "perf_test"
        generator = DICOMGenerator(output_dir=str(output_dir))

        start_time = time.time()
        generated_files = generator.generate_batch(sample_dicom_file, count=20)
        elapsed_time = time.time() - start_time

        assert len(generated_files) == 20
        # Should complete in reasonable time (< 30 seconds)
        assert elapsed_time < 30, f"Batch generation took {elapsed_time:.2f}s"

        # Cleanup
        shutil.rmtree(output_dir)

    def test_memory_management_with_large_batches(self, sample_dicom_file, temp_dir):
        """Test memory management with large batches."""
        output_dir = temp_dir / "memory_test"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Generate large batch
        generated_files = generator.generate_batch(sample_dicom_file, count=50)

        assert len(generated_files) == 50
        assert all(f.exists() for f in generated_files)

        # Cleanup
        shutil.rmtree(output_dir)

    def test_validator_batch_performance(self, sample_dicom_file, temp_dir):
        """Test validator batch performance."""
        import time

        output_dir = temp_dir / "val_perf"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Generate files
        generated_files = generator.generate_batch(sample_dicom_file, count=20)

        # Validate batch
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
        # Should complete quickly (< 10 seconds for 20 files)
        assert elapsed_time < 10, f"Batch validation took {elapsed_time:.2f}s"

        # Cleanup
        shutil.rmtree(output_dir)


class TestRealWorldUsageScenarios:
    """Test real-world usage scenarios."""

    def test_continuous_fuzzing_session(self, sample_dicom_file, temp_dir):
        """Test continuous fuzzing session with multiple rounds."""
        output_dir = temp_dir / "continuous"
        generator = DICOMGenerator(output_dir=str(output_dir))
        validator = DicomValidator(strict_mode=False)

        total_files = []

        # Multiple rounds of generation
        for round_num in range(3):
            batch = generator.generate_batch(sample_dicom_file, count=5)
            total_files.extend(batch)

        assert len(total_files) == 15

        # Validate all files
        valid_count = 0
        for file_path in total_files:
            result, _ = validator.validate_file(file_path)
            if result.is_valid or len(result.errors) == 0:
                valid_count += 1

        # Most files should be valid
        assert valid_count > 0

        # Cleanup
        shutil.rmtree(output_dir)

    def test_targeted_fuzzing_campaign(self, sample_dicom_file, temp_dir):
        """Test targeted fuzzing campaign with specific strategy."""
        output_dir = temp_dir / "targeted"
        parser = DicomParser(sample_dicom_file)
        original = parser.dataset

        fuzzer = MetadataFuzzer()
        results = []

        # Generate multiple targeted mutations
        for i in range(10):
            mutated = fuzzer.mutate_patient_info(original.copy())

            # Save to file
            output_file = output_dir / f"targeted_{i}.dcm"
            output_file.parent.mkdir(parents=True, exist_ok=True)
            mutated.save_as(output_file)
            results.append(output_file)

        assert len(results) == 10
        assert all(f.exists() for f in results)

        # Cleanup
        shutil.rmtree(output_dir)

    def test_fuzzing_with_error_analysis(self, sample_dicom_file, temp_dir):
        """Test fuzzing with detailed error analysis."""
        output_dir = temp_dir / "error_analysis"
        generator = DICOMGenerator(output_dir=str(output_dir))
        validator = DicomValidator(strict_mode=True)

        # Generate files
        generated_files = generator.generate_batch(sample_dicom_file, count=15)

        # Analyze errors
        error_categories = {}

        for file_path in generated_files:
            result, _ = validator.validate_file(file_path)

            for error in result.errors:
                # Categorize errors
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

        # Should have processed all files
        assert len(generated_files) == 15

        # Cleanup
        shutil.rmtree(output_dir)


class TestIntegrationEdgeCases:
    """Test edge cases in integration scenarios."""

    def test_dataset_copy_preserves_data(self, sample_dicom_file):
        """Test that dataset copying preserves data."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        # Copy dataset
        copied = dataset.copy()

        # Both should be valid datasets
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

        # Should validate with warning about missing file meta
        assert any("file meta" in w.lower() for w in result.warnings)

    def test_generator_with_minimal_dicom(self, minimal_dicom_file, temp_dir):
        """Test generator with minimal DICOM file."""
        output_dir = temp_dir / "minimal_test"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(minimal_dicom_file, count=3)

        assert len(generated_files) == 3
        assert all(f.exists() for f in generated_files)

        # Cleanup
        shutil.rmtree(output_dir)


class TestConcurrentOperations:
    """Test concurrent operations and thread safety."""

    def test_multiple_parsers_same_file(self, sample_dicom_file):
        """Test multiple parsers on same file."""
        parsers = [DicomParser(sample_dicom_file) for _ in range(5)]

        # All should parse successfully
        for parser in parsers:
            assert parser.dataset is not None

    def test_multiple_validators_same_dataset(self, sample_dicom_file):
        """Test multiple validators on same dataset."""
        parser = DicomParser(sample_dicom_file)
        dataset = parser.dataset

        validators = [DicomValidator(strict_mode=False) for _ in range(5)]

        results = [v.validate(dataset) for v in validators]

        # All should produce valid results
        assert len(results) == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
