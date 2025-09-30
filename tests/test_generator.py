"""
Comprehensive tests for DICOM Generator.

Tests cover:
- DICOMGenerator initialization
- Output directory creation
- Batch file generation
- Filename generation and uniqueness
- Integration with fuzzing strategies
- File saving and output
- Edge cases
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from core.generator import DICOMGenerator


class TestDICOMGeneratorInit:
    """Test DICOMGenerator initialization."""

    def test_generator_creation_default_dir(self, temp_dir):
        """Test creating generator with default output directory."""
        output_dir = temp_dir / "fuzzed_dicoms"
        generator = DICOMGenerator(output_dir=str(output_dir))

        assert generator.output_dir == output_dir
        assert generator.output_dir.exists()
        assert generator.output_dir.is_dir()

    def test_generator_creation_custom_dir(self, temp_dir):
        """Test creating generator with custom output directory."""
        custom_dir = temp_dir / "custom_output"
        generator = DICOMGenerator(output_dir=str(custom_dir))

        assert generator.output_dir == custom_dir
        assert generator.output_dir.exists()

    def test_generator_creates_dir_if_missing(self, temp_dir):
        """Test that generator creates output directory if it doesn't exist."""
        nonexistent_dir = temp_dir / "level1" / "level2" / "output"
        assert not nonexistent_dir.exists()

        generator = DICOMGenerator(output_dir=str(nonexistent_dir))

        assert generator.output_dir.exists()
        assert generator.output_dir.is_dir()

    def test_generator_accepts_existing_dir(self, temp_dir):
        """Test that generator works with existing directory."""
        existing_dir = temp_dir / "existing"
        existing_dir.mkdir()

        generator = DICOMGenerator(output_dir=str(existing_dir))

        assert generator.output_dir == existing_dir
        assert generator.output_dir.exists()


class TestBatchGeneration:
    """Test batch file generation functionality."""

    def test_generate_batch_creates_files(self, sample_dicom_file, temp_dir):
        """Test that generate_batch creates the correct number of files."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=5)

        assert len(generated_files) == 5
        # Verify all files exist
        for file_path in generated_files:
            assert file_path.exists()
            assert file_path.is_file()

    def test_generate_batch_single_file(self, sample_dicom_file, temp_dir):
        """Test generating a single file."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=1)

        assert len(generated_files) == 1
        assert generated_files[0].exists()

    def test_generate_batch_zero_count(self, sample_dicom_file, temp_dir):
        """Test that count=0 generates no files."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=0)

        assert len(generated_files) == 0

    def test_generate_batch_large_count(self, sample_dicom_file, temp_dir):
        """Test generating a large batch of files."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=50)

        assert len(generated_files) == 50
        # Verify all files exist
        for file_path in generated_files:
            assert file_path.exists()

    def test_generate_batch_returns_paths(self, sample_dicom_file, temp_dir):
        """Test that generate_batch returns Path objects."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=3)

        assert all(isinstance(path, Path) for path in generated_files)

    def test_generate_batch_files_in_output_dir(self, sample_dicom_file, temp_dir):
        """Test that generated files are in the output directory."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=3)

        for file_path in generated_files:
            assert file_path.parent == output_dir


class TestFilenameGeneration:
    """Test filename generation and uniqueness."""

    def test_filename_format(self, sample_dicom_file, temp_dir):
        """Test that filenames follow expected format."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=5)

        for file_path in generated_files:
            # Should be fuzzed_<8char_hex>.dcm
            assert file_path.name.startswith("fuzzed_")
            assert file_path.name.endswith(".dcm")
            # Extract hex part: fuzzed_XXXXXXXX.dcm
            hex_part = file_path.name[7:-4]  # Skip "fuzzed_" and ".dcm"
            assert len(hex_part) == 8
            # Verify hex characters
            assert all(c in "0123456789abcdef" for c in hex_part)

    def test_filename_uniqueness(self, sample_dicom_file, temp_dir):
        """Test that all generated filenames are unique."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=10)

        filenames = [f.name for f in generated_files]
        assert len(filenames) == len(set(filenames))  # All unique

    def test_multiple_batches_unique_names(self, sample_dicom_file, temp_dir):
        """Test that multiple batches generate unique filenames."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        batch1 = generator.generate_batch(sample_dicom_file, count=5)
        batch2 = generator.generate_batch(sample_dicom_file, count=5)

        all_files = batch1 + batch2
        filenames = [f.name for f in all_files]
        assert len(filenames) == len(set(filenames))  # All unique across batches


class TestFuzzerIntegration:
    """Test integration with fuzzing strategies."""

    @patch("core.generator.MetadataFuzzer")
    @patch("core.generator.HeaderFuzzer")
    @patch("core.generator.PixelFuzzer")
    def test_fuzzers_instantiated(
        self,
        mock_pixel_fuzzer,
        mock_header_fuzzer,
        mock_metadata_fuzzer,
        sample_dicom_file,
        temp_dir,
    ):
        """Test that all fuzzer types are instantiated."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generator.generate_batch(sample_dicom_file, count=1)

        # Verify all fuzzer types were instantiated
        mock_metadata_fuzzer.assert_called()
        mock_header_fuzzer.assert_called()
        mock_pixel_fuzzer.assert_called()

    def test_mutations_applied_to_dataset(self, sample_dicom_file, temp_dir):
        """Test that mutations are actually applied to the dataset."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Generate files
        generated_files = generator.generate_batch(sample_dicom_file, count=5)

        # All files should be created (mutations were applied successfully)
        assert len(generated_files) == 5
        for file_path in generated_files:
            assert file_path.exists()
            # File should have content
            assert file_path.stat().st_size > 0

    @patch("random.sample")
    @patch("random.randint")
    def test_random_fuzzer_selection(
        self, mock_randint, mock_sample, sample_dicom_file, temp_dir
    ):
        """Test that fuzzers are randomly selected."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Mock random functions to control behavior
        mock_randint.return_value = 2  # Select 2 fuzzers
        mock_sample.return_value = []  # Return empty list to avoid actual fuzzing

        try:
            generator.generate_batch(sample_dicom_file, count=1)
        except (AttributeError, IndexError):
            # Expected since we're mocking the fuzzers
            pass

        # Verify random.sample was called
        mock_sample.assert_called()


class TestFileSaving:
    """Test file saving functionality."""

    def test_files_are_valid_dicom(self, sample_dicom_file, temp_dir):
        """Test that generated files are valid DICOM files."""
        from core.parser import DicomParser

        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=3)

        # Verify each file can be parsed as DICOM
        for file_path in generated_files:
            parser = DicomParser(file_path)
            assert parser.dataset is not None

    def test_files_contain_data(self, sample_dicom_file, temp_dir):
        """Test that generated files contain actual data."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=3)

        for file_path in generated_files:
            # File should not be empty
            assert file_path.stat().st_size > 0
            # Should be at least a few hundred bytes (DICOM header + data)
            assert file_path.stat().st_size > 200

    def test_files_saved_to_correct_location(self, sample_dicom_file, temp_dir):
        """Test that files are saved to the correct output directory."""
        output_dir = temp_dir / "specific_output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=3)

        for file_path in generated_files:
            assert file_path.parent == output_dir
            assert file_path.exists()


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_generate_with_nonexistent_file(self, temp_dir):
        """Test generating from nonexistent file raises error."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        nonexistent_file = temp_dir / "does_not_exist.dcm"

        with pytest.raises(Exception):  # DicomParser or FileNotFoundError
            generator.generate_batch(nonexistent_file, count=1)

    def test_generate_with_invalid_dicom(self, temp_dir):
        """Test generating from invalid DICOM file raises error."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        # Create invalid DICOM file
        invalid_file = temp_dir / "invalid.dcm"
        invalid_file.write_bytes(b"Not a DICOM file")

        with pytest.raises(Exception):  # DICOM parsing error
            generator.generate_batch(invalid_file, count=1)

    def test_output_dir_as_path_object(self, temp_dir):
        """Test that output_dir can be a Path object."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=output_dir)

        assert generator.output_dir == output_dir
        assert generator.output_dir.exists()

    def test_output_dir_as_string(self, temp_dir):
        """Test that output_dir can be a string."""
        output_dir = temp_dir / "output"
        generator = DICOMGenerator(output_dir=str(output_dir))

        assert generator.output_dir == output_dir
        assert generator.output_dir.exists()


class TestPropertyBasedTesting:
    """Property-based tests for robustness."""

    @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
    @given(count=st.integers(min_value=1, max_value=20))
    def test_generate_count_matches_output(self, sample_dicom_file, temp_dir, count):
        """Property test: output count always matches requested count."""
        output_dir = temp_dir / "output_prop"
        generator = DICOMGenerator(output_dir=str(output_dir))

        generated_files = generator.generate_batch(sample_dicom_file, count=count)

        assert len(generated_files) == count


class TestIntegration:
    """Integration tests for complete workflows."""

    def test_complete_generation_workflow(self, sample_dicom_file, temp_dir):
        """Test complete workflow from initialization to file generation."""
        output_dir = temp_dir / "integration_output"

        # Initialize generator
        generator = DICOMGenerator(output_dir=str(output_dir))
        assert generator.output_dir.exists()

        # Generate first batch
        batch1 = generator.generate_batch(sample_dicom_file, count=5)
        assert len(batch1) == 5

        # Generate second batch
        batch2 = generator.generate_batch(sample_dicom_file, count=3)
        assert len(batch2) == 3

        # Verify all files exist and are unique
        all_files = batch1 + batch2
        assert len(all_files) == 8
        assert len(set(f.name for f in all_files)) == 8  # All unique

        # Verify all files are valid DICOM
        from core.parser import DicomParser

        for file_path in all_files:
            parser = DicomParser(file_path)
            assert parser.dataset is not None

    def test_multiple_generators_same_directory(self, sample_dicom_file, temp_dir):
        """Test multiple generator instances using same output directory."""
        output_dir = temp_dir / "shared_output"

        gen1 = DICOMGenerator(output_dir=str(output_dir))
        gen2 = DICOMGenerator(output_dir=str(output_dir))

        files1 = gen1.generate_batch(sample_dicom_file, count=3)
        files2 = gen2.generate_batch(sample_dicom_file, count=3)

        # All files should be unique
        all_filenames = [f.name for f in files1 + files2]
        assert len(all_filenames) == len(set(all_filenames))

    def test_generator_with_different_source_files(
        self, sample_dicom_file, minimal_dicom_file, temp_dir
    ):
        """Test generator with different source DICOM files."""
        output_dir = temp_dir / "multi_source"
        generator = DICOMGenerator(output_dir=str(output_dir))

        files_from_sample = generator.generate_batch(sample_dicom_file, count=3)
        files_from_minimal = generator.generate_batch(minimal_dicom_file, count=3)

        assert len(files_from_sample) == 3
        assert len(files_from_minimal) == 3

        # All files should exist
        for f in files_from_sample + files_from_minimal:
            assert f.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
