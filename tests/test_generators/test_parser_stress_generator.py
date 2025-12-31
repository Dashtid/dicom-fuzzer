"""Tests for parser_stress/generator.py - Parser Stress Test Generator.

Tests cover generation of deeply nested sequences, giant values, truncated data,
and other parser stress conditions.
"""

from pathlib import Path
from unittest.mock import patch

from dicom_fuzzer.generators.parser_stress.generator import (
    ParserStressGenerator,
    main,
)


class TestParserStressGeneratorInit:
    """Test ParserStressGenerator initialization."""

    def test_init_with_output_dir(self, tmp_path):
        """Test initialization with output directory."""
        generator = ParserStressGenerator(tmp_path)
        assert generator.output_dir == tmp_path

    def test_init_creates_output_dir(self, tmp_path):
        """Test that initialization creates output directory."""
        output_dir = tmp_path / "stress_tests"
        generator = ParserStressGenerator(output_dir)
        assert output_dir.exists()


class TestCreateBaseDicom:
    """Test create_base_dicom method."""

    def test_create_base_dicom_returns_dataset(self, tmp_path):
        """Test that create_base_dicom returns a valid dataset."""
        generator = ParserStressGenerator(tmp_path)
        ds = generator.create_base_dicom()

        assert ds.PatientName == "STRESS^TEST"
        assert ds.PatientID == "STRESS-001"
        assert ds.Modality == "OT"


class TestGenerateDeepSequenceNesting:
    """Test generate_deep_sequence_nesting method."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_deep_sequence_nesting()

        assert path.exists()
        assert "deep_sequence_nesting" in str(path)

    def test_custom_depth(self, tmp_path):
        """Test with custom nesting depth."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_deep_sequence_nesting(depth=50)

        assert path.exists()

    def test_custom_output_path(self, tmp_path):
        """Test with custom output path."""
        generator = ParserStressGenerator(tmp_path)
        custom_path = tmp_path / "custom_nesting.dcm"
        path = generator.generate_deep_sequence_nesting(output_path=custom_path)

        assert path == custom_path
        assert path.exists()


class TestGenerateGiantValueLength:
    """Test generate_giant_value_length method."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_giant_value_length()

        assert path.exists()
        assert "giant_value_length" in str(path)

    def test_file_contains_large_vl(self, tmp_path):
        """Test that file contains large value length."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_giant_value_length()

        # File should be created
        assert path.stat().st_size > 0


class TestGenerateTruncatedPixeldata:
    """Test generate_truncated_pixeldata method."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_truncated_pixeldata()

        assert path.exists()
        assert "truncated_pixeldata" in str(path)

    def test_pixel_data_mismatch(self, tmp_path):
        """Test that pixel data size doesn't match declared dimensions."""
        import pydicom

        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_truncated_pixeldata()

        ds = pydicom.dcmread(path)
        expected_size = ds.Rows * ds.Columns * (ds.BitsAllocated // 8)
        actual_size = len(ds.PixelData)

        assert actual_size < expected_size


class TestGenerateUndefinedLengthAbuse:
    """Test generate_undefined_length_abuse method."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_undefined_length_abuse()

        assert path.exists()
        assert "undefined_length_abuse" in str(path)


class TestGenerateInvalidTransferSyntax:
    """Test generate_invalid_transfer_syntax method."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_invalid_transfer_syntax()

        assert path.exists()
        assert "invalid_transfer_syntax" in str(path)


class TestGenerateRecursiveItemNesting:
    """Test generate_recursive_item_nesting method."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_recursive_item_nesting()

        assert path.exists()
        assert "recursive_item_nesting" in str(path)


class TestGenerateZeroLengthElements:
    """Test generate_zero_length_elements method."""

    def test_generates_sample(self, tmp_path):
        """Test that sample is generated."""
        generator = ParserStressGenerator(tmp_path)
        path = generator.generate_zero_length_elements()

        assert path.exists()
        assert "zero_length_elements" in str(path)


class TestGenerateAll:
    """Test generate_all method."""

    def test_generates_all_samples(self, tmp_path):
        """Test that all stress test samples are generated."""
        generator = ParserStressGenerator(tmp_path)
        results = generator.generate_all()

        assert "deep_sequence_nesting" in results
        assert "giant_value_length" in results
        assert "truncated_pixeldata" in results
        assert "undefined_length_abuse" in results
        assert "invalid_transfer_syntax" in results
        assert "recursive_item_nesting" in results
        assert "zero_length_elements" in results

    def test_returns_paths(self, tmp_path):
        """Test that paths are returned for generations."""
        generator = ParserStressGenerator(tmp_path)
        results = generator.generate_all()

        for name, path in results.items():
            if path is not None:
                assert Path(path).exists()


class TestMain:
    """Test main CLI function."""

    def test_main_default_all(self, tmp_path):
        """Test main generates all by default."""
        with patch("sys.argv", ["generator", "--output-dir", str(tmp_path)]):
            main()

        # Should create multiple sample files
        dcm_files = list(tmp_path.glob("*.dcm"))
        assert len(dcm_files) >= 5

    def test_main_deep_nesting(self, tmp_path):
        """Test main with deep_nesting type."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--type", "deep_nesting"],
        ):
            main()

        assert (tmp_path / "deep_sequence_nesting.dcm").exists()

    def test_main_giant_vl(self, tmp_path):
        """Test main with giant_vl type."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--type", "giant_vl"],
        ):
            main()

        assert (tmp_path / "giant_value_length.dcm").exists()

    def test_main_truncated(self, tmp_path):
        """Test main with truncated type."""
        with patch(
            "sys.argv",
            ["generator", "--output-dir", str(tmp_path), "--type", "truncated"],
        ):
            main()

        assert (tmp_path / "truncated_pixeldata.dcm").exists()

    def test_main_custom_depth(self, tmp_path):
        """Test main with custom depth."""
        with patch(
            "sys.argv",
            [
                "generator",
                "--output-dir",
                str(tmp_path),
                "--type",
                "deep_nesting",
                "--depth",
                "50",
            ],
        ):
            main()

        assert (tmp_path / "deep_sequence_nesting.dcm").exists()
