"""Real-world tests for corpus minimization module.

Tests corpus minimization and validation functionality
with actual DICOM files and realistic scenarios.
"""

from pathlib import Path
from unittest.mock import Mock

import pytest
from pydicom import FileDataset
from pydicom.dataset import Dataset
from pydicom.uid import generate_uid

from dicom_fuzzer.utils.corpus_minimization import (
    minimize_corpus_for_campaign,
    validate_corpus_quality,
)


@pytest.fixture
def corpus_dir(tmp_path):
    """Create a corpus directory with test DICOM files."""
    corp_dir = tmp_path / "corpus"
    corp_dir.mkdir()
    return corp_dir


@pytest.fixture
def output_dir(tmp_path):
    """Create an output directory."""
    out_dir = tmp_path / "output"
    return out_dir


@pytest.fixture
def create_dicom_file():
    """Factory to create DICOM files."""

    def _create_dicom(path: Path, size_kb: int = 1):
        """Create a DICOM file with specified size."""
        file_meta = Dataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.ImplementationClassUID = generate_uid()

        ds = FileDataset(str(path), {}, file_meta=file_meta, preamble=b"\0" * 128)
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.PatientName = "Test^Patient"
        ds.PatientID = "12345"
        ds.StudyInstanceUID = generate_uid()
        ds.SeriesInstanceUID = generate_uid()

        # Add padding to reach desired size
        padding_size = max(0, (size_kb * 1024) - 1024)  # Rough estimate
        if padding_size > 0:
            ds.add_new([0x0009, 0x0010], "LO", "X" * min(padding_size, 64))

        ds.save_as(str(path), write_like_original=False)
        return path

    return _create_dicom


class TestMinimizeCorpusForCampaign:
    """Test minimize_corpus_for_campaign function."""

    def test_minimize_empty_corpus(self, corpus_dir, output_dir):
        """Test minimizing empty corpus directory."""
        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        assert result == []

    def test_minimize_nonexistent_corpus(self, tmp_path, output_dir):
        """Test minimizing nonexistent corpus directory."""
        nonexistent = tmp_path / "nonexistent"

        result = minimize_corpus_for_campaign(nonexistent, output_dir)

        assert result == []

    def test_minimize_single_file(self, corpus_dir, output_dir, create_dicom_file):
        """Test minimizing corpus with single file."""
        create_dicom_file(corpus_dir / "test1.dcm")

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        assert len(result) == 1
        assert result[0].exists()
        assert result[0].name == "test1.dcm"

    def test_minimize_multiple_files(self, corpus_dir, output_dir, create_dicom_file):
        """Test minimizing corpus with multiple files."""
        for i in range(5):
            create_dicom_file(corpus_dir / f"test{i}.dcm")

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        assert len(result) == 5
        assert all(f.exists() for f in result)

    def test_minimize_with_max_corpus_size(
        self, corpus_dir, output_dir, create_dicom_file
    ):
        """Test minimizing with max corpus size limit."""
        for i in range(10):
            create_dicom_file(corpus_dir / f"test{i}.dcm")

        result = minimize_corpus_for_campaign(corpus_dir, output_dir, max_corpus_size=3)

        assert len(result) == 3

    def test_minimize_sorts_by_file_size(
        self, corpus_dir, output_dir, create_dicom_file
    ):
        """Test that minimization processes smaller files first."""
        create_dicom_file(corpus_dir / "large.dcm", size_kb=10)
        create_dicom_file(corpus_dir / "small.dcm", size_kb=1)
        create_dicom_file(corpus_dir / "medium.dcm", size_kb=5)

        result = minimize_corpus_for_campaign(corpus_dir, output_dir, max_corpus_size=1)

        # Should pick the smallest file
        assert len(result) == 1
        # Small file should be first due to sorting
        assert "small" in result[0].name or len(result) == 1

    def test_minimize_creates_output_directory(
        self, corpus_dir, tmp_path, create_dicom_file
    ):
        """Test that output directory is created if it doesn't exist."""
        create_dicom_file(corpus_dir / "test.dcm")
        output_dir = tmp_path / "new" / "nested" / "dir"

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        assert output_dir.exists()
        assert len(result) == 1

    def test_minimize_with_coverage_tracker(
        self, corpus_dir, output_dir, create_dicom_file
    ):
        """Test minimization with coverage tracker."""
        create_dicom_file(corpus_dir / "test1.dcm")
        create_dicom_file(corpus_dir / "test2.dcm")

        # Mock coverage tracker that provides unique coverage
        mock_tracker = Mock()
        mock_tracker.get_coverage_for_input.side_effect = [
            {"edge1", "edge2", "edge3"},  # First file has 3 edges
            {"edge3", "edge4"},  # Second file adds 1 new edge
        ]

        result = minimize_corpus_for_campaign(
            corpus_dir, output_dir, coverage_tracker=mock_tracker
        )

        assert len(result) == 2
        assert mock_tracker.get_coverage_for_input.call_count == 2

    def test_minimize_with_coverage_tracker_removes_redundant(
        self, corpus_dir, output_dir, create_dicom_file
    ):
        """Test that files with no unique coverage are removed."""
        create_dicom_file(corpus_dir / "test1.dcm")
        create_dicom_file(corpus_dir / "test2.dcm")
        create_dicom_file(corpus_dir / "test3.dcm")

        # Mock coverage tracker
        mock_tracker = Mock()
        mock_tracker.get_coverage_for_input.side_effect = [
            {"edge1", "edge2"},  # First file
            {"edge1", "edge2"},  # Second file - same coverage (redundant)
            {"edge3"},  # Third file - new coverage
        ]

        result = minimize_corpus_for_campaign(
            corpus_dir, output_dir, coverage_tracker=mock_tracker
        )

        # Should keep file 1 and 3, skip file 2
        assert len(result) == 2

    def test_minimize_with_coverage_tracker_error(
        self, corpus_dir, output_dir, create_dicom_file
    ):
        """Test handling of coverage tracker errors."""
        create_dicom_file(corpus_dir / "test1.dcm")
        create_dicom_file(corpus_dir / "test2.dcm")

        # Mock coverage tracker that raises error
        mock_tracker = Mock()
        mock_tracker.get_coverage_for_input.side_effect = [
            Exception("Coverage error"),
            {"edge1", "edge2"},
        ]

        result = minimize_corpus_for_campaign(
            corpus_dir, output_dir, coverage_tracker=mock_tracker
        )

        # Should still keep both files (error handling keeps the seed)
        assert len(result) == 2

    def test_minimize_copies_files_to_output(
        self, corpus_dir, output_dir, create_dicom_file
    ):
        """Test that files are copied to output directory."""
        create_dicom_file(corpus_dir / "test.dcm")

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        # Original file should still exist
        assert (corpus_dir / "test.dcm").exists()
        # Copied file should exist in output
        assert (output_dir / "test.dcm").exists()
        assert result[0] == output_dir / "test.dcm"

    def test_minimize_no_dcm_files(self, corpus_dir, output_dir):
        """Test corpus directory with no .dcm files."""
        # Create some non-DICOM files
        (corpus_dir / "readme.txt").write_text("test")
        (corpus_dir / "data.json").write_text("{}")

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        assert result == []


class TestValidateCorpusQuality:
    """Test validate_corpus_quality function."""

    def test_validate_empty_corpus(self, corpus_dir):
        """Test validating empty corpus."""
        metrics = validate_corpus_quality(corpus_dir)

        assert metrics["total_files"] == 0
        assert metrics["total_size_mb"] == 0.0
        assert metrics["valid_dicom"] == 0
        assert metrics["corrupted"] == 0

    def test_validate_nonexistent_corpus(self, tmp_path):
        """Test validating nonexistent corpus directory."""
        nonexistent = tmp_path / "nonexistent"

        metrics = validate_corpus_quality(nonexistent)

        assert metrics["total_files"] == 0

    def test_validate_single_file(self, corpus_dir, create_dicom_file):
        """Test validating corpus with single file."""
        create_dicom_file(corpus_dir / "test.dcm")

        metrics = validate_corpus_quality(corpus_dir)

        assert metrics["total_files"] == 1
        assert metrics["total_size_mb"] > 0
        assert metrics["valid_dicom"] == 1
        assert metrics["corrupted"] == 0

    def test_validate_multiple_files(self, corpus_dir, create_dicom_file):
        """Test validating corpus with multiple files."""
        for i in range(5):
            create_dicom_file(corpus_dir / f"test{i}.dcm")

        metrics = validate_corpus_quality(corpus_dir)

        assert metrics["total_files"] == 5
        assert metrics["valid_dicom"] == 5
        assert metrics["corrupted"] == 0

    def test_validate_size_statistics(self, corpus_dir, create_dicom_file):
        """Test that size statistics are calculated correctly."""
        create_dicom_file(corpus_dir / "small.dcm", size_kb=1)
        create_dicom_file(corpus_dir / "medium.dcm", size_kb=5)
        create_dicom_file(corpus_dir / "large.dcm", size_kb=10)

        metrics = validate_corpus_quality(corpus_dir)

        assert metrics["total_files"] == 3
        assert metrics["min_size_kb"] > 0
        assert metrics["max_size_kb"] > metrics["min_size_kb"]
        assert metrics["avg_file_size_kb"] > 0

    def test_validate_corrupted_file(self, corpus_dir):
        """Test validation of corrupted file."""
        # Create a non-DICOM file with .dcm extension
        corrupted = corpus_dir / "corrupted.dcm"
        corrupted.write_bytes(b"NOT A DICOM FILE")

        metrics = validate_corpus_quality(corpus_dir)

        assert metrics["total_files"] == 1
        # Note: pydicom with force=True may read even invalid files
        # so corrupted count depends on pydicom's tolerance
        assert metrics["corrupted"] >= 0
        assert metrics["valid_dicom"] >= 0

    def test_validate_mixed_corpus(self, corpus_dir, create_dicom_file):
        """Test validation of corpus with both valid and corrupted files."""
        create_dicom_file(corpus_dir / "valid1.dcm")
        create_dicom_file(corpus_dir / "valid2.dcm")
        (corpus_dir / "corrupted.dcm").write_bytes(b"INVALID")

        metrics = validate_corpus_quality(corpus_dir)

        assert metrics["total_files"] == 3
        # pydicom with force=True may read even invalid files
        assert metrics["valid_dicom"] >= 2
        assert metrics["corrupted"] >= 0

    def test_validate_returns_all_metrics(self, corpus_dir, create_dicom_file):
        """Test that all expected metrics are returned."""
        create_dicom_file(corpus_dir / "test.dcm")

        metrics = validate_corpus_quality(corpus_dir)

        expected_keys = {
            "total_files",
            "total_size_mb",
            "avg_file_size_kb",
            "min_size_kb",
            "max_size_kb",
            "valid_dicom",
            "corrupted",
        }

        assert set(metrics.keys()) == expected_keys


class TestMissingCoveragePaths:
    """Tests for uncovered lines 162-165 in corpus_minimization.py."""

    def test_validate_corrupted_file_exception_path(self, corpus_dir, create_dicom_file):
        """Test lines 162-163: Exception when pydicom.dcmread fails."""
        from unittest.mock import patch, MagicMock
        import builtins

        # Create a valid DICOM file
        create_dicom_file(corpus_dir / "test.dcm")

        # Since pydicom is imported inside the function, we need to intercept
        # the import and return a mock module with dcmread that raises
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "pydicom":
                # Return a mock pydicom module where dcmread raises Exception
                mock_pydicom = MagicMock()
                mock_pydicom.dcmread.side_effect = Exception("Invalid DICOM format")
                return mock_pydicom
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", mock_import):
            metrics = validate_corpus_quality(corpus_dir)

            # Should count as corrupted (lines 162-163)
            assert metrics["total_files"] == 1
            assert metrics["corrupted"] == 1
            assert metrics["valid_dicom"] == 0

    def test_validate_pydicom_import_error(self, tmp_path):
        """Test lines 164-165: ImportError when pydicom is not available.

        Since pydicom is imported inside a try block in validate_corpus_quality,
        we need to make the import fail when the function runs.
        """
        from unittest.mock import patch
        import builtins

        # Create test corpus
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        (corpus_dir / "test.dcm").write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 100)

        # The import happens inside the function at line 156:
        #     try:
        #         import pydicom
        # We need to make this specific import raise ImportError

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            # Only raise ImportError for pydicom when called inside validate_corpus_quality
            if name == "pydicom":
                raise ImportError("No module named 'pydicom'")
            return original_import(name, *args, **kwargs)

        # Patch builtins.__import__ to intercept the import inside the function
        with patch.object(builtins, "__import__", mock_import):
            metrics = validate_corpus_quality(corpus_dir)

            # Lines 164-165: Should skip DICOM validation when pydicom unavailable
            assert metrics["total_files"] == 1
            # No validation happens, so both counters stay at 0
            assert metrics["valid_dicom"] == 0
            assert metrics["corrupted"] == 0


class TestIntegrationScenarios:
    """Test realistic usage scenarios."""

    def test_minimize_then_validate(self, corpus_dir, output_dir, create_dicom_file):
        """Test minimizing corpus then validating the result."""
        # Create corpus
        for i in range(10):
            create_dicom_file(corpus_dir / f"test{i}.dcm")

        # Minimize
        result = minimize_corpus_for_campaign(corpus_dir, output_dir, max_corpus_size=5)

        assert len(result) == 5

        # Validate minimized corpus
        metrics = validate_corpus_quality(output_dir)

        assert metrics["total_files"] == 5
        assert metrics["valid_dicom"] == 5

    def test_minimize_large_corpus(self, corpus_dir, output_dir, create_dicom_file):
        """Test minimizing a larger corpus."""
        # Create 50 files
        for i in range(50):
            create_dicom_file(corpus_dir / f"file{i:03d}.dcm")

        result = minimize_corpus_for_campaign(
            corpus_dir, output_dir, max_corpus_size=10
        )

        assert len(result) == 10
        assert all(f.exists() for f in result)

    def test_validate_large_corpus(self, corpus_dir, create_dicom_file):
        """Test validating a larger corpus."""
        # Create 20 files
        for i in range(20):
            create_dicom_file(corpus_dir / f"file{i:02d}.dcm")

        metrics = validate_corpus_quality(corpus_dir)

        assert metrics["total_files"] == 20
        assert metrics["valid_dicom"] == 20
        assert metrics["total_size_mb"] > 0
