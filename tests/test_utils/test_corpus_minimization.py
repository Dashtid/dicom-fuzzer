"""Tests for Corpus Minimization Utility.

Tests for corpus optimization and minimization functions.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.utils.corpus_minimization import (
    OVERLAY_GROUP_END,
    OVERLAY_GROUP_START,
    STRIP_TAGS,
    MoonLightMinimizer,
    minimize_corpus_for_campaign,
    optimize_corpus,
    strip_pixel_data,
)


class TestStripTags:
    """Test STRIP_TAGS configuration."""

    def test_strip_tags_contains_pixel_data(self):
        """Test that PixelData tag is in strip list."""
        assert (0x7FE0, 0x0010) in STRIP_TAGS

    def test_strip_tags_contains_float_pixel_data(self):
        """Test that FloatPixelData tag is in strip list."""
        assert (0x7FE0, 0x0008) in STRIP_TAGS

    def test_strip_tags_contains_waveform_data(self):
        """Test that WaveformData tag is in strip list."""
        assert (0x5400, 0x0100) in STRIP_TAGS

    def test_overlay_group_range(self):
        """Test overlay group range is valid."""
        assert OVERLAY_GROUP_START == 0x6000
        assert OVERLAY_GROUP_END == 0x601E


class TestStripPixelData:
    """Test strip_pixel_data function."""

    @pytest.fixture
    def temp_dirs(self, tmp_path):
        """Create temp directories for input/output."""
        input_dir = tmp_path / "input"
        output_dir = tmp_path / "output"
        input_dir.mkdir()
        output_dir.mkdir()
        return input_dir, output_dir

    @pytest.fixture
    def sample_dicom_file(self, temp_dirs):
        """Create a sample DICOM file with pydicom."""
        input_dir, _ = temp_dirs
        filepath = input_dir / "test.dcm"

        try:
            import numpy as np
            from pydicom.dataset import FileDataset, FileMetaDataset
            from pydicom.uid import UID

            file_meta = FileMetaDataset()
            file_meta.MediaStorageSOPClassUID = UID("1.2.840.10008.5.1.4.1.1.2")
            file_meta.MediaStorageSOPInstanceUID = UID("1.2.3.4.5.6.7.8.9")
            file_meta.TransferSyntaxUID = UID("1.2.840.10008.1.2.1")

            ds = FileDataset(
                str(filepath),
                {},
                file_meta=file_meta,
                preamble=b"\x00" * 128,
            )

            ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
            ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
            ds.Modality = "CT"
            ds.Rows = 64
            ds.Columns = 64
            ds.BitsAllocated = 16
            ds.BitsStored = 12
            ds.HighBit = 11
            ds.PixelRepresentation = 0
            ds.SamplesPerPixel = 1
            ds.PhotometricInterpretation = "MONOCHROME2"

            # Add PixelData (this is what we want to strip)
            pixel_data = np.zeros((64, 64), dtype=np.uint16)
            ds.PixelData = pixel_data.tobytes()

            ds.save_as(str(filepath))
            return filepath

        except ImportError:
            pytest.skip("pydicom or numpy not available")

    def test_strip_pixel_data_success(self, sample_dicom_file, temp_dirs):
        """Test successful pixel data stripping."""
        _, output_dir = temp_dirs
        output_file = output_dir / "stripped.dcm"

        success, bytes_saved = strip_pixel_data(sample_dicom_file, output_file)

        assert success is True
        assert bytes_saved > 0
        assert output_file.exists()
        # Output should be smaller than input
        assert output_file.stat().st_size < sample_dicom_file.stat().st_size

    def test_strip_pixel_data_output_missing_parent(self, sample_dicom_file, tmp_path):
        """Test that output parent directory is created."""
        output_file = tmp_path / "new_dir" / "subdir" / "output.dcm"

        success, _ = strip_pixel_data(sample_dicom_file, output_file)

        assert success is True
        assert output_file.exists()

    def test_strip_pixel_data_invalid_file(self, temp_dirs):
        """Test stripping from invalid file falls back to copy."""
        input_dir, output_dir = temp_dirs
        input_file = input_dir / "invalid.dcm"
        input_file.write_bytes(b"not a dicom file")
        output_file = output_dir / "output.dcm"

        success, bytes_saved = strip_pixel_data(input_file, output_file)

        # Should fall back to copy
        assert success is True
        assert bytes_saved == 0
        assert output_file.exists()

    def test_strip_pixel_data_nonexistent_file(self, temp_dirs):
        """Test stripping from non-existent file."""
        _, output_dir = temp_dirs
        input_file = Path("/nonexistent/file.dcm")
        output_file = output_dir / "output.dcm"

        success, bytes_saved = strip_pixel_data(input_file, output_file)

        assert success is False
        assert bytes_saved == 0


class TestOptimizeCorpus:
    """Test optimize_corpus function."""

    @pytest.fixture
    def corpus_dir(self, tmp_path):
        """Create a corpus directory with DICOM files."""
        corpus = tmp_path / "corpus"
        corpus.mkdir()

        # Create some dummy DICOM files
        for i in range(3):
            dcm_file = corpus / f"test_{i}.dcm"
            # Write minimal valid-ish DICOM
            dcm_file.write_bytes(b"\x00" * 128 + b"DICM" + b"\x00" * 1000)

        return corpus

    def test_optimize_corpus_basic(self, corpus_dir, tmp_path):
        """Test basic corpus optimization."""
        output_dir = tmp_path / "output"

        stats = optimize_corpus(corpus_dir, output_dir)

        assert stats["files_processed"] == 3
        assert "original_size_mb" in stats
        assert "optimized_size_mb" in stats

    def test_optimize_corpus_dry_run(self, corpus_dir, tmp_path):
        """Test dry run mode doesn't write files."""
        output_dir = tmp_path / "output"

        stats = optimize_corpus(corpus_dir, output_dir, dry_run=True)

        assert stats["files_processed"] == 3
        assert not output_dir.exists()

    def test_optimize_corpus_empty_dir(self, tmp_path):
        """Test optimization of empty directory."""
        corpus_dir = tmp_path / "empty"
        corpus_dir.mkdir()
        output_dir = tmp_path / "output"

        stats = optimize_corpus(corpus_dir, output_dir)

        assert stats["files_processed"] == 0
        assert stats["files_optimized"] == 0

    def test_optimize_corpus_nonexistent_dir(self, tmp_path):
        """Test optimization of non-existent directory."""
        corpus_dir = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"

        stats = optimize_corpus(corpus_dir, output_dir)

        assert stats["files_processed"] == 0

    def test_optimize_corpus_no_stripping(self, corpus_dir, tmp_path):
        """Test optimization with all stripping disabled."""
        output_dir = tmp_path / "output"

        stats = optimize_corpus(
            corpus_dir,
            output_dir,
            strip_pixels=False,
            strip_overlays=False,
            strip_waveforms=False,
        )

        assert stats["files_processed"] == 3
        assert stats["bytes_saved"] == 0


class TestMinimizeCorpusForCampaign:
    """Test minimize_corpus_for_campaign function."""

    @pytest.fixture
    def seed_corpus(self, tmp_path):
        """Create a seed corpus directory."""
        corpus = tmp_path / "seeds"
        corpus.mkdir()

        # Create seeds of varying sizes
        for i, size in enumerate([100, 500, 1000, 2000, 5000]):
            seed = corpus / f"seed_{i}.dcm"
            seed.write_bytes(b"D" * size)

        return corpus

    def test_minimize_corpus_basic(self, seed_corpus, tmp_path):
        """Test basic corpus minimization."""
        output_dir = tmp_path / "minimized"

        result = minimize_corpus_for_campaign(seed_corpus, output_dir)

        assert len(result) > 0
        assert output_dir.exists()
        # All original seeds should be kept (no coverage tracker)
        assert len(result) == 5

    def test_minimize_corpus_with_max_size(self, seed_corpus, tmp_path):
        """Test minimization with max corpus size."""
        output_dir = tmp_path / "minimized"

        result = minimize_corpus_for_campaign(
            seed_corpus, output_dir, max_corpus_size=3
        )

        assert len(result) <= 3

    def test_minimize_corpus_sorted_by_size(self, seed_corpus, tmp_path):
        """Test that seeds are sorted by size."""
        output_dir = tmp_path / "minimized"

        result = minimize_corpus_for_campaign(
            seed_corpus, output_dir, max_corpus_size=2
        )

        # Should keep the 2 smallest seeds
        assert len(result) == 2
        sizes = [f.stat().st_size for f in result]
        assert sizes == sorted(sizes)

    def test_minimize_corpus_nonexistent_dir(self, tmp_path):
        """Test minimization of non-existent directory."""
        corpus_dir = tmp_path / "nonexistent"
        output_dir = tmp_path / "output"

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        assert result == []

    def test_minimize_corpus_empty_dir(self, tmp_path):
        """Test minimization of empty directory."""
        corpus_dir = tmp_path / "empty"
        corpus_dir.mkdir()
        output_dir = tmp_path / "output"

        result = minimize_corpus_for_campaign(corpus_dir, output_dir)

        assert result == []

    def test_minimize_corpus_with_coverage_tracker(self, seed_corpus, tmp_path):
        """Test minimization with mock coverage tracker."""
        output_dir = tmp_path / "minimized"

        # Mock coverage tracker that reports different coverage per seed
        mock_tracker = MagicMock()
        coverage_sets = [
            {"edge1", "edge2"},
            {"edge1", "edge3"},  # edge1 is duplicate
            {"edge4", "edge5"},
            {"edge1", "edge2"},  # All duplicates
            {"edge6"},
        ]
        mock_tracker.get_coverage_for_input.side_effect = coverage_sets

        result = minimize_corpus_for_campaign(
            seed_corpus, output_dir, coverage_tracker=mock_tracker
        )

        # Seeds with unique coverage should be kept
        assert len(result) < 5


class TestMoonLightMinimizer:
    """Test MoonLightMinimizer class."""

    @pytest.fixture
    def minimizer(self):
        """Create a MoonLightMinimizer instance."""
        return MoonLightMinimizer(
            weight_by_size=True, weight_by_time=True, size_weight=0.5, time_weight=0.5
        )

    @pytest.fixture
    def seed_files(self, tmp_path):
        """Create seed files for testing."""
        seeds = []
        # Use sizes > 1KB to ensure weight differentiation
        for i, size in enumerate([2000, 10000, 50000]):
            seed = tmp_path / f"seed_{i}.dcm"
            seed.write_bytes(b"S" * size)
            seeds.append(seed)
        return seeds

    def test_init_default_values(self):
        """Test default initialization values."""
        minimizer = MoonLightMinimizer()
        assert minimizer.weight_by_size is True
        assert minimizer.weight_by_time is True
        assert minimizer.size_weight == 0.5
        assert minimizer.time_weight == 0.5

    def test_init_custom_values(self):
        """Test custom initialization values."""
        minimizer = MoonLightMinimizer(
            weight_by_size=False, weight_by_time=False, size_weight=0.3, time_weight=0.7
        )
        assert minimizer.weight_by_size is False
        assert minimizer.weight_by_time is False
        assert minimizer.size_weight == 0.3
        assert minimizer.time_weight == 0.7

    def test_compute_seed_weight_size_only(self, seed_files):
        """Test seed weight computation based on size."""
        minimizer = MoonLightMinimizer(weight_by_size=True, weight_by_time=False)

        weights = [minimizer.compute_seed_weight(seed) for seed in seed_files]

        # Larger files should have higher weights
        assert weights[0] < weights[1] < weights[2]

    def test_compute_seed_weight_with_time(self, seed_files):
        """Test seed weight computation including execution time."""
        minimizer = MoonLightMinimizer(weight_by_size=False, weight_by_time=True)

        # Set execution times
        minimizer.set_execution_time(seed_files[0], 0.1)
        minimizer.set_execution_time(seed_files[1], 0.5)
        minimizer.set_execution_time(seed_files[2], 1.0)

        weights = [minimizer.compute_seed_weight(seed) for seed in seed_files]

        # Seeds with longer execution time should have higher weights
        assert weights[0] < weights[1] < weights[2]

    def test_get_coverage_default(self, seed_files, minimizer):
        """Test default coverage (hash-based)."""
        coverage = minimizer.get_coverage(seed_files[0])

        assert isinstance(coverage, set)
        assert len(coverage) == 1
        # Coverage should be hash-based
        assert any(cov.startswith("hash:") for cov in coverage)

    def test_get_coverage_cached(self, seed_files, minimizer):
        """Test coverage caching."""
        coverage1 = minimizer.get_coverage(seed_files[0])
        coverage2 = minimizer.get_coverage(seed_files[0])

        assert coverage1 == coverage2
        assert coverage1 is coverage2  # Same object (cached)

    def test_set_coverage(self, seed_files, minimizer):
        """Test setting custom coverage."""
        custom_coverage = {"edge1", "edge2", "edge3"}
        minimizer.set_coverage(seed_files[0], custom_coverage)

        result = minimizer.get_coverage(seed_files[0])
        assert result == custom_coverage

    def test_set_execution_time(self, seed_files, minimizer):
        """Test setting execution time."""
        minimizer.set_execution_time(seed_files[0], 0.5)
        assert minimizer._time_cache[seed_files[0]] == 0.5

    def test_minimize_empty_list(self, minimizer):
        """Test minimization of empty seed list."""
        result = minimizer.minimize([])
        assert result == []

    def test_minimize_single_seed(self, seed_files, minimizer):
        """Test minimization with single seed."""
        result = minimizer.minimize([seed_files[0]])
        assert len(result) == 1
        assert result[0] == seed_files[0]

    def test_minimize_removes_duplicates(self, seed_files, minimizer):
        """Test that minimization removes duplicate coverage."""
        # Set same coverage for all seeds
        same_coverage = {"edge1", "edge2"}
        for seed in seed_files:
            minimizer.set_coverage(seed, same_coverage)

        result = minimizer.minimize(seed_files)

        # Only one seed should be kept
        assert len(result) == 1

    def test_minimize_keeps_unique_coverage(self, seed_files, minimizer):
        """Test that minimization keeps seeds with unique coverage."""
        # Set different coverage for each seed
        minimizer.set_coverage(seed_files[0], {"edge1", "edge2"})
        minimizer.set_coverage(seed_files[1], {"edge3", "edge4"})
        minimizer.set_coverage(seed_files[2], {"edge5", "edge6"})

        result = minimizer.minimize(seed_files)

        # All seeds should be kept (unique coverage)
        assert len(result) == 3

    def test_minimize_with_overlapping_coverage(self, seed_files, minimizer):
        """Test minimization with overlapping coverage."""
        # Seed 0 covers edges 1-4
        minimizer.set_coverage(seed_files[0], {"edge1", "edge2", "edge3", "edge4"})
        # Seed 1 covers edges 1-2 only (subset)
        minimizer.set_coverage(seed_files[1], {"edge1", "edge2"})
        # Seed 2 covers edges 5-6 (unique)
        minimizer.set_coverage(seed_files[2], {"edge5", "edge6"})

        result = minimizer.minimize(seed_files)

        # Seed 1 should be removed (coverage is subset of seed 0)
        assert len(result) == 2

    def test_minimize_with_target_coverage(self, seed_files, minimizer):
        """Test minimization with specific target coverage."""
        # Seed 0 covers target edge1
        minimizer.set_coverage(seed_files[0], {"edge1"})
        # Seed 1 covers target edge3
        minimizer.set_coverage(seed_files[1], {"edge3"})
        # Seed 2 has no target coverage (won't be selected)
        minimizer.set_coverage(seed_files[2], {"edge5", "edge6"})

        # Only target edge1 and edge3
        target = {"edge1", "edge3"}
        result = minimizer.minimize(seed_files, target_coverage=target)

        # Should keep exactly the 2 seeds that cover the target
        assert len(result) == 2
        assert seed_files[0] in result
        assert seed_files[1] in result

    def test_minimize_corpus_dir_empty(self, minimizer, tmp_path):
        """Test minimizing empty directory."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        output_dir = tmp_path / "output"

        stats = minimizer.minimize_corpus_dir(corpus_dir, output_dir)

        assert stats["original_count"] == 0
        assert stats["minimized_count"] == 0

    def test_minimize_corpus_dir_basic(self, minimizer, tmp_path):
        """Test basic directory minimization."""
        corpus_dir = tmp_path / "corpus"
        corpus_dir.mkdir()
        output_dir = tmp_path / "output"

        # Create test seeds
        for i in range(5):
            seed = corpus_dir / f"seed_{i}.dcm"
            seed.write_bytes(b"D" * (100 + i * 100))

        stats = minimizer.minimize_corpus_dir(corpus_dir, output_dir)

        assert stats["original_count"] == 5
        assert stats["minimized_count"] > 0
        assert stats["original_size_mb"] > 0


class TestMoonLightMinimizerWeighting:
    """Test weighting behavior in MoonLightMinimizer."""

    def test_prefers_smaller_files(self, tmp_path):
        """Test that minimizer prefers smaller files when size-weighted."""
        minimizer = MoonLightMinimizer(
            weight_by_size=True, weight_by_time=False, size_weight=1.0
        )

        # Create seeds with same coverage but different sizes
        small_seed = tmp_path / "small.dcm"
        large_seed = tmp_path / "large.dcm"
        small_seed.write_bytes(b"S" * 100)
        large_seed.write_bytes(b"L" * 10000)

        # Set same coverage
        coverage = {"edge1", "edge2"}
        minimizer.set_coverage(small_seed, coverage)
        minimizer.set_coverage(large_seed, coverage)

        result = minimizer.minimize([large_seed, small_seed])

        # Should prefer the smaller seed
        assert len(result) == 1
        assert result[0] == small_seed

    def test_prefers_faster_execution(self, tmp_path):
        """Test that minimizer prefers faster-executing seeds when time-weighted."""
        minimizer = MoonLightMinimizer(
            weight_by_size=False, weight_by_time=True, time_weight=1.0
        )

        # Create seeds with same size
        fast_seed = tmp_path / "fast.dcm"
        slow_seed = tmp_path / "slow.dcm"
        fast_seed.write_bytes(b"F" * 100)
        slow_seed.write_bytes(b"S" * 100)

        # Set execution times
        minimizer.set_execution_time(fast_seed, 0.01)
        minimizer.set_execution_time(slow_seed, 1.0)

        # Set same coverage
        coverage = {"edge1", "edge2"}
        minimizer.set_coverage(fast_seed, coverage)
        minimizer.set_coverage(slow_seed, coverage)

        result = minimizer.minimize([slow_seed, fast_seed])

        # Should prefer the faster seed
        assert len(result) == 1
        assert result[0] == fast_seed
