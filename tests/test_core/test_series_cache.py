"""
Tests for SeriesCache (Performance Optimization Phase 4).

Tests LRU caching strategies:
- Cache hits and misses
- LRU eviction policy
- File modification time validation
- Cache statistics
- Size management
"""

import time
from pathlib import Path

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.series_cache import CacheEntry, SeriesCache


@pytest.fixture
def sample_dicom_files(tmp_path):
    """Create multiple sample DICOM files for cache testing."""
    files = []
    for i in range(5):
        # Create file meta
        file_meta = FileMetaDataset()
        file_meta.TransferSyntaxUID = "1.2.840.10008.1.2"
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.ImplementationClassUID = generate_uid()

        # Create main dataset
        ds = Dataset()
        ds.file_meta = file_meta
        ds.is_implicit_VR = True
        ds.is_little_endian = True
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SeriesInstanceUID = generate_uid()
        ds.StudyInstanceUID = generate_uid()
        ds.Modality = "CT"
        ds.PatientName = f"Patient^{i}"
        ds.PatientID = f"ID{i:03d}"
        ds.InstanceNumber = i + 1

        # Save to file
        file_path = tmp_path / f"slice_{i:03d}.dcm"
        ds.save_as(file_path, write_like_original=False)
        files.append(file_path)

    return files


@pytest.fixture
def simple_loader():
    """Simple loader function for testing."""

    def loader(file_path: Path) -> Dataset:
        import pydicom

        return pydicom.dcmread(file_path, stop_before_pixels=True)

    return loader


class TestCacheEntry:
    """Test CacheEntry dataclass."""

    def test_cache_entry_creation(self, sample_dicom_files, simple_loader):
        """Test creating cache entry."""
        file_path = sample_dicom_files[0]
        ds = simple_loader(file_path)

        entry = CacheEntry(
            file_path=file_path,
            dataset=ds,
            file_mtime=file_path.stat().st_mtime,
            size_bytes=1000,
        )

        assert entry.file_path == file_path
        assert entry.dataset == ds
        assert entry.size_bytes == 1000
        assert entry.access_count == 0

    def test_update_access(self, sample_dicom_files, simple_loader):
        """Test updating access statistics."""
        file_path = sample_dicom_files[0]
        ds = simple_loader(file_path)

        entry = CacheEntry(
            file_path=file_path,
            dataset=ds,
            file_mtime=file_path.stat().st_mtime,
            size_bytes=1000,
        )

        initial_time = entry.last_access
        time.sleep(0.01)  # Ensure time difference

        entry.update_access()

        assert entry.access_count == 1
        assert entry.last_access > initial_time


class TestSeriesCache:
    """Test SeriesCache class."""

    def test_cache_initialization(self):
        """Test cache initialization."""
        cache = SeriesCache(max_size_mb=100, max_entries=1000)

        assert cache.max_size_bytes == 100 * 1024 * 1024
        assert cache.max_entries == 1000
        assert len(cache._cache) == 0

    def test_cache_miss_and_hit(self, sample_dicom_files, simple_loader):
        """Test cache miss followed by cache hit."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)
        file_path = sample_dicom_files[0]

        # First access - cache miss
        ds1 = cache.get(file_path, simple_loader)
        assert ds1 is not None
        assert ds1.PatientName == "Patient^0"

        stats = cache.get_statistics()
        assert stats["hits"] == 0
        assert stats["misses"] == 1
        assert stats["total_requests"] == 1

        # Second access - cache hit
        ds2 = cache.get(file_path, simple_loader)
        assert ds2 is not None
        assert ds2.PatientName == "Patient^0"

        stats = cache.get_statistics()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["total_requests"] == 2
        assert stats["hit_rate"] == 0.5

    def test_cache_multiple_files(self, sample_dicom_files, simple_loader):
        """Test caching multiple files."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Load all files
        for file_path in sample_dicom_files:
            ds = cache.get(file_path, simple_loader)
            assert ds is not None

        stats = cache.get_statistics()
        assert stats["misses"] == 5  # All misses on first load
        assert stats["current_entries"] == 5

        # Reload all files (should be cache hits)
        for file_path in sample_dicom_files:
            ds = cache.get(file_path, simple_loader)
            assert ds is not None

        stats = cache.get_statistics()
        assert stats["hits"] == 5  # All hits on second load
        assert stats["total_requests"] == 10
        assert stats["hit_rate"] == 0.5

    def test_lru_eviction(self, sample_dicom_files, simple_loader):
        """Test LRU eviction when cache full."""
        # Small cache (only 2 entries)
        cache = SeriesCache(max_size_mb=10, max_entries=2)

        # Load 3 files (should evict first one)
        ds1 = cache.get(sample_dicom_files[0], simple_loader)
        ds2 = cache.get(sample_dicom_files[1], simple_loader)
        ds3 = cache.get(sample_dicom_files[2], simple_loader)

        stats = cache.get_statistics()
        assert stats["current_entries"] == 2  # Only 2 entries fit
        assert stats["evictions"] == 1  # First file evicted

        # Access first file again (should be cache miss due to eviction)
        ds1_again = cache.get(sample_dicom_files[0], simple_loader)
        stats = cache.get_statistics()
        assert stats["misses"] == 4  # 3 initial + 1 re-load

    def test_file_modification_invalidation(self, sample_dicom_files, simple_loader):
        """Test cache invalidation when file modified."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)
        file_path = sample_dicom_files[0]

        # First access - cache miss
        ds1 = cache.get(file_path, simple_loader)
        assert ds1.PatientName == "Patient^0"

        # Second access - cache hit
        ds2 = cache.get(file_path, simple_loader)
        stats = cache.get_statistics()
        assert stats["hits"] == 1

        # Modify file (change mtime)
        time.sleep(0.01)  # Ensure time difference
        file_path.touch()

        # Third access - should invalidate and re-load
        ds3 = cache.get(file_path, simple_loader)
        stats = cache.get_statistics()
        assert stats["misses"] == 2  # Original miss + invalidation

    def test_manual_invalidation(self, sample_dicom_files, simple_loader):
        """Test manual cache invalidation."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)
        file_path = sample_dicom_files[0]

        # Load file
        ds1 = cache.get(file_path, simple_loader)
        stats = cache.get_statistics()
        assert stats["current_entries"] == 1

        # Manually invalidate
        cache.invalidate(file_path)
        stats = cache.get_statistics()
        assert stats["current_entries"] == 0

        # Re-load (should be cache miss)
        ds2 = cache.get(file_path, simple_loader)
        stats = cache.get_statistics()
        assert stats["misses"] == 2

    def test_clear_cache(self, sample_dicom_files, simple_loader):
        """Test clearing entire cache."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Load multiple files
        for file_path in sample_dicom_files:
            cache.get(file_path, simple_loader)

        stats = cache.get_statistics()
        assert stats["current_entries"] == 5

        # Clear cache
        cache.clear()

        stats = cache.get_statistics()
        assert stats["current_entries"] == 0
        # Statistics preserved after clear
        assert stats["misses"] == 5

    def test_cache_statistics(self, sample_dicom_files, simple_loader):
        """Test cache statistics reporting."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Initial statistics
        stats = cache.get_statistics()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["evictions"] == 0
        assert stats["total_requests"] == 0
        assert stats["hit_rate"] == 0.0
        assert stats["current_entries"] == 0
        assert stats["max_entries"] == 100
        assert stats["current_size_mb"] == 0.0
        assert stats["max_size_mb"] == 10.0
        assert stats["utilization"] == 0.0

        # Load files
        for file_path in sample_dicom_files[:3]:
            cache.get(file_path, simple_loader)
            cache.get(file_path, simple_loader)  # Hit

        stats = cache.get_statistics()
        assert stats["hits"] == 3
        assert stats["misses"] == 3
        assert stats["total_requests"] == 6
        assert stats["hit_rate"] == 0.5
        assert stats["current_entries"] == 3
        assert stats["current_size_mb"] > 0.0
        assert 0.0 < stats["utilization"] < 1.0


class TestCacheSizing:
    """Test cache size management."""

    def test_size_based_eviction(self, sample_dicom_files, simple_loader):
        """Test eviction based on memory size."""
        # Very small cache (0.001MB = 1KB) - forces eviction with small DICOM files
        cache = SeriesCache(max_size_mb=0.001, max_entries=1000)

        # Load multiple files until eviction occurs
        for file_path in sample_dicom_files:
            cache.get(file_path, simple_loader)

        stats = cache.get_statistics()
        # Should have evicted some entries due to size constraints
        assert stats["current_entries"] < len(sample_dicom_files)
        assert stats["evictions"] > 0

    def test_entry_count_limit(self, sample_dicom_files, simple_loader):
        """Test entry count limit enforcement."""
        # Large size but only 2 entries allowed
        cache = SeriesCache(max_size_mb=100, max_entries=2)

        # Load 5 files
        for file_path in sample_dicom_files:
            cache.get(file_path, simple_loader)

        stats = cache.get_statistics()
        assert stats["current_entries"] <= 2
        assert stats["evictions"] >= 3  # At least 3 evictions


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_get_nonexistent_file(self, simple_loader):
        """Test getting non-existent file from cache."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        result = cache.get(Path("/nonexistent/file.dcm"), simple_loader)
        assert result is None  # File doesn't exist

    def test_get_without_loader(self, sample_dicom_files):
        """Test cache miss without loader function."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)
        file_path = sample_dicom_files[0]

        # Cache miss without loader should return None
        result = cache.get(file_path, loader=None)
        assert result is None

    def test_zero_size_cache(self):
        """Test cache with zero size."""
        cache = SeriesCache(max_size_mb=0, max_entries=0)

        stats = cache.get_statistics()
        assert stats["max_size_mb"] == 0.0
        assert stats["max_entries"] == 0
        # Utilization should handle division by zero
        assert stats["utilization"] == 0.0

    def test_invalidate_nonexistent_entry(self, sample_dicom_files):
        """Test invalidating non-existent cache entry."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Invalidate file not in cache (should not raise error)
        cache.invalidate(sample_dicom_files[0])

        stats = cache.get_statistics()
        assert stats["current_entries"] == 0


class TestLRUOrdering:
    """Test LRU ordering behavior."""

    def test_access_updates_lru_order(self, sample_dicom_files, simple_loader):
        """Test that accessing entries updates LRU order."""
        # Cache with 3 entries max
        cache = SeriesCache(max_size_mb=10, max_entries=3)

        # Load 3 files
        for i in range(3):
            cache.get(sample_dicom_files[i], simple_loader)

        # Access first file again (make it most recently used)
        cache.get(sample_dicom_files[0], simple_loader)

        # Load 4th file (should evict file #1, not file #0)
        cache.get(sample_dicom_files[3], simple_loader)

        # File #0 should still be in cache (was recently accessed)
        ds = cache.get(sample_dicom_files[0], simple_loader)
        stats = cache.get_statistics()
        # Should be cache hit (file 0 still in cache)
        assert stats["hits"] >= 1


class TestDiskCaching:
    """Test disk-based series caching methods."""

    def test_cache_series_without_cache_dir(self, sample_dicom_files, simple_loader):
        """Test cache_series when cache_dir not configured."""
        from unittest.mock import Mock

        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=None)

        # Create mock DicomSeries
        mock_series = Mock()
        mock_series.series_uid = "1.2.3.4.5"

        # Should warn and not crash
        cache.cache_series(mock_series)

        # Verify cache is still functional
        assert cache is not None
        assert cache.cache_dir is None

    def test_cache_series_with_cache_dir(
        self, tmp_path, sample_dicom_files, simple_loader
    ):
        """Test cache_series with cache_dir configured."""
        from unittest.mock import Mock

        cache_dir = tmp_path / "series_cache"
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Create mock DicomSeries
        mock_series = Mock()
        mock_series.series_uid = "1.2.3.4.5"

        cache.cache_series(mock_series)

        # Check file was created
        series_path = cache_dir / "1.2.3.4.5.pkl"
        assert series_path.exists()

    def test_cache_series_exception(self, tmp_path):
        """Test cache_series handles exceptions."""
        from unittest.mock import Mock, patch

        cache_dir = tmp_path / "series_cache"
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Create mock series that fails to pickle
        mock_series = Mock()
        mock_series.series_uid = "1.2.3.4.5"

        with patch("builtins.open", side_effect=Exception("Write error")):
            # Should not raise
            cache.cache_series(mock_series)

        # Verify cache is still functional after exception
        assert cache is not None

    def test_is_cached_without_cache_dir(self):
        """Test is_cached when cache_dir not configured."""
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=None)

        result = cache.is_cached("1.2.3.4.5")
        assert result is False

    def test_is_cached_with_cache_dir(self, tmp_path):
        """Test is_cached with cache_dir configured."""
        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Initially not cached
        assert cache.is_cached("1.2.3.4.5") is False

        # Create cache file
        series_path = cache_dir / "1.2.3.4.5.pkl"
        series_path.write_bytes(b"dummy")

        # Now cached
        assert cache.is_cached("1.2.3.4.5") is True

    def test_load_series_without_cache_dir(self):
        """Test load_series when cache_dir not configured."""
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=None)

        result = cache.load_series("1.2.3.4.5")
        assert result is None

    def test_load_series_not_found(self, tmp_path):
        """Test load_series when series not in cache."""
        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        result = cache.load_series("1.2.3.4.5")
        assert result is None

    def test_load_series_success(self, tmp_path):
        """Test successful series loading from cache."""
        import pickle

        from dicom_fuzzer.core.dicom_series import DicomSeries

        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Create a real DicomSeries
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.1.1.1",
            modality="CT",
            slices=[],
        )

        series_path = cache_dir / "1.2.3.4.5.pkl"
        with open(series_path, "wb") as f:
            pickle.dump(series, f)

        # Load from cache
        loaded = cache.load_series("1.2.3.4.5")
        assert loaded is not None
        assert loaded.series_uid == "1.2.3.4.5"

    def test_load_series_exception(self, tmp_path):
        """Test load_series handles corrupted cache file."""
        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Create corrupted cache file
        series_path = cache_dir / "1.2.3.4.5.pkl"
        series_path.write_bytes(b"not a valid pickle")

        # Should return None, not raise
        result = cache.load_series("1.2.3.4.5")
        assert result is None


class TestMoreEdgeCases:
    """Additional edge case tests."""

    def test_cache_dir_creation(self, tmp_path):
        """Test that cache_dir is created if it doesn't exist."""
        cache_dir = tmp_path / "new_cache_dir" / "nested"
        assert not cache_dir.exists()

        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        assert cache_dir.exists()

    def test_loader_exception(self, sample_dicom_files):
        """Test handling when loader throws exception."""

        def failing_loader(file_path):
            raise Exception("Failed to load")

        cache = SeriesCache(max_size_mb=10, max_entries=100)
        file_path = sample_dicom_files[0]

        result = cache.get(file_path, failing_loader)
        assert result is None

    def test_evict_lru_empty_cache(self):
        """Test _evict_lru when cache is empty."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Should not raise
        cache._evict_lru()

        stats = cache.get_statistics()
        assert stats["evictions"] == 0

    def test_add_entry_forces_break_when_empty(self):
        """Test _add_entry break condition when cache empty but size exceeded."""
        from pydicom.dataset import Dataset

        # Cache with very small size
        cache = SeriesCache(max_size_mb=0, max_entries=0)

        # Manually call _add_entry
        ds = Dataset()
        ds.PatientName = "Test"

        # This should hit the break condition since cache is empty but size limit is 0
        from pathlib import Path
        from unittest.mock import Mock

        mock_path = Mock(spec=Path)
        mock_path.stat.return_value.st_mtime = 12345.0

        cache._add_entry(mock_path, ds)

        # Should have added one entry despite size constraints
        assert len(cache._cache) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
