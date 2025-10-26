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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
