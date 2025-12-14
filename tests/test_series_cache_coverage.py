"""Comprehensive Coverage Tests for SeriesCache Module

This test file is specifically designed to improve series_cache.py coverage from 50% to 85%+.

Target uncovered lines:
- 45: TYPE_CHECKING import for DicomSeries
- 63-64: CacheEntry.update_access() method
- 123-168: get() method edge cases (file not found, cache invalidation, loader errors)
- 177-180: invalidate() method
- 184-186: clear() method
- 195-198: get_statistics() edge cases (zero requests)
- 216-217: _get_cache_key() method
- 231-234: _estimate_size() method
- 244-268: _add_entry() with eviction logic
- 275-277: _remove_entry() method
- 281-289: _evict_lru() method
- 310: cache_series() success path with logging

Test strategy:
1. Test all cache operations (get, invalidate, clear)
2. Test LRU eviction thoroughly
3. Test disk-based caching (cache_series, load_series, is_cached)
4. Test error conditions and edge cases
5. Test statistics calculation with various states
"""

import pickle
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import generate_uid

from dicom_fuzzer.core.series_cache import CacheEntry, SeriesCache

# Fixtures


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


# CacheEntry Tests


class TestCacheEntryUpdateAccess:
    """Tests for CacheEntry.update_access() method - covering lines 63-64."""

    def test_update_access_increments_count(self, sample_dicom_files, simple_loader):
        """Test that update_access increments access_count."""
        file_path = sample_dicom_files[0]
        ds = simple_loader(file_path)

        entry = CacheEntry(
            file_path=file_path,
            dataset=ds,
            file_mtime=file_path.stat().st_mtime,
            size_bytes=1000,
        )

        assert entry.access_count == 0

        # Call update_access multiple times
        entry.update_access()
        assert entry.access_count == 1

        entry.update_access()
        assert entry.access_count == 2

        entry.update_access()
        assert entry.access_count == 3

    def test_update_access_updates_timestamp(self, sample_dicom_files, simple_loader):
        """Test that update_access updates last_access timestamp."""
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

        assert entry.last_access > initial_time


# SeriesCache.get() Tests


class TestSeriesCacheGet:
    """Tests for SeriesCache.get() method - covering lines 123-168."""

    def test_get_nonexistent_file_returns_none(self, simple_loader):
        """Test get() with non-existent file returns None - line 126-128."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        result = cache.get(Path("/nonexistent/file.dcm"), simple_loader)

        assert result is None
        stats = cache.get_statistics()
        assert stats["misses"] == 0  # No miss recorded for non-existent file
        assert stats["hits"] == 0

    def test_get_cache_hit_updates_lru_order(self, sample_dicom_files, simple_loader):
        """Test that cache hit moves entry to end (most recently used) - line 141."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Load two files
        cache.get(sample_dicom_files[0], simple_loader)
        cache.get(sample_dicom_files[1], simple_loader)

        # Access first file again (should move to end)
        ds = cache.get(sample_dicom_files[0], simple_loader)

        assert ds is not None
        stats = cache.get_statistics()
        assert stats["hits"] == 1

        # Check internal ordering - first file should be at end
        cache_keys = list(cache._cache.keys())
        first_file_key = cache._get_cache_key(sample_dicom_files[0])
        assert cache_keys[-1] == first_file_key  # Last item is most recently used

    def test_get_file_modified_invalidates_cache(
        self, sample_dicom_files, simple_loader
    ):
        """Test that modified file invalidates cache entry - line 145-148."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)
        file_path = sample_dicom_files[0]

        # First access - cache miss
        ds1 = cache.get(file_path, simple_loader)
        assert ds1 is not None
        assert cache.get_statistics()["current_entries"] == 1

        # Modify file (change mtime)
        time.sleep(0.01)
        file_path.touch()

        # Second access - should invalidate and reload
        ds2 = cache.get(file_path, simple_loader)

        assert ds2 is not None
        stats = cache.get_statistics()
        assert stats["misses"] == 2  # Original miss + reload after invalidation
        assert stats["current_entries"] == 1

    def test_get_cache_miss_without_loader_returns_none(self, sample_dicom_files):
        """Test cache miss without loader returns None - line 153-155."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        result = cache.get(sample_dicom_files[0], loader=None)

        assert result is None
        stats = cache.get_statistics()
        assert stats["misses"] == 1

    def test_get_loader_exception_returns_none(self, sample_dicom_files):
        """Test that loader exception returns None - line 166-168."""

        def failing_loader(file_path):
            raise ValueError("Simulated loader failure")

        cache = SeriesCache(max_size_mb=10, max_entries=100)

        result = cache.get(sample_dicom_files[0], failing_loader)

        assert result is None
        stats = cache.get_statistics()
        assert stats["misses"] == 1
        assert stats["current_entries"] == 0  # Nothing cached due to error


# SeriesCache.invalidate() Tests


class TestSeriesCacheInvalidate:
    """Tests for SeriesCache.invalidate() method - covering lines 177-180."""

    def test_invalidate_existing_entry(self, sample_dicom_files, simple_loader):
        """Test invalidating an existing cache entry - line 177-180."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Load file into cache
        cache.get(sample_dicom_files[0], simple_loader)
        assert cache.get_statistics()["current_entries"] == 1

        # Invalidate
        cache.invalidate(sample_dicom_files[0])

        stats = cache.get_statistics()
        assert stats["current_entries"] == 0

    def test_invalidate_nonexistent_entry_no_error(self, sample_dicom_files):
        """Test invalidating non-existent entry doesn't raise error - line 178-179."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Invalidate file not in cache (should not raise)
        cache.invalidate(sample_dicom_files[0])

        stats = cache.get_statistics()
        assert stats["current_entries"] == 0


# SeriesCache.clear() Tests


class TestSeriesCacheClear:
    """Tests for SeriesCache.clear() method - covering lines 184-186."""

    def test_clear_empties_cache(self, sample_dicom_files, simple_loader):
        """Test clear() removes all entries and resets size - line 184-186."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Load multiple files
        for file_path in sample_dicom_files:
            cache.get(file_path, simple_loader)

        stats_before = cache.get_statistics()
        assert stats_before["current_entries"] == 5
        assert stats_before["current_size_mb"] > 0

        # Clear cache
        cache.clear()

        stats_after = cache.get_statistics()
        assert stats_after["current_entries"] == 0
        assert stats_after["current_size_mb"] == 0.0
        # Statistics (hits, misses) should be preserved
        assert stats_after["misses"] == 5


# SeriesCache.get_statistics() Tests


class TestSeriesCacheStatistics:
    """Tests for SeriesCache.get_statistics() - covering lines 195-198."""

    def test_statistics_with_zero_requests(self):
        """Test statistics calculation with zero requests - line 196."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        stats = cache.get_statistics()

        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["total_requests"] == 0
        assert stats["hit_rate"] == 0.0  # Should handle division by zero

    def test_statistics_with_zero_max_size(self):
        """Test utilization calculation with zero max_size - line 209-210."""
        cache = SeriesCache(max_size_mb=0, max_entries=100)

        stats = cache.get_statistics()

        assert stats["max_size_mb"] == 0.0
        assert stats["utilization"] == 0.0  # Should handle division by zero


# Internal Methods Tests


class TestSeriesCacheInternalMethods:
    """Tests for internal cache methods."""

    def test_get_cache_key_consistency(self, sample_dicom_files):
        """Test _get_cache_key() produces consistent keys - line 216-217."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        file_path = sample_dicom_files[0]
        key1 = cache._get_cache_key(file_path)
        key2 = cache._get_cache_key(file_path)

        assert key1 == key2
        assert isinstance(key1, str)
        assert len(key1) > 0

    def test_estimate_size_scales_with_elements(self):
        """Test _estimate_size() calculation - line 231-234."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Create datasets with different number of DICOM elements
        # Note: len(dataset) only counts proper DICOM data elements, not setattr attributes
        ds_small = Dataset()
        ds_small.PatientName = "Test"
        ds_small.PatientID = "123"

        ds_large = Dataset()
        ds_large.PatientName = "Test"
        ds_large.PatientID = "123"
        ds_large.StudyInstanceUID = "1.2.3"
        ds_large.SeriesInstanceUID = "1.2.4"
        ds_large.SOPInstanceUID = "1.2.5"
        ds_large.Modality = "CT"
        ds_large.StudyDate = "20250101"
        ds_large.StudyTime = "120000"
        ds_large.AccessionNumber = "ACC123"
        ds_large.InstitutionName = "Hospital"

        size_small = cache._estimate_size(ds_small)
        size_large = cache._estimate_size(ds_large)

        assert size_small > 0
        assert size_large > size_small

    def test_remove_entry_updates_size(self, sample_dicom_files, simple_loader):
        """Test _remove_entry() updates total size - line 275-277."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Add entry
        cache.get(sample_dicom_files[0], simple_loader)

        size_before = cache._total_size_bytes
        assert size_before > 0

        # Remove entry
        cache_key = cache._get_cache_key(sample_dicom_files[0])
        cache._remove_entry(cache_key)

        assert cache._total_size_bytes == 0

    def test_evict_lru_removes_oldest_entry(self, sample_dicom_files, simple_loader):
        """Test _evict_lru() removes least recently used - line 281-289."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Add entries
        cache.get(sample_dicom_files[0], simple_loader)
        cache.get(sample_dicom_files[1], simple_loader)
        cache.get(sample_dicom_files[2], simple_loader)

        # Access first file to make it recently used
        cache.get(sample_dicom_files[0], simple_loader)

        # Manually evict
        cache._evict_lru()

        stats = cache.get_statistics()
        assert stats["evictions"] == 1
        assert stats["current_entries"] == 2

        # First file should still be in cache (recently accessed)
        first_key = cache._get_cache_key(sample_dicom_files[0])
        assert first_key in cache._cache

    def test_evict_lru_on_empty_cache_no_error(self):
        """Test _evict_lru() on empty cache doesn't error - line 281-282."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Should not raise
        cache._evict_lru()

        stats = cache.get_statistics()
        assert stats["evictions"] == 0


# LRU Eviction Tests


class TestLRUEviction:
    """Tests for LRU eviction logic - covering lines 244-268."""

    def test_add_entry_evicts_when_max_entries_reached(
        self, sample_dicom_files, simple_loader
    ):
        """Test _add_entry() evicts when max_entries reached - line 250."""
        cache = SeriesCache(max_size_mb=100, max_entries=2)

        # Add 3 entries (should evict oldest)
        cache.get(sample_dicom_files[0], simple_loader)
        cache.get(sample_dicom_files[1], simple_loader)
        cache.get(sample_dicom_files[2], simple_loader)

        stats = cache.get_statistics()
        assert stats["current_entries"] == 2
        assert stats["evictions"] == 1

    def test_add_entry_evicts_when_max_size_reached(
        self, sample_dicom_files, simple_loader
    ):
        """Test _add_entry() evicts when max_size reached - line 251."""
        # Very small cache (forces eviction based on size)
        cache = SeriesCache(max_size_mb=0.001, max_entries=1000)

        # Add entries until eviction occurs
        cache.get(sample_dicom_files[0], simple_loader)
        cache.get(sample_dicom_files[1], simple_loader)

        stats = cache.get_statistics()
        # Should have evicted due to size constraints
        assert stats["current_entries"] < 2 or stats["evictions"] > 0

    def test_add_entry_break_condition_when_cache_empty(self):
        """Test _add_entry() break when cache empty but size exceeded - line 253-254."""
        cache = SeriesCache(max_size_mb=0, max_entries=0)

        # Create a mock dataset
        ds = Dataset()
        ds.PatientName = "Test"

        # Create mock path
        mock_path = Mock(spec=Path)
        mock_path.stat.return_value.st_mtime = 12345.0

        # Should hit break condition (cache empty, can't evict more)
        cache._add_entry(mock_path, ds)

        # Entry should be added despite size constraints
        assert len(cache._cache) == 1


# Disk-Based Series Caching Tests


class TestDiskBasedCaching:
    """Tests for disk-based series caching methods."""

    def test_cache_series_success_with_logging(self, tmp_path):
        """Test cache_series() success path with logging - line 310."""
        from dicom_fuzzer.core.dicom_series import DicomSeries

        cache_dir = tmp_path / "series_cache"
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Create a real DicomSeries object
        series = DicomSeries(
            series_uid="1.2.3.4.5.6",
            study_uid="1.1.1.1.1",
            modality="CT",
            slices=[],
        )

        # Cache the series
        cache.cache_series(series)

        # Verify file was created
        series_path = cache_dir / "1.2.3.4.5.6.pkl"
        assert series_path.exists()

        # Verify we can unpickle it
        with open(series_path, "rb") as f:
            loaded = pickle.load(f)  # nosec B301
            assert loaded.series_uid == "1.2.3.4.5.6"

    def test_cache_series_without_cache_dir_warns(self):
        """Test cache_series() without cache_dir logs warning."""
        from dicom_fuzzer.core.dicom_series import DicomSeries

        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=None)

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.1.1.1",
            modality="CT",
            slices=[],
        )

        # Should warn but not crash
        cache.cache_series(series)

    def test_cache_series_handles_exception(self, tmp_path):
        """Test cache_series() handles write exceptions."""
        from dicom_fuzzer.core.dicom_series import DicomSeries

        cache_dir = tmp_path / "series_cache"
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.1.1.1",
            modality="CT",
            slices=[],
        )

        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            # Should not raise
            cache.cache_series(series)

    def test_is_cached_without_cache_dir(self):
        """Test is_cached() returns False when cache_dir not configured."""
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=None)

        result = cache.is_cached("1.2.3.4.5")

        assert result is False

    def test_is_cached_with_cache_dir_file_exists(self, tmp_path):
        """Test is_cached() returns True when file exists."""
        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Create cache file
        series_path = cache_dir / "1.2.3.4.5.pkl"
        series_path.write_bytes(b"dummy")

        result = cache.is_cached("1.2.3.4.5")

        assert result is True

    def test_is_cached_with_cache_dir_file_not_exists(self, tmp_path):
        """Test is_cached() returns False when file doesn't exist."""
        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        result = cache.is_cached("1.2.3.4.5")

        assert result is False

    def test_load_series_without_cache_dir(self):
        """Test load_series() returns None when cache_dir not configured."""
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=None)

        result = cache.load_series("1.2.3.4.5")

        assert result is None

    def test_load_series_file_not_found(self, tmp_path):
        """Test load_series() returns None when file doesn't exist."""
        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        result = cache.load_series("1.2.3.4.5")

        assert result is None

    def test_load_series_success(self, tmp_path):
        """Test successful load_series()."""
        from dicom_fuzzer.core.dicom_series import DicomSeries

        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Create and save a series
        series = DicomSeries(
            series_uid="1.2.3.4.5",
            study_uid="1.1.1.1",
            modality="MR",
            slices=[],
        )

        series_path = cache_dir / "1.2.3.4.5.pkl"
        with open(series_path, "wb") as f:
            pickle.dump(series, f)

        # Load from cache
        loaded = cache.load_series("1.2.3.4.5")

        assert loaded is not None
        assert loaded.series_uid == "1.2.3.4.5"
        assert loaded.modality == "MR"

    def test_load_series_corrupted_file(self, tmp_path):
        """Test load_series() handles corrupted pickle file."""
        cache_dir = tmp_path / "series_cache"
        cache_dir.mkdir()
        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        # Create corrupted cache file
        series_path = cache_dir / "1.2.3.4.5.pkl"
        series_path.write_bytes(b"not a valid pickle file")

        # Should return None, not raise
        result = cache.load_series("1.2.3.4.5")

        assert result is None


# Edge Cases and Integration Tests


class TestEdgeCasesAndIntegration:
    """Additional edge cases and integration tests."""

    def test_cache_dir_creation(self, tmp_path):
        """Test cache_dir is created if it doesn't exist."""
        cache_dir = tmp_path / "new_cache" / "nested"
        assert not cache_dir.exists()

        cache = SeriesCache(max_size_mb=10, max_entries=100, cache_dir=str(cache_dir))

        assert cache_dir.exists()

    def test_multiple_cache_hits_update_access_count(
        self, sample_dicom_files, simple_loader
    ):
        """Test multiple cache hits properly update access statistics."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        file_path = sample_dicom_files[0]

        # First access (miss)
        cache.get(file_path, simple_loader)

        # Multiple hits
        for _ in range(5):
            cache.get(file_path, simple_loader)

        stats = cache.get_statistics()
        assert stats["hits"] == 5
        assert stats["misses"] == 1
        assert stats["total_requests"] == 6

        # Check entry access count
        cache_key = cache._get_cache_key(file_path)
        entry = cache._cache[cache_key]
        assert entry.access_count == 5

    def test_mixed_operations_maintain_consistency(
        self, sample_dicom_files, simple_loader
    ):
        """Test that mixed cache operations maintain consistency."""
        cache = SeriesCache(max_size_mb=10, max_entries=3)

        # Load 3 files (fill cache)
        cache.get(sample_dicom_files[0], simple_loader)
        cache.get(sample_dicom_files[1], simple_loader)
        cache.get(sample_dicom_files[2], simple_loader)

        # Invalidate one
        cache.invalidate(sample_dicom_files[0])

        # Load more (should eventually evict when cache fills again)
        cache.get(sample_dicom_files[3], simple_loader)
        cache.get(sample_dicom_files[4], simple_loader)

        stats = cache.get_statistics()
        # After invalidation we have 2 entries, adding 2 more gives us 4 total operations
        # but max_entries=3, so we should have 3 entries and 1 eviction
        assert stats["current_entries"] == 3
        assert stats["misses"] == 5
        assert stats["evictions"] == 1

    def test_cache_size_tracking_accuracy(self, sample_dicom_files, simple_loader):
        """Test that cache size tracking is accurate."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Load files and track size
        for file_path in sample_dicom_files[:3]:
            cache.get(file_path, simple_loader)

        size_after_load = cache._total_size_bytes

        # Clear and verify size reset
        cache.clear()
        assert cache._total_size_bytes == 0

        # Reload and verify size matches
        for file_path in sample_dicom_files[:3]:
            cache.get(file_path, simple_loader)

        size_after_reload = cache._total_size_bytes
        assert size_after_reload == size_after_load


# Performance and Stress Tests


class TestPerformanceAndStress:
    """Performance and stress tests for cache."""

    def test_large_number_of_cache_operations(self, sample_dicom_files, simple_loader):
        """Test cache performance with many operations."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        # Perform many operations
        for _ in range(10):
            for file_path in sample_dicom_files:
                cache.get(file_path, simple_loader)

        stats = cache.get_statistics()
        assert stats["total_requests"] == 50  # 10 iterations * 5 files
        assert stats["current_entries"] == 5
        # First iteration is all misses, rest are hits
        assert stats["misses"] == 5
        assert stats["hits"] == 45

    def test_cache_with_rapid_invalidations(self, sample_dicom_files, simple_loader):
        """Test cache with rapid invalidation cycles."""
        cache = SeriesCache(max_size_mb=10, max_entries=100)

        file_path = sample_dicom_files[0]

        # Rapid load-invalidate-reload cycles
        for _ in range(5):
            cache.get(file_path, simple_loader)
            cache.invalidate(file_path)

        stats = cache.get_statistics()
        assert stats["misses"] == 5  # Each cycle is a miss
        assert stats["current_entries"] == 0  # Ends invalidated


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
