"""Series Metadata Caching for Performance Optimization

Implements LRU (Least Recently Used) cache for parsed DICOM metadata to avoid
redundant file I/O and parsing operations.

PERFORMANCE BENEFITS:
- Avoid re-parsing unchanged files (10-100x faster)
- Reduce disk I/O for repeated operations
- Enable efficient mutation iterations

CACHE STRATEGY:
- Only cache metadata (NOT pixel data) - memory efficient
- LRU eviction when cache full
- Cache statistics tracking (hits, misses, evictions)
- Configurable cache size

USAGE:
    cache = SeriesCache(max_size_mb=100)

    # First access - cache miss, loads from disk
    metadata = cache.get(file_path, loader)

    # Second access - cache hit, instant
    metadata = cache.get(file_path, loader)

    # Check statistics
    stats = cache.get_statistics()
    print(f"Hit rate: {stats['hit_rate']:.1%}")
"""

import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CacheEntry:
    """Single cache entry with metadata."""

    file_path: Path
    dataset: Dataset
    file_mtime: float  # File modification time for invalidation
    size_bytes: int  # Estimated memory size
    access_count: int = 0
    last_access: float = field(default_factory=time.time)

    def update_access(self) -> None:
        """Update access statistics."""
        self.access_count += 1
        self.last_access = time.time()


class SeriesCache:
    """LRU cache for DICOM series metadata.

    Caches parsed metadata (NOT pixel data) to avoid redundant I/O.
    """

    def __init__(self, max_size_mb: int = 100, max_entries: int = 1000):
        """Initialize series cache.

        Args:
            max_size_mb: Maximum cache size in megabytes
            max_entries: Maximum number of cached entries

        """
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.max_entries = max_entries

        # OrderedDict for LRU (oldest entries at start)
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()

        # Statistics
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._total_size_bytes = 0

        logger.info(
            f"SeriesCache initialized: max_size={max_size_mb}MB, "
            f"max_entries={max_entries}"
        )

    def get(
        self, file_path: Path, loader: Callable[[Path], Dataset] | None = None
    ) -> Dataset | None:
        """Get dataset from cache or load from disk.

        Args:
            file_path: Path to DICOM file
            loader: Callable to load file if not cached (e.g., LazyDicomLoader.load)

        Returns:
            Cached or freshly loaded dataset, or None if file doesn't exist

        """
        cache_key = self._get_cache_key(file_path)

        # Check if file exists
        if not file_path.exists():
            logger.warning(f"File not found: {file_path}")
            return None

        # Check cache
        if cache_key in self._cache:
            entry = self._cache[cache_key]

            # Validate cache entry (check if file modified)
            current_mtime = file_path.stat().st_mtime
            if current_mtime == entry.file_mtime:
                # Cache hit!
                self._hits += 1
                entry.update_access()
                # Move to end (most recently used)
                self._cache.move_to_end(cache_key)

                logger.debug(f"Cache HIT: {file_path.name}")
                return entry.dataset
            else:
                # File modified, invalidate entry
                logger.debug(f"Cache INVALIDATE: {file_path.name} (file modified)")
                self._remove_entry(cache_key)

        # Cache miss - load from disk
        self._misses += 1

        if loader is None:
            logger.warning(f"Cache MISS but no loader provided: {file_path.name}")
            return None

        try:
            dataset = loader(file_path)

            # Add to cache
            self._add_entry(file_path, dataset)

            logger.debug(f"Cache MISS: {file_path.name} (loaded and cached)")
            return dataset

        except Exception as e:
            logger.error(f"Failed to load {file_path.name}: {e}")
            return None

    def invalidate(self, file_path: Path) -> None:
        """Invalidate cache entry for a file.

        Args:
            file_path: Path to invalidate

        """
        cache_key = self._get_cache_key(file_path)
        if cache_key in self._cache:
            self._remove_entry(cache_key)
            logger.debug(f"Cache INVALIDATE: {file_path.name}")

    def clear(self) -> None:
        """Clear entire cache."""
        self._cache.clear()
        self._total_size_bytes = 0
        logger.info("Cache CLEARED")

    def get_statistics(self) -> dict:
        """Get cache statistics.

        Returns:
            Dict with cache performance metrics

        """
        total_requests = self._hits + self._misses
        hit_rate = self._hits / total_requests if total_requests > 0 else 0.0

        return {
            "hits": self._hits,
            "misses": self._misses,
            "evictions": self._evictions,
            "total_requests": total_requests,
            "hit_rate": hit_rate,
            "current_entries": len(self._cache),
            "max_entries": self.max_entries,
            "current_size_mb": self._total_size_bytes / 1024 / 1024,
            "max_size_mb": self.max_size_bytes / 1024 / 1024,
            "utilization": self._total_size_bytes / self.max_size_bytes
            if self.max_size_bytes > 0
            else 0.0,
        }

    def _get_cache_key(self, file_path: Path) -> str:
        """Generate cache key from file path."""
        # Use hash of absolute path for consistent keys
        abs_path = str(file_path.absolute())
        return hashlib.md5(abs_path.encode()).hexdigest()

    def _estimate_size(self, dataset: Dataset) -> int:
        """Estimate memory size of dataset (metadata only).

        Args:
            dataset: pydicom Dataset

        Returns:
            Estimated size in bytes

        """
        # Rough estimation based on number of elements
        # Average ~100 bytes per element (conservative)
        num_elements = len(dataset)
        estimated_size = num_elements * 100

        return estimated_size

    def _add_entry(self, file_path: Path, dataset: Dataset) -> None:
        """Add entry to cache, evicting if necessary.

        Args:
            file_path: File path
            dataset: Parsed dataset

        """
        cache_key = self._get_cache_key(file_path)
        file_mtime = file_path.stat().st_mtime
        size_bytes = self._estimate_size(dataset)

        # Evict if cache full
        while (
            len(self._cache) >= self.max_entries
            or self._total_size_bytes + size_bytes > self.max_size_bytes
        ):
            if not self._cache:
                break
            self._evict_lru()

        # Add entry
        entry = CacheEntry(
            file_path=file_path,
            dataset=dataset,
            file_mtime=file_mtime,
            size_bytes=size_bytes,
        )

        self._cache[cache_key] = entry
        self._total_size_bytes += size_bytes

        logger.debug(
            f"Cache ADD: {file_path.name} "
            f"(size={size_bytes / 1024:.1f}KB, entries={len(self._cache)})"
        )

    def _remove_entry(self, cache_key: str) -> None:
        """Remove entry from cache."""
        if cache_key in self._cache:
            entry = self._cache.pop(cache_key)
            self._total_size_bytes -= entry.size_bytes

    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self._cache:
            return

        # OrderedDict: first item is least recently used
        cache_key, entry = self._cache.popitem(last=False)
        self._total_size_bytes -= entry.size_bytes
        self._evictions += 1

        logger.debug(
            f"Cache EVICT: {entry.file_path.name} "
            f"(accesses={entry.access_count}, age={time.time() - entry.last_access:.1f}s)"
        )
