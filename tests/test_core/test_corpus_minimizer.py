"""
Tests for Corpus Minimizer Module.

Tests AFL-style corpus minimization and coverage collection.
"""

import hashlib

import pytest

from dicom_fuzzer.core.corpus_minimizer import (
    CorpusStats,
    CoverageInfo,
    CoverageType,
    SimpleCoverageCollector,
)

# ============================================================================
# Test CoverageType Enum
# ============================================================================


class TestCoverageType:
    """Test CoverageType enumeration."""

    def test_coverage_type_values(self):
        """Test coverage type values."""
        assert CoverageType.EDGE.value == "edge"
        assert CoverageType.BRANCH.value == "branch"
        assert CoverageType.PATH.value == "path"
        assert CoverageType.FUNCTION.value == "function"


# ============================================================================
# Test CoverageInfo Dataclass
# ============================================================================


class TestCoverageInfo:
    """Test CoverageInfo dataclass."""

    def test_basic_creation(self, tmp_path):
        """Test basic CoverageInfo creation."""
        seed_path = tmp_path / "test.dcm"
        seed_path.write_bytes(b"test data")

        info = CoverageInfo(seed_path=seed_path)

        assert info.seed_path == seed_path
        assert info.coverage_hash == ""
        assert info.edges_hit == 0
        assert info.branches_hit == 0
        assert info.bitmap == b""
        assert info.file_size == len(b"test data")

    def test_creation_with_bitmap(self, tmp_path):
        """Test CoverageInfo with bitmap auto-generates hash."""
        seed_path = tmp_path / "test.dcm"
        seed_path.write_bytes(b"test data")

        bitmap = b"\x01\x02\x03\x04"
        info = CoverageInfo(seed_path=seed_path, bitmap=bitmap)

        expected_hash = hashlib.sha256(bitmap).hexdigest()[:16]
        assert info.coverage_hash == expected_hash
        assert info.bitmap == bitmap

    def test_creation_with_explicit_hash(self, tmp_path):
        """Test CoverageInfo with explicit hash preserves it."""
        seed_path = tmp_path / "test.dcm"
        seed_path.write_bytes(b"test data")

        info = CoverageInfo(
            seed_path=seed_path,
            coverage_hash="explicit_hash",
            bitmap=b"\x01\x02\x03",
        )

        # Explicit hash should be preserved
        assert info.coverage_hash == "explicit_hash"

    def test_file_size_auto_calculated(self, tmp_path):
        """Test file size is auto-calculated."""
        seed_path = tmp_path / "test.dcm"
        test_data = b"x" * 100
        seed_path.write_bytes(test_data)

        info = CoverageInfo(seed_path=seed_path)

        assert info.file_size == 100

    def test_nonexistent_file(self, tmp_path):
        """Test with nonexistent file."""
        seed_path = tmp_path / "nonexistent.dcm"

        info = CoverageInfo(seed_path=seed_path)

        assert info.file_size == 0

    def test_full_initialization(self, tmp_path):
        """Test full initialization with all fields."""
        seed_path = tmp_path / "test.dcm"
        seed_path.write_bytes(b"test")

        info = CoverageInfo(
            seed_path=seed_path,
            coverage_hash="abc123",
            edges_hit=10,
            branches_hit=5,
            bitmap=b"\xff" * 16,
            exec_time_us=1234.5,
        )

        assert info.edges_hit == 10
        assert info.branches_hit == 5
        assert info.exec_time_us == 1234.5


# ============================================================================
# Test CorpusStats Dataclass
# ============================================================================


class TestCorpusStats:
    """Test CorpusStats dataclass."""

    def test_default_values(self):
        """Test default CorpusStats values."""
        stats = CorpusStats()

        assert stats.total_seeds == 0
        assert stats.unique_coverage_hashes == 0
        assert stats.total_edges == 0
        assert stats.total_size_bytes == 0
        assert stats.avg_seed_size == 0.0
        assert stats.avg_exec_time_us == 0.0
        assert stats.redundant_seeds == 0
        assert stats.minimized_seeds == 0

    def test_custom_values(self):
        """Test CorpusStats with custom values."""
        stats = CorpusStats(
            total_seeds=100,
            unique_coverage_hashes=50,
            total_edges=1000,
            total_size_bytes=50000,
            avg_seed_size=500.5,
            avg_exec_time_us=1234.56,
            redundant_seeds=30,
            minimized_seeds=70,
        )

        assert stats.total_seeds == 100
        assert stats.unique_coverage_hashes == 50
        assert stats.avg_seed_size == 500.5

    def test_to_dict(self):
        """Test CorpusStats to_dict method."""
        stats = CorpusStats(
            total_seeds=100,
            unique_coverage_hashes=50,
            total_edges=1000,
            total_size_bytes=50000,
            avg_seed_size=500.555,  # Should be rounded to 2 decimal places
            avg_exec_time_us=1234.567,  # Should be rounded
            redundant_seeds=30,
            minimized_seeds=70,
        )

        result = stats.to_dict()

        assert result["total_seeds"] == 100
        assert result["unique_coverage_hashes"] == 50
        assert result["total_edges"] == 1000
        assert result["total_size_bytes"] == 50000
        assert result["avg_seed_size"] == 500.56  # Rounded
        assert result["avg_exec_time_us"] == 1234.57  # Rounded
        assert result["redundant_seeds"] == 30
        assert result["minimized_seeds"] == 70


# ============================================================================
# Test SimpleCoverageCollector
# ============================================================================


class TestSimpleCoverageCollector:
    """Test SimpleCoverageCollector class."""

    @pytest.fixture
    def collector(self):
        """Create a SimpleCoverageCollector."""
        return SimpleCoverageCollector()

    def test_get_coverage_with_file(self, collector, tmp_path):
        """Test getting coverage from existing file."""
        seed_path = tmp_path / "test.dcm"
        seed_path.write_bytes(b"test content for coverage")

        coverage = collector.get_coverage(seed_path)

        assert coverage.seed_path == seed_path
        assert coverage.coverage_hash != ""
        assert len(coverage.coverage_hash) == 16  # Truncated hash
        assert coverage.edges_hit > 0
        assert coverage.bitmap != b""
        assert coverage.file_size == len(b"test content for coverage")

    def test_get_coverage_nonexistent_file(self, collector, tmp_path):
        """Test getting coverage from nonexistent file."""
        seed_path = tmp_path / "nonexistent.dcm"

        coverage = collector.get_coverage(seed_path)

        assert coverage.seed_path == seed_path
        assert coverage.coverage_hash == ""
        assert coverage.edges_hit == 0
        assert coverage.bitmap == b""

    def test_get_coverage_hash_is_deterministic(self, collector, tmp_path):
        """Test that same content produces same hash."""
        seed1 = tmp_path / "test1.dcm"
        seed2 = tmp_path / "test2.dcm"

        content = b"identical content"
        seed1.write_bytes(content)
        seed2.write_bytes(content)

        cov1 = collector.get_coverage(seed1)
        cov2 = collector.get_coverage(seed2)

        assert cov1.coverage_hash == cov2.coverage_hash
        assert cov1.bitmap == cov2.bitmap

    def test_get_coverage_different_content_different_hash(self, collector, tmp_path):
        """Test that different content produces different hash."""
        seed1 = tmp_path / "test1.dcm"
        seed2 = tmp_path / "test2.dcm"

        seed1.write_bytes(b"content A")
        seed2.write_bytes(b"content B")

        cov1 = collector.get_coverage(seed1)
        cov2 = collector.get_coverage(seed2)

        assert cov1.coverage_hash != cov2.coverage_hash

    def test_merge_coverage_empty(self, collector):
        """Test merging empty coverage list."""
        result = collector.merge_coverage([])
        assert result == b""

    def test_merge_coverage_single(self, collector, tmp_path):
        """Test merging single coverage."""
        seed = tmp_path / "test.dcm"
        seed.write_bytes(b"test")

        cov = collector.get_coverage(seed)
        result = collector.merge_coverage([cov])

        assert result == cov.bitmap

    def test_merge_coverage_multiple(self, collector, tmp_path):
        """Test merging multiple coverages."""
        seed1 = tmp_path / "test1.dcm"
        seed2 = tmp_path / "test2.dcm"

        seed1.write_bytes(b"A")
        seed2.write_bytes(b"B")

        cov1 = collector.get_coverage(seed1)
        cov2 = collector.get_coverage(seed2)

        result = collector.merge_coverage([cov1, cov2])

        # Result should be OR of both bitmaps
        assert len(result) >= min(len(cov1.bitmap), len(cov2.bitmap))

    def test_edges_hit_counts_unique_bytes(self, collector, tmp_path):
        """Test edges_hit counts unique bytes in content."""
        seed = tmp_path / "test.dcm"
        # Content with limited unique bytes
        seed.write_bytes(b"\x00\x01\x02\x00\x01\x02")

        coverage = collector.get_coverage(seed)

        # edges_hit should reflect unique bytes in the SHA256 hash
        assert coverage.edges_hit > 0


# ============================================================================
# Test Edge Cases
# ============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_file(self, tmp_path):
        """Test with empty file."""
        seed = tmp_path / "empty.dcm"
        seed.write_bytes(b"")

        collector = SimpleCoverageCollector()
        coverage = collector.get_coverage(seed)

        assert coverage.file_size == 0
        assert coverage.coverage_hash != ""  # Hash of empty is still valid

    def test_large_file(self, tmp_path):
        """Test with large file."""
        seed = tmp_path / "large.dcm"
        seed.write_bytes(b"x" * 100000)

        collector = SimpleCoverageCollector()
        coverage = collector.get_coverage(seed)

        assert coverage.file_size == 100000
        assert coverage.coverage_hash != ""

    def test_binary_content(self, tmp_path):
        """Test with binary content."""
        seed = tmp_path / "binary.dcm"
        seed.write_bytes(bytes(range(256)))

        collector = SimpleCoverageCollector()
        coverage = collector.get_coverage(seed)

        assert coverage.file_size == 256
        assert coverage.edges_hit > 0
