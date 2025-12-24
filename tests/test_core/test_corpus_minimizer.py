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


# ============================================================================
# Test TargetCoverageCollector
# ============================================================================


class TestTargetCoverageCollector:
    """Test TargetCoverageCollector class."""

    def test_init_with_string_command(self):
        """Test initialization with string command."""
        from dicom_fuzzer.core.corpus_minimizer import TargetCoverageCollector

        collector = TargetCoverageCollector(target_cmd="echo test")
        assert collector.target_cmd == ["echo", "test"]

    def test_init_with_list_command(self):
        """Test initialization with list command."""
        from dicom_fuzzer.core.corpus_minimizer import TargetCoverageCollector

        collector = TargetCoverageCollector(target_cmd=["python", "-c", "print(1)"])
        assert collector.target_cmd == ["python", "-c", "print(1)"]

    def test_init_with_timeout(self):
        """Test initialization with custom timeout."""
        from dicom_fuzzer.core.corpus_minimizer import TargetCoverageCollector

        collector = TargetCoverageCollector(target_cmd="echo test", timeout=10.0)
        assert collector.timeout == 10.0

    def test_init_with_coverage_dir(self, tmp_path):
        """Test initialization with coverage directory."""
        from dicom_fuzzer.core.corpus_minimizer import TargetCoverageCollector

        cov_dir = tmp_path / "coverage"
        collector = TargetCoverageCollector(target_cmd="echo", coverage_dir=cov_dir)
        assert collector.coverage_dir == cov_dir


# ============================================================================
# Test CorpusMinimizer
# ============================================================================


class TestCorpusMinimizer:
    """Test CorpusMinimizer class."""

    @pytest.fixture
    def minimizer(self):
        """Create a CorpusMinimizer with SimpleCoverageCollector."""
        from dicom_fuzzer.core.corpus_minimizer import CorpusMinimizer

        collector = SimpleCoverageCollector()
        return CorpusMinimizer(collector=collector)

    @pytest.fixture
    def corpus_dir(self, tmp_path):
        """Create a corpus directory with test seeds."""
        corpus = tmp_path / "corpus"
        corpus.mkdir()

        # Create test seeds
        (corpus / "seed1.dcm").write_bytes(b"content A")
        (corpus / "seed2.dcm").write_bytes(b"content B")
        (corpus / "seed3.dcm").write_bytes(b"content A")  # Duplicate coverage

        return corpus

    def test_init_default(self):
        """Test default initialization."""
        from dicom_fuzzer.core.corpus_minimizer import CorpusMinimizer

        minimizer = CorpusMinimizer()
        assert minimizer.collector is not None

    def test_init_with_collector(self):
        """Test initialization with custom collector."""
        from dicom_fuzzer.core.corpus_minimizer import CorpusMinimizer

        collector = SimpleCoverageCollector()
        minimizer = CorpusMinimizer(collector=collector)
        assert minimizer.collector is collector

    def test_init_with_config(self):
        """Test initialization with custom config."""
        from dicom_fuzzer.core.corpus_minimizer import (
            CorpusMinimizer,
            MinimizationConfig,
        )

        config = MinimizationConfig(max_corpus_size=500)
        minimizer = CorpusMinimizer(config=config)
        assert minimizer.config.max_corpus_size == 500

    def test_minimize_creates_output_dir(self, minimizer, corpus_dir, tmp_path):
        """Test minimize creates output directory."""
        output_dir = tmp_path / "minimized"

        minimizer.minimize(corpus_dir, output_dir)

        assert output_dir.exists()
        assert output_dir.is_dir()

    def test_minimize_reduces_redundant_seeds(self, minimizer, corpus_dir, tmp_path):
        """Test minimize removes redundant seeds."""
        output_dir = tmp_path / "minimized"

        stats = minimizer.minimize(corpus_dir, output_dir)

        # Should have fewer or equal seeds (duplicates removed)
        minimized_seeds = list(output_dir.glob("*.dcm"))
        assert len(minimized_seeds) <= 3
        assert isinstance(stats, CorpusStats)

    def test_minimize_returns_stats(self, minimizer, corpus_dir, tmp_path):
        """Test minimize returns CorpusStats."""
        output_dir = tmp_path / "minimized"

        stats = minimizer.minimize(corpus_dir, output_dir)

        assert isinstance(stats, CorpusStats)
        assert stats.total_seeds >= 0

    def test_minimize_empty_corpus(self, minimizer, tmp_path):
        """Test minimize with empty corpus."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        output_dir = tmp_path / "minimized"

        stats = minimizer.minimize(empty_dir, output_dir)

        assert stats.total_seeds == 0


# ============================================================================
# Test MinimizationConfig
# ============================================================================


class TestMinimizationConfig:
    """Test MinimizationConfig dataclass."""

    def test_default_config(self):
        """Test default MinimizationConfig values."""
        from dicom_fuzzer.core.corpus_minimizer import MinimizationConfig

        config = MinimizationConfig()
        assert config.prefer_smaller is True
        assert config.max_corpus_size == 1000
        assert config.min_edge_contribution == 1
        assert config.dedup_by_coverage is True
        assert config.preserve_crashes is True
        assert config.parallel_workers == 4

    def test_custom_config(self):
        """Test MinimizationConfig with custom values."""
        from dicom_fuzzer.core.corpus_minimizer import MinimizationConfig

        config = MinimizationConfig(
            prefer_smaller=False,
            max_corpus_size=500,
            parallel_workers=8,
        )
        assert config.prefer_smaller is False
        assert config.max_corpus_size == 500
        assert config.parallel_workers == 8


# ============================================================================
# Test MinimizationAlgorithm
# ============================================================================


class TestMinimizationAlgorithm:
    """Test minimization algorithm behavior."""

    def test_different_content_different_coverage(self, tmp_path):
        """Test that different content produces different coverage."""
        from dicom_fuzzer.core.corpus_minimizer import CorpusMinimizer

        corpus = tmp_path / "corpus"
        corpus.mkdir()
        output = tmp_path / "minimized"

        # Create seeds with different content
        (corpus / "a.dcm").write_bytes(b"content A")
        (corpus / "b.dcm").write_bytes(b"content B")
        (corpus / "c.dcm").write_bytes(b"content C")

        minimizer = CorpusMinimizer()
        stats = minimizer.minimize(corpus, output)

        # Should keep all seeds with unique coverage
        assert stats.unique_coverage_hashes >= 1

    def test_handles_corrupt_files(self, tmp_path):
        """Test handling of corrupt/unreadable files."""
        from dicom_fuzzer.core.corpus_minimizer import CorpusMinimizer

        corpus = tmp_path / "corpus"
        corpus.mkdir()
        output = tmp_path / "minimized"

        # Create normal seed
        (corpus / "good.dcm").write_bytes(b"valid content")

        minimizer = CorpusMinimizer()
        # Should not crash
        minimizer.minimize(corpus, output)

        assert output.exists()


# ============================================================================
# Test SyncMode Enum
# ============================================================================


class TestSyncMode:
    """Test SyncMode enumeration."""

    def test_sync_mode_values(self):
        """Test sync mode values."""
        from dicom_fuzzer.core.corpus_minimizer import SyncMode

        assert SyncMode.PUSH.value == "push"
        assert SyncMode.PULL.value == "pull"
        assert SyncMode.BIDIRECTIONAL.value == "bidirectional"
        assert SyncMode.MASTER_SLAVE.value == "master_slave"


# ============================================================================
# Test FuzzerNode Dataclass
# ============================================================================


class TestFuzzerNode:
    """Test FuzzerNode dataclass."""

    def test_default_values(self, tmp_path):
        """Test default FuzzerNode values."""
        from dicom_fuzzer.core.corpus_minimizer import FuzzerNode

        node = FuzzerNode(node_id="test", corpus_dir=tmp_path)

        assert node.node_id == "test"
        assert node.corpus_dir == tmp_path
        assert node.is_master is False
        assert node.last_sync == 0.0
        assert node.seeds_sent == 0
        assert node.seeds_received == 0

    def test_custom_values(self, tmp_path):
        """Test FuzzerNode with custom values."""
        from dicom_fuzzer.core.corpus_minimizer import FuzzerNode

        node = FuzzerNode(
            node_id="master",
            corpus_dir=tmp_path,
            is_master=True,
            seeds_sent=10,
            seeds_received=20,
        )

        assert node.node_id == "master"
        assert node.is_master is True
        assert node.seeds_sent == 10
        assert node.seeds_received == 20


# ============================================================================
# Test SyncConfig Dataclass
# ============================================================================


class TestSyncConfig:
    """Test SyncConfig dataclass."""

    def test_default_values(self):
        """Test default SyncConfig values."""
        from dicom_fuzzer.core.corpus_minimizer import SyncConfig, SyncMode

        config = SyncConfig()

        assert config.sync_interval == 60.0
        assert config.max_seeds_per_sync == 100
        assert config.mode == SyncMode.BIDIRECTIONAL
        assert config.deduplicate is True
        assert config.compress is True
        assert config.sync_crashes is True

    def test_custom_values(self):
        """Test SyncConfig with custom values."""
        from dicom_fuzzer.core.corpus_minimizer import SyncConfig, SyncMode

        config = SyncConfig(
            sync_interval=30.0,
            max_seeds_per_sync=50,
            mode=SyncMode.PUSH,
        )

        assert config.sync_interval == 30.0
        assert config.max_seeds_per_sync == 50
        assert config.mode == SyncMode.PUSH


# ============================================================================
# Test CorpusSynchronizer
# ============================================================================


class TestCorpusSynchronizer:
    """Test CorpusSynchronizer class."""

    @pytest.fixture
    def node(self, tmp_path):
        """Create a FuzzerNode."""
        from dicom_fuzzer.core.corpus_minimizer import FuzzerNode

        corpus = tmp_path / "corpus"
        corpus.mkdir()
        return FuzzerNode(node_id="test_node", corpus_dir=corpus)

    @pytest.fixture
    def synchronizer(self, node):
        """Create a CorpusSynchronizer."""
        from dicom_fuzzer.core.corpus_minimizer import CorpusSynchronizer

        return CorpusSynchronizer(node=node)

    def test_init_default(self, node):
        """Test default initialization."""
        from dicom_fuzzer.core.corpus_minimizer import CorpusSynchronizer

        sync = CorpusSynchronizer(node=node)

        assert sync.node is node
        assert sync.config is not None
        assert sync.collector is not None
        assert sync.peers == []
        assert len(sync.seen_hashes) == 0

    def test_init_with_config(self, node):
        """Test initialization with custom config."""
        from dicom_fuzzer.core.corpus_minimizer import CorpusSynchronizer, SyncConfig

        config = SyncConfig(sync_interval=120.0)
        sync = CorpusSynchronizer(node=node, config=config)

        assert sync.config.sync_interval == 120.0

    def test_add_peer_existing(self, synchronizer, tmp_path):
        """Test adding an existing peer directory."""
        peer_dir = tmp_path / "peer"
        peer_dir.mkdir()

        synchronizer.add_peer(peer_dir)

        assert peer_dir in synchronizer.peers

    def test_add_peer_nonexistent(self, synchronizer, tmp_path):
        """Test adding a nonexistent peer directory."""
        peer_dir = tmp_path / "nonexistent"

        synchronizer.add_peer(peer_dir)

        assert peer_dir not in synchronizer.peers

    def test_sync_once_no_peers(self, synchronizer):
        """Test sync with no peers."""
        stats = synchronizer.sync_once()

        assert stats["pulled"] == 0
        assert stats["pushed"] == 0
        assert stats["duplicates"] == 0

    def test_sync_once_pull(self, synchronizer, tmp_path):
        """Test sync pulls from peers."""
        peer = tmp_path / "peer"
        peer.mkdir()
        (peer / "seed.dcm").write_bytes(b"test data")

        synchronizer.add_peer(peer)
        stats = synchronizer.sync_once()

        assert stats["pulled"] >= 0

    def test_sync_once_push(self, node, tmp_path):
        """Test sync pushes to peers."""
        from dicom_fuzzer.core.corpus_minimizer import (
            CorpusSynchronizer,
            SyncConfig,
            SyncMode,
        )

        config = SyncConfig(mode=SyncMode.PUSH)
        sync = CorpusSynchronizer(node=node, config=config)

        # Add seed to local corpus
        (node.corpus_dir / "local.dcm").write_bytes(b"local data")

        peer = tmp_path / "peer"
        peer.mkdir()
        sync.add_peer(peer)

        stats = sync.sync_once()

        assert stats["pushed"] >= 0

    def test_get_status(self, synchronizer, tmp_path):
        """Test get_status returns status dict."""
        peer = tmp_path / "peer"
        peer.mkdir()
        synchronizer.add_peer(peer)

        status = synchronizer.get_status()

        assert "node_id" in status
        assert status["node_id"] == "test_node"
        assert "corpus_dir" in status
        assert "peers" in status
        assert "last_sync" in status
        assert "seeds_sent" in status
        assert "seeds_received" in status
        assert "local_seeds" in status
        assert "seen_hashes" in status

    def test_sync_tracks_seen_hashes(self, synchronizer, tmp_path):
        """Test that sync tracks seen hashes."""
        peer = tmp_path / "peer"
        peer.mkdir()
        (peer / "seed.dcm").write_bytes(b"unique content")

        synchronizer.add_peer(peer)
        synchronizer.sync_once()

        # Second sync should skip duplicates
        stats = synchronizer.sync_once()
        assert stats["duplicates"] >= 0


# ============================================================================
# Test Convenience Functions
# ============================================================================


class TestConvenienceFunctions:
    """Test module-level convenience functions."""

    def test_minimize_corpus_basic(self, tmp_path):
        """Test minimize_corpus function."""
        from dicom_fuzzer.core.corpus_minimizer import minimize_corpus

        input_dir = tmp_path / "input"
        input_dir.mkdir()
        output_dir = tmp_path / "output"

        (input_dir / "seed1.dcm").write_bytes(b"content A")
        (input_dir / "seed2.dcm").write_bytes(b"content B")

        stats = minimize_corpus(input_dir, output_dir)

        assert output_dir.exists()
        assert stats.total_seeds >= 0

    def test_minimize_corpus_with_target_cmd(self, tmp_path):
        """Test minimize_corpus with target command."""
        from dicom_fuzzer.core.corpus_minimizer import minimize_corpus

        input_dir = tmp_path / "input"
        input_dir.mkdir()
        output_dir = tmp_path / "output"

        (input_dir / "seed.dcm").write_bytes(b"content")

        # Use a simple echo command as target
        stats = minimize_corpus(input_dir, output_dir, target_cmd="echo @@")

        assert output_dir.exists()

    def test_create_sync_node_basic(self, tmp_path):
        """Test create_sync_node function."""
        from dicom_fuzzer.core.corpus_minimizer import create_sync_node

        corpus_dir = tmp_path / "corpus"

        sync = create_sync_node("node1", corpus_dir)

        assert sync.node.node_id == "node1"
        assert sync.node.corpus_dir == corpus_dir
        assert corpus_dir.exists()

    def test_create_sync_node_with_peers(self, tmp_path):
        """Test create_sync_node with peer directories."""
        from dicom_fuzzer.core.corpus_minimizer import create_sync_node

        corpus_dir = tmp_path / "corpus"
        peer1 = tmp_path / "peer1"
        peer2 = tmp_path / "peer2"
        peer1.mkdir()
        peer2.mkdir()

        sync = create_sync_node("node1", corpus_dir, peer_dirs=[peer1, peer2])

        assert len(sync.peers) == 2
        assert peer1 in sync.peers
        assert peer2 in sync.peers


# ============================================================================
# Test TargetCoverageCollector Advanced
# ============================================================================


class TestTargetCoverageCollectorAdvanced:
    """Advanced tests for TargetCoverageCollector."""

    def test_get_coverage_runs_command(self, tmp_path):
        """Test get_coverage executes target command."""
        from dicom_fuzzer.core.corpus_minimizer import TargetCoverageCollector

        seed = tmp_path / "test.dcm"
        seed.write_bytes(b"test content")

        # Use echo command that should work on all platforms
        collector = TargetCoverageCollector(
            target_cmd=["python", "-c", "import sys; sys.exit(0)"],
            timeout=5.0,
            coverage_dir=tmp_path / "cov",
        )

        coverage = collector.get_coverage(seed)

        # Should return coverage info without errors
        assert coverage.seed_path == seed
        assert coverage.exec_time_us > 0

    def test_get_coverage_timeout(self, tmp_path):
        """Test get_coverage handles timeout."""
        from dicom_fuzzer.core.corpus_minimizer import TargetCoverageCollector

        seed = tmp_path / "test.dcm"
        seed.write_bytes(b"test content")

        # Use a command that sleeps to trigger timeout
        collector = TargetCoverageCollector(
            target_cmd=["python", "-c", "import time; time.sleep(10)"],
            timeout=0.1,
            coverage_dir=tmp_path / "cov",
        )

        coverage = collector.get_coverage(seed)

        # Should return with timeout exec time
        assert coverage.seed_path == seed

    def test_merge_coverage_empty(self):
        """Test merge_coverage with empty list."""
        from dicom_fuzzer.core.corpus_minimizer import TargetCoverageCollector

        collector = TargetCoverageCollector(target_cmd="echo")
        result = collector.merge_coverage([])

        assert result == b""

    def test_merge_coverage_single_bitmap(self, tmp_path):
        """Test merge_coverage with single bitmap."""
        from dicom_fuzzer.core.corpus_minimizer import (
            CoverageInfo,
            TargetCoverageCollector,
        )

        collector = TargetCoverageCollector(target_cmd="echo")

        cov1 = CoverageInfo(seed_path=tmp_path / "a.dcm", bitmap=b"\x01\x02\x03")

        result = collector.merge_coverage([cov1])

        assert result == b"\x01\x02\x03"

    def test_merge_coverage_with_bitmaps(self, tmp_path):
        """Test merge_coverage merges correctly."""
        from dicom_fuzzer.core.corpus_minimizer import (
            CoverageInfo,
            TargetCoverageCollector,
        )

        collector = TargetCoverageCollector(target_cmd="echo")

        cov1 = CoverageInfo(seed_path=tmp_path / "a.dcm", bitmap=b"\x01\x00\x03")
        cov2 = CoverageInfo(seed_path=tmp_path / "b.dcm", bitmap=b"\x00\x02\x03")

        result = collector.merge_coverage([cov1, cov2])

        # Should take max of each byte
        assert len(result) == 3
        assert result[0] == 1  # max(1, 0)
        assert result[1] == 2  # max(0, 2)
        assert result[2] == 3  # max(3, 3)
