"""Corpus Minimization for DICOM Fuzzing.

Implements AFL-cmin style corpus minimization to reduce corpus size while
maintaining code coverage. Also includes multi-fuzzer synchronization
capabilities for distributed fuzzing.

Based on:
- AFL++ afl-cmin algorithm
- Google FuzzBench corpus management
- "Coverage-based Greybox Fuzzing" (CCS 2016)

Features:
- Coverage-based seed selection
- Deduplication by coverage hash
- Weighted minimization (prefer smaller seeds)
- Multi-fuzzer corpus synchronization
- Corpus health monitoring

"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

# Import unified types from central location
from dicom_fuzzer.core.coverage_types import SeedCoverageInfo

logger = logging.getLogger(__name__)

# Backward compatibility alias
CoverageInfo = SeedCoverageInfo


@dataclass
class CorpusStats:
    """Statistics about corpus state."""

    total_seeds: int = 0
    unique_coverage_hashes: int = 0
    total_edges: int = 0
    total_size_bytes: int = 0
    avg_seed_size: float = 0.0
    avg_exec_time_us: float = 0.0
    redundant_seeds: int = 0
    minimized_seeds: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_seeds": self.total_seeds,
            "unique_coverage_hashes": self.unique_coverage_hashes,
            "total_edges": self.total_edges,
            "total_size_bytes": self.total_size_bytes,
            "avg_seed_size": round(self.avg_seed_size, 2),
            "avg_exec_time_us": round(self.avg_exec_time_us, 2),
            "redundant_seeds": self.redundant_seeds,
            "minimized_seeds": self.minimized_seeds,
        }


# =============================================================================
# Coverage Collector Interface
# =============================================================================


class CoverageCollector(ABC):
    """Abstract interface for collecting coverage information."""

    @abstractmethod
    def get_coverage(self, seed_path: Path) -> CoverageInfo:
        """Execute seed and collect coverage.

        Args:
            seed_path: Path to seed file

        Returns:
            Coverage information for the seed

        """

    @abstractmethod
    def merge_coverage(self, coverages: list[CoverageInfo]) -> bytes:
        """Merge multiple coverage bitmaps.

        Args:
            coverages: List of coverage info to merge

        Returns:
            Merged coverage bitmap

        """


class SimpleCoverageCollector(CoverageCollector):
    """Simple coverage collector using file hashing.

    For use when actual code coverage is not available.
    Uses file content hash as a proxy for coverage.

    """

    def get_coverage(self, seed_path: Path) -> CoverageInfo:
        """Get coverage by hashing file content."""
        if not seed_path.exists():
            return CoverageInfo(seed_path=seed_path)

        content = seed_path.read_bytes()
        content_hash = hashlib.sha256(content).hexdigest()

        # Create a pseudo-bitmap from the hash
        bitmap = bytes.fromhex(content_hash)

        return CoverageInfo(
            seed_path=seed_path,
            coverage_hash=content_hash[:16],
            edges_hit=len(set(bitmap)),  # Unique bytes as pseudo-edges
            bitmap=bitmap,
            file_size=len(content),
        )

    def merge_coverage(self, coverages: list[CoverageInfo]) -> bytes:
        """Merge coverage by combining bitmaps."""
        if not coverages:
            return b""

        # Simple union of all bytes
        max_len = max(len(c.bitmap) for c in coverages if c.bitmap)
        merged = bytearray(max_len)

        for cov in coverages:
            for i, b in enumerate(cov.bitmap):
                merged[i] |= b

        return bytes(merged)


class TargetCoverageCollector(CoverageCollector):
    """Coverage collector that executes a target binary.

    Uses a target program to get actual code coverage.
    Requires target to output coverage data.

    """

    def __init__(
        self,
        target_cmd: str | list[str],
        timeout: float = 5.0,
        coverage_dir: Path | None = None,
    ) -> None:
        """Initialize target coverage collector.

        Args:
            target_cmd: Command to run target (@@  = seed file placeholder)
            timeout: Execution timeout in seconds
            coverage_dir: Directory for coverage output

        """
        if isinstance(target_cmd, str):
            self.target_cmd = target_cmd.split()
        else:
            self.target_cmd = list(target_cmd)
        self.timeout = timeout
        self.coverage_dir = coverage_dir or Path("./artifacts/coverage")
        self.coverage_dir.mkdir(parents=True, exist_ok=True)

    def get_coverage(self, seed_path: Path) -> CoverageInfo:
        """Execute target and collect coverage."""
        import subprocess

        start_time = time.time()

        # Replace @@ with seed path
        cmd = [seed_path.as_posix() if arg == "@@" else arg for arg in self.target_cmd]

        try:
            subprocess.run(
                cmd,
                timeout=self.timeout,
                capture_output=True,
                env={
                    **os.environ,
                    "LLVM_PROFILE_FILE": str(self.coverage_dir / "cov.profraw"),
                },
            )
            exec_time = (time.time() - start_time) * 1_000_000

            # Try to read coverage data
            bitmap = self._read_coverage_bitmap()

            return CoverageInfo(
                seed_path=seed_path,
                coverage_hash=hashlib.sha256(bitmap).hexdigest()[:16] if bitmap else "",
                edges_hit=sum(1 for b in bitmap if b > 0) if bitmap else 0,
                bitmap=bitmap,
                exec_time_us=exec_time,
                file_size=seed_path.stat().st_size,
            )

        except subprocess.TimeoutExpired:
            return CoverageInfo(
                seed_path=seed_path,
                exec_time_us=self.timeout * 1_000_000,
            )

        except Exception as e:
            logger.error(f"Coverage collection failed: {e}")
            return CoverageInfo(seed_path=seed_path)

    def _read_coverage_bitmap(self) -> bytes:
        """Read coverage bitmap from profraw file."""
        profraw = self.coverage_dir / "cov.profraw"
        if profraw.exists():
            return profraw.read_bytes()
        return b""

    def merge_coverage(self, coverages: list[CoverageInfo]) -> bytes:
        """Merge coverage bitmaps."""
        if not coverages:
            return b""

        max_len = max(len(c.bitmap) for c in coverages if c.bitmap)
        if max_len == 0:
            return b""

        merged = bytearray(max_len)
        for cov in coverages:
            for i, b in enumerate(cov.bitmap):
                merged[i] = max(merged[i], b)

        return bytes(merged)


# =============================================================================
# Corpus Minimizer
# =============================================================================


@dataclass
class MinimizationConfig:
    """Configuration for corpus minimization.

    Attributes:
        prefer_smaller: Prefer smaller seeds when coverage is equal
        max_corpus_size: Maximum number of seeds to keep
        min_edge_contribution: Minimum new edges for seed to be kept
        dedup_by_coverage: Deduplicate by coverage hash
        preserve_crashes: Always keep crash-inducing seeds
        parallel_workers: Number of parallel workers for coverage collection

    """

    prefer_smaller: bool = True
    max_corpus_size: int = 1000
    min_edge_contribution: int = 1
    dedup_by_coverage: bool = True
    preserve_crashes: bool = True
    parallel_workers: int = 4


class CorpusMinimizer:
    """AFL-cmin style corpus minimizer.

    Reduces corpus size while maintaining code coverage by:
    1. Collecting coverage for all seeds
    2. Selecting minimal set that covers all edges
    3. Preferring smaller/faster seeds

    Usage:
        minimizer = CorpusMinimizer(
            collector=SimpleCoverageCollector(),
            config=MinimizationConfig()
        )
        stats = minimizer.minimize(
            input_dir=Path("./artifacts/corpus"),
            output_dir=Path("./artifacts/corpus_min")
        )

    """

    def __init__(
        self,
        collector: CoverageCollector | None = None,
        config: MinimizationConfig | None = None,
    ) -> None:
        self.collector = collector or SimpleCoverageCollector()
        self.config = config or MinimizationConfig()
        self.coverage_map: dict[str, CoverageInfo] = {}

    def minimize(
        self,
        input_dir: Path,
        output_dir: Path,
        pattern: str = "*.dcm",
    ) -> CorpusStats:
        """Minimize corpus from input_dir to output_dir.

        Args:
            input_dir: Directory containing original corpus
            output_dir: Directory for minimized corpus
            pattern: Glob pattern for seed files

        Returns:
            Statistics about the minimization

        """
        input_dir = Path(input_dir)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Minimizing corpus from {input_dir} to {output_dir}")

        # Collect all seeds
        seeds = list(input_dir.glob(pattern))
        if not seeds:
            logger.warning(f"No seeds found matching {pattern} in {input_dir}")
            return CorpusStats()

        logger.info(f"Found {len(seeds)} seeds to process")

        # Collect coverage for all seeds
        coverages = self._collect_all_coverage(seeds)

        # Select minimal covering set
        selected = self._select_minimal_set(coverages)

        # Copy selected seeds to output
        for cov in selected:
            src = cov.seed_path
            dst = output_dir / src.name
            shutil.copy2(src, dst)

        # Compute statistics
        stats = self._compute_stats(coverages, selected)
        logger.info(
            f"Minimization complete: {stats.total_seeds} -> {stats.minimized_seeds} seeds"
        )

        return stats

    def _collect_all_coverage(self, seeds: list[Path]) -> list[CoverageInfo]:
        """Collect coverage for all seeds."""
        coverages = []

        for i, seed in enumerate(seeds):
            if i % 100 == 0:
                logger.info(f"Processing seed {i + 1}/{len(seeds)}")

            cov = self.collector.get_coverage(seed)
            coverages.append(cov)
            self.coverage_map[str(seed)] = cov

        return coverages

    def _select_minimal_set(self, coverages: list[CoverageInfo]) -> list[CoverageInfo]:
        """Select minimal set of seeds that covers all edges.

        Uses greedy algorithm:
        1. Sort seeds by (edges_hit / file_size) ratio (prefer efficient seeds)
        2. Iteratively add seeds that contribute new coverage
        3. Stop when all coverage is reached or max size hit

        """
        if not coverages:
            return []

        # Track which edges are covered
        covered_edges: set[int] = set()
        selected: list[CoverageInfo] = []

        # Sort by efficiency (edges per byte)
        def efficiency(c: CoverageInfo) -> float:
            if c.file_size == 0:
                return 0.0
            return c.edges_hit / c.file_size

        sorted_coverages = sorted(coverages, key=efficiency, reverse=True)

        # Greedy selection
        for cov in sorted_coverages:
            if len(selected) >= self.config.max_corpus_size:
                break

            # Find new edges this seed covers
            new_edges = set()
            for i, b in enumerate(cov.bitmap):
                if b > 0 and i not in covered_edges:
                    new_edges.add(i)

            # Check if seed contributes enough new coverage
            if len(new_edges) >= self.config.min_edge_contribution:
                selected.append(cov)
                covered_edges.update(new_edges)

            # If using deduplication, also skip exact coverage duplicates
            if self.config.dedup_by_coverage:
                if cov.coverage_hash in {c.coverage_hash for c in selected}:
                    continue

        return selected

    def _compute_stats(
        self, original: list[CoverageInfo], minimized: list[CoverageInfo]
    ) -> CorpusStats:
        """Compute minimization statistics."""
        total_edges = set()
        for cov in original:
            for i, b in enumerate(cov.bitmap):
                if b > 0:
                    total_edges.add(i)

        minimized_size = sum(c.file_size for c in minimized)

        return CorpusStats(
            total_seeds=len(original),
            unique_coverage_hashes=len({c.coverage_hash for c in original}),
            total_edges=len(total_edges),
            total_size_bytes=minimized_size,
            avg_seed_size=minimized_size / len(minimized) if minimized else 0,
            avg_exec_time_us=sum(c.exec_time_us for c in minimized) / len(minimized)
            if minimized
            else 0,
            redundant_seeds=len(original) - len(minimized),
            minimized_seeds=len(minimized),
        )


# =============================================================================
# Multi-Fuzzer Synchronization
# =============================================================================


class SyncMode(Enum):
    """Synchronization modes for multi-fuzzer setups."""

    PUSH = "push"  # Push local seeds to remote
    PULL = "pull"  # Pull seeds from remote
    BIDIRECTIONAL = "bidirectional"  # Both directions
    MASTER_SLAVE = "master_slave"  # Master sends, slaves receive


@dataclass
class FuzzerNode:
    """Information about a fuzzer node.

    Attributes:
        node_id: Unique identifier for this node
        corpus_dir: Local corpus directory
        is_master: Whether this is the master node
        last_sync: Timestamp of last synchronization
        seeds_sent: Number of seeds sent
        seeds_received: Number of seeds received

    """

    node_id: str
    corpus_dir: Path
    is_master: bool = False
    last_sync: float = 0.0
    seeds_sent: int = 0
    seeds_received: int = 0


@dataclass
class SyncConfig:
    """Configuration for corpus synchronization.

    Attributes:
        sync_interval: Seconds between sync operations
        max_seeds_per_sync: Maximum seeds to transfer per sync
        mode: Synchronization mode
        deduplicate: Deduplicate before sync
        compress: Compress seeds for transfer
        sync_crashes: Synchronize crash-inducing seeds

    """

    sync_interval: float = 60.0
    max_seeds_per_sync: int = 100
    mode: SyncMode = SyncMode.BIDIRECTIONAL
    deduplicate: bool = True
    compress: bool = True
    sync_crashes: bool = True


class CorpusSynchronizer:
    """Synchronize corpus between multiple fuzzer instances.

    Supports:
    - Local file-based sync (shared filesystem)
    - Network sync via simple protocol
    - Deduplication during sync

    Usage:
        sync = CorpusSynchronizer(
            node=FuzzerNode(node_id="fuzzer1", corpus_dir=Path("./artifacts/corpus")),
            config=SyncConfig()
        )
        sync.add_peer(peer_corpus_dir=Path("/shared/corpus2"))
        sync.sync_once()

    """

    def __init__(
        self,
        node: FuzzerNode,
        config: SyncConfig | None = None,
        collector: CoverageCollector | None = None,
    ) -> None:
        self.node = node
        self.config = config or SyncConfig()
        self.collector = collector or SimpleCoverageCollector()
        self.peers: list[Path] = []
        self.seen_hashes: set[str] = set()

    def add_peer(self, peer_corpus_dir: Path) -> None:
        """Add a peer corpus directory for synchronization."""
        peer_dir = Path(peer_corpus_dir)
        if peer_dir.exists():
            self.peers.append(peer_dir)
            logger.info(f"Added peer corpus: {peer_dir}")
        else:
            logger.warning(f"Peer corpus not found: {peer_dir}")

    def sync_once(self) -> dict[str, int]:
        """Perform one synchronization cycle.

        Returns:
            Dictionary with sync statistics

        """
        stats = {"pulled": 0, "pushed": 0, "duplicates": 0}

        if self.config.mode in [SyncMode.PULL, SyncMode.BIDIRECTIONAL]:
            pulled, dupes = self._pull_from_peers()
            stats["pulled"] = pulled
            stats["duplicates"] += dupes

        if self.config.mode in [SyncMode.PUSH, SyncMode.BIDIRECTIONAL]:
            pushed = self._push_to_peers()
            stats["pushed"] = pushed

        self.node.last_sync = time.time()

        return stats

    def _pull_from_peers(self) -> tuple[int, int]:
        """Pull new seeds from peer directories.

        Returns:
            Tuple of (seeds pulled, duplicates skipped)

        """
        pulled = 0
        duplicates = 0

        for peer_dir in self.peers:
            for seed in peer_dir.glob("*.dcm"):
                # Check if we already have this seed
                content_hash = hashlib.sha256(seed.read_bytes()).hexdigest()[:16]

                if content_hash in self.seen_hashes:
                    duplicates += 1
                    continue

                # Copy to local corpus
                dest = self.node.corpus_dir / f"sync_{self.node.node_id}_{seed.name}"
                if not dest.exists():
                    shutil.copy2(seed, dest)
                    self.seen_hashes.add(content_hash)
                    pulled += 1
                    self.node.seeds_received += 1

                if pulled >= self.config.max_seeds_per_sync:
                    break

        return pulled, duplicates

    def _push_to_peers(self) -> int:
        """Push local seeds to peer directories.

        Returns:
            Number of seeds pushed

        """
        pushed = 0

        for seed in self.node.corpus_dir.glob("*.dcm"):
            for peer_dir in self.peers:
                dest = peer_dir / f"sync_{self.node.node_id}_{seed.name}"
                if not dest.exists():
                    shutil.copy2(seed, dest)
                    pushed += 1
                    self.node.seeds_sent += 1

            if pushed >= self.config.max_seeds_per_sync:
                break

        return pushed

    def run_sync_loop(self, stop_event: Any = None) -> None:
        """Run continuous synchronization loop.

        Args:
            stop_event: Threading event to signal stop

        """
        logger.info(f"Starting sync loop with interval {self.config.sync_interval}s")

        while True:
            if stop_event and stop_event.is_set():
                break

            try:
                stats = self.sync_once()
                logger.info(
                    f"Sync complete: pulled={stats['pulled']}, "
                    f"pushed={stats['pushed']}, dupes={stats['duplicates']}"
                )
            except Exception as e:
                logger.error(f"Sync error: {e}")

            time.sleep(self.config.sync_interval)

    def get_status(self) -> dict[str, Any]:
        """Get synchronization status.

        Returns:
            Dictionary with sync status

        """
        return {
            "node_id": self.node.node_id,
            "corpus_dir": str(self.node.corpus_dir),
            "peers": [str(p) for p in self.peers],
            "last_sync": self.node.last_sync,
            "seeds_sent": self.node.seeds_sent,
            "seeds_received": self.node.seeds_received,
            "local_seeds": len(list(self.node.corpus_dir.glob("*.dcm"))),
            "seen_hashes": len(self.seen_hashes),
        }


# =============================================================================
# Convenience Functions
# =============================================================================


def minimize_corpus(
    input_dir: str | Path,
    output_dir: str | Path,
    target_cmd: str | None = None,
) -> CorpusStats:
    """Convenience function to minimize a DICOM corpus.

    Args:
        input_dir: Directory containing original corpus
        output_dir: Directory for minimized corpus
        target_cmd: Optional target command for coverage (@@  = seed file)

    Returns:
        Minimization statistics

    """
    collector: CoverageCollector
    if target_cmd:
        collector = TargetCoverageCollector(target_cmd)
    else:
        collector = SimpleCoverageCollector()

    minimizer = CorpusMinimizer(
        collector=collector,
        config=MinimizationConfig(),
    )

    return minimizer.minimize(
        input_dir=Path(input_dir),
        output_dir=Path(output_dir),
    )


def create_sync_node(
    node_id: str,
    corpus_dir: str | Path,
    peer_dirs: list[str | Path] | None = None,
) -> CorpusSynchronizer:
    """Create a corpus synchronization node.

    Args:
        node_id: Unique node identifier
        corpus_dir: Local corpus directory
        peer_dirs: List of peer corpus directories

    Returns:
        Configured CorpusSynchronizer

    """
    corpus_path = Path(corpus_dir)
    corpus_path.mkdir(parents=True, exist_ok=True)

    node = FuzzerNode(
        node_id=node_id,
        corpus_dir=corpus_path,
    )

    sync = CorpusSynchronizer(node=node)

    if peer_dirs:
        for peer in peer_dirs:
            sync.add_peer(Path(peer))

    return sync
