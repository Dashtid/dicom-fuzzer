"""Stack trace clustering for crash deduplication.

Implements CASR/ECHO-style stack trace clustering using:
- Longest Common Subsequence (LCS) for call stack comparison
- Weighted frame matching (innermost frames weighted higher)
- Stability metrics for cluster quality assessment
- PC-based signature generation

References:
- ECHO: Call Stack-Aware Crash Deduplication (2025)
- CASR: Crash Analysis and Severity Rating
- Igor: Root-Cause Clustering

"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum, auto
from typing import Any

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class ClusteringMethod(Enum):
    """Methods for clustering stack traces."""

    LCS = auto()  # Longest Common Subsequence
    WEIGHTED_LCS = auto()  # LCS with frame weighting
    SIGNATURE = auto()  # Hash-based signature matching
    HYBRID = auto()  # Combination of methods


@dataclass
class StackFrame:
    """Represents a single stack frame.

    Attributes:
        function: Function name
        filename: Source file name
        lineno: Line number (may be None for stripped binaries)
        address: Memory address (for PC-based matching)
        module: Module/library name
        is_system: Whether this is a system/library frame

    """

    function: str
    filename: str | None = None
    lineno: int | None = None
    address: str | None = None
    module: str | None = None
    is_system: bool = False

    def normalized_name(self) -> str:
        """Get normalized function name for comparison."""
        # Remove template parameters, addresses, etc.
        name = self.function

        # Remove C++ template parameters
        name = re.sub(r"<[^>]+>", "<>", name)

        # Remove function arguments
        name = re.sub(r"\([^)]*\)", "()", name)

        # Remove address suffixes
        name = re.sub(r"\+0x[0-9a-fA-F]+", "", name)

        return name.strip()

    def signature(self) -> str:
        """Generate a signature for this frame."""
        parts = [self.normalized_name()]
        if self.filename:
            parts.append(self.filename.split("/")[-1].split("\\")[-1])
        return ":".join(parts)


@dataclass
class StackTrace:
    """Represents a complete stack trace.

    Attributes:
        frames: List of stack frames (innermost first)
        crash_type: Type of crash (SIGSEGV, exception, etc.)
        crash_address: Address where crash occurred
        raw_trace: Original raw trace string

    """

    frames: list[StackFrame] = field(default_factory=list)
    crash_type: str | None = None
    crash_address: str | None = None
    raw_trace: str | None = None

    def get_function_sequence(self, max_depth: int | None = None) -> list[str]:
        """Get sequence of normalized function names."""
        frames = self.frames[:max_depth] if max_depth else self.frames
        return [f.normalized_name() for f in frames if not f.is_system]

    def get_user_frames(self) -> list[StackFrame]:
        """Get only user (non-system) frames."""
        return [f for f in self.frames if not f.is_system]

    def signature(self, depth: int = 5) -> str:
        """Generate a signature for this trace."""
        func_seq = self.get_function_sequence(depth)
        sig_str = "|".join(func_seq)
        return hashlib.md5(sig_str.encode(), usedforsecurity=False).hexdigest()[:16]


@dataclass
class ClusterMetrics:
    """Metrics for evaluating cluster quality.

    Attributes:
        size: Number of crashes in cluster
        stability: How stable the cluster membership is (0-1)
        cohesion: Average similarity within cluster (0-1)
        separation: Average distance to nearest other cluster (0-1)
        representative_confidence: Confidence in representative selection

    """

    size: int = 0
    stability: float = 1.0
    cohesion: float = 1.0
    separation: float = 0.0
    representative_confidence: float = 1.0

    def quality_score(self) -> float:
        """Calculate overall cluster quality score."""
        return (
            self.cohesion * 0.4
            + self.stability * 0.3
            + self.separation * 0.2
            + self.representative_confidence * 0.1
        )


@dataclass
class CrashCluster:
    """A cluster of similar crashes.

    Attributes:
        cluster_id: Unique identifier
        representative: Representative stack trace
        members: List of member crash IDs
        signatures: Set of signatures in this cluster
        metrics: Cluster quality metrics

    """

    cluster_id: str
    representative: StackTrace
    members: list[str] = field(default_factory=list)
    signatures: set[str] = field(default_factory=set)
    metrics: ClusterMetrics = field(default_factory=ClusterMetrics)

    def add_member(self, crash_id: str, trace: StackTrace) -> None:
        """Add a crash to this cluster."""
        self.members.append(crash_id)
        self.signatures.add(trace.signature())
        self.metrics.size = len(self.members)


@dataclass
class ClustererConfig:
    """Configuration for stack trace clustering.

    Attributes:
        similarity_threshold: Minimum similarity for same cluster (0-1)
        max_depth: Maximum stack depth to consider
        weight_decay: How quickly frame importance decays with depth
        min_frames: Minimum frames required for comparison
        ignore_system_frames: Whether to ignore system library frames
        method: Clustering method to use

    """

    similarity_threshold: float = 0.7
    max_depth: int = 20
    weight_decay: float = 0.9
    min_frames: int = 2
    ignore_system_frames: bool = True
    method: ClusteringMethod = ClusteringMethod.WEIGHTED_LCS


class StackTraceClusterer:
    """Clusters stack traces using LCS-based similarity.

    Implements CASR/ECHO-style clustering with:
    - LCS computation on normalized call stacks
    - Weighted frame matching (innermost = higher weight)
    - Stability tracking across iterations
    - Multiple clustering strategies
    """

    # Common system library patterns to filter
    SYSTEM_PATTERNS = [
        r"^libc\.",
        r"^libpthread\.",
        r"^libstdc\+\+\.",
        r"^_start$",
        r"^__libc_start",
        r"^clone$",
        r"^start_thread$",
        r"^Python/",
        r"^_Py",
        r"^<frozen",
    ]

    def __init__(self, config: ClustererConfig | None = None):
        """Initialize the clusterer.

        Args:
            config: Clustering configuration

        """
        self.config = config or ClustererConfig()
        self.clusters: dict[str, CrashCluster] = {}
        self._trace_cache: dict[str, StackTrace] = {}
        self._similarity_cache: dict[tuple[str, str], float] = {}
        self._next_cluster_id = 0

        # Compile system patterns
        self._system_re = re.compile("|".join(f"({p})" for p in self.SYSTEM_PATTERNS))

    def parse_trace(self, raw_trace: str) -> StackTrace:
        """Parse a raw stack trace string into structured form.

        Supports multiple formats:
        - Python tracebacks
        - GDB-style traces
        - AddressSanitizer output
        - Generic "at file:line" format

        Args:
            raw_trace: Raw stack trace string

        Returns:
            Parsed StackTrace object

        """
        trace = StackTrace(raw_trace=raw_trace)
        lines = raw_trace.strip().split("\n")

        for line in lines:
            frame = self._parse_frame(line)
            if frame:
                # Check if system frame
                if self._system_re.search(frame.function):
                    frame.is_system = True
                trace.frames.append(frame)

        # Extract crash type if present
        trace.crash_type = self._extract_crash_type(raw_trace)

        return trace

    def _parse_frame(self, line: str) -> StackFrame | None:
        """Parse a single stack frame line."""
        line = line.strip()

        # Python traceback format: File "path", line N, in function
        py_match = re.match(r'File "([^"]+)", line (\d+), in (.+)', line)
        if py_match:
            return StackFrame(
                function=py_match.group(3),
                filename=py_match.group(1),
                lineno=int(py_match.group(2)),
            )

        # GDB format: #N 0xADDR in function at file:line
        gdb_match = re.match(
            r"#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?(\S+)(?:\s+at\s+([^:]+):(\d+))?",
            line,
        )
        if gdb_match:
            return StackFrame(
                function=gdb_match.group(1),
                filename=gdb_match.group(2),
                lineno=int(gdb_match.group(3)) if gdb_match.group(3) else None,
            )

        # ASAN format: #N 0xADDR in function file:line
        asan_match = re.match(
            r"#\d+\s+0x([0-9a-fA-F]+)\s+in\s+(\S+)\s+(\S+):(\d+)",
            line,
        )
        if asan_match:
            return StackFrame(
                function=asan_match.group(2),
                filename=asan_match.group(3),
                lineno=int(asan_match.group(4)),
                address=asan_match.group(1),
            )

        # Simple function-only format
        func_match = re.match(r"^\s*(\w+)\s*$", line)
        if func_match and len(func_match.group(1)) > 2:
            return StackFrame(function=func_match.group(1))

        return None

    def _extract_crash_type(self, raw_trace: str) -> str | None:
        """Extract crash type from trace."""
        patterns = [
            (r"SIGSEGV", "SIGSEGV"),
            (r"SIGABRT", "SIGABRT"),
            (r"SIGFPE", "SIGFPE"),
            (r"SIGILL", "SIGILL"),
            (r"SIGBUS", "SIGBUS"),
            (r"AddressSanitizer:\s+(\w+)", None),  # Capture ASAN type
            (r"(\w+Error):", None),  # Python errors
            (r"(\w+Exception):", None),  # Python exceptions
        ]

        for pattern, default_type in patterns:
            match = re.search(pattern, raw_trace)
            if match:
                return default_type or match.group(1)

        return None

    def compute_lcs_similarity(self, trace1: StackTrace, trace2: StackTrace) -> float:
        """Compute LCS-based similarity between two traces.

        Args:
            trace1: First stack trace
            trace2: Second stack trace

        Returns:
            Similarity score between 0 and 1

        """
        seq1 = trace1.get_function_sequence(self.config.max_depth)
        seq2 = trace2.get_function_sequence(self.config.max_depth)

        if not seq1 or not seq2:
            return 0.0

        if len(seq1) < self.config.min_frames or len(seq2) < self.config.min_frames:
            return 0.0

        # Compute LCS length
        lcs_len = self._lcs_length(seq1, seq2)

        # Normalize by average length
        avg_len = (len(seq1) + len(seq2)) / 2
        return lcs_len / avg_len if avg_len > 0 else 0.0

    def _lcs_length(self, seq1: list[str], seq2: list[str]) -> int:
        """Compute length of longest common subsequence."""
        m, n = len(seq1), len(seq2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if seq1[i - 1] == seq2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

        return dp[m][n]

    def compute_weighted_similarity(
        self, trace1: StackTrace, trace2: StackTrace
    ) -> float:
        """Compute weighted similarity with frame importance decay.

        Innermost frames (closest to crash) are weighted more heavily.

        Args:
            trace1: First stack trace
            trace2: Second stack trace

        Returns:
            Weighted similarity score between 0 and 1

        """
        frames1 = trace1.get_user_frames()[: self.config.max_depth]
        frames2 = trace2.get_user_frames()[: self.config.max_depth]

        if not frames1 or not frames2:
            return 0.0

        # Build weighted comparison
        total_weight = 0.0
        matched_weight = 0.0

        for i, frame1 in enumerate(frames1):
            weight = self.config.weight_decay**i

            # Find best match in trace2
            best_match = 0.0
            for j, frame2 in enumerate(frames2):
                frame_sim = self._frame_similarity(frame1, frame2)
                # Penalize position differences
                pos_penalty = 1.0 / (1.0 + abs(i - j) * 0.1)
                best_match = max(best_match, frame_sim * pos_penalty)

            matched_weight += weight * best_match
            total_weight += weight

        return matched_weight / total_weight if total_weight > 0 else 0.0

    def _frame_similarity(self, frame1: StackFrame, frame2: StackFrame) -> float:
        """Compute similarity between two frames."""
        # Function name comparison
        name1 = frame1.normalized_name()
        name2 = frame2.normalized_name()

        if name1 == name2:
            name_sim = 1.0
        else:
            # Use sequence matcher for fuzzy matching
            name_sim = SequenceMatcher(None, name1, name2).ratio()

        # File name bonus
        file_bonus = 0.0
        if frame1.filename and frame2.filename:
            f1 = frame1.filename.split("/")[-1].split("\\")[-1]
            f2 = frame2.filename.split("/")[-1].split("\\")[-1]
            if f1 == f2:
                file_bonus = 0.1

        return min(1.0, name_sim + file_bonus)

    def compute_similarity(self, trace1: StackTrace, trace2: StackTrace) -> float:
        """Compute similarity based on configured method.

        Args:
            trace1: First stack trace
            trace2: Second stack trace

        Returns:
            Similarity score between 0 and 1

        """
        method = self.config.method

        if method == ClusteringMethod.LCS:
            return self.compute_lcs_similarity(trace1, trace2)
        elif method == ClusteringMethod.WEIGHTED_LCS:
            return self.compute_weighted_similarity(trace1, trace2)
        elif method == ClusteringMethod.SIGNATURE:
            return 1.0 if trace1.signature() == trace2.signature() else 0.0
        else:  # ClusteringMethod.HYBRID
            # Combine methods
            lcs_sim = self.compute_lcs_similarity(trace1, trace2)
            weighted_sim = self.compute_weighted_similarity(trace1, trace2)
            sig_match = 1.0 if trace1.signature() == trace2.signature() else 0.0
            return lcs_sim * 0.3 + weighted_sim * 0.5 + sig_match * 0.2

    def find_cluster(self, trace: StackTrace) -> CrashCluster | None:
        """Find the best matching cluster for a trace.

        Args:
            trace: Stack trace to cluster

        Returns:
            Matching cluster or None if no match

        """
        best_cluster = None
        best_similarity = 0.0

        for cluster in self.clusters.values():
            similarity = self.compute_similarity(trace, cluster.representative)

            if similarity >= self.config.similarity_threshold:
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_cluster = cluster

        return best_cluster

    def add_crash(self, crash_id: str, trace: StackTrace) -> tuple[CrashCluster, bool]:
        """Add a crash to clustering.

        Args:
            crash_id: Unique crash identifier
            trace: Stack trace for the crash

        Returns:
            Tuple of (cluster, is_new_cluster)

        """
        # Check cache
        self._trace_cache[crash_id] = trace

        # Find matching cluster
        cluster = self.find_cluster(trace)

        if cluster:
            # Add to existing cluster
            cluster.add_member(crash_id, trace)
            self._update_cluster_metrics(cluster)
            return cluster, False
        else:
            # Create new cluster
            cluster_id = f"cluster_{self._next_cluster_id}"
            self._next_cluster_id += 1

            cluster = CrashCluster(
                cluster_id=cluster_id,
                representative=trace,
                members=[crash_id],
                signatures={trace.signature()},
            )
            cluster.metrics.size = 1

            self.clusters[cluster_id] = cluster
            return cluster, True

    def _update_cluster_metrics(self, cluster: CrashCluster) -> None:
        """Update metrics for a cluster."""
        if len(cluster.members) < 2:
            return

        # Compute cohesion (average internal similarity)
        total_sim = 0.0
        comparisons = 0

        member_traces = [
            self._trace_cache[mid]
            for mid in cluster.members
            if mid in self._trace_cache
        ]

        for i, trace1 in enumerate(member_traces):
            for trace2 in member_traces[i + 1 :]:
                total_sim += self.compute_similarity(trace1, trace2)
                comparisons += 1

        if comparisons > 0:
            cluster.metrics.cohesion = total_sim / comparisons

        # Update representative confidence based on cohesion
        cluster.metrics.representative_confidence = cluster.metrics.cohesion

    def recluster(self) -> dict[str, str]:
        """Recluster all crashes with current configuration.

        Returns:
            Mapping of crash_id to new cluster_id

        """
        # Clear existing clusters
        self.clusters.clear()
        self._next_cluster_id = 0

        # Re-add all cached traces
        mapping: dict[str, str] = {}

        for crash_id, trace in self._trace_cache.items():
            cluster, _ = self.add_crash(crash_id, trace)
            mapping[crash_id] = cluster.cluster_id

        # Update all cluster metrics
        for cluster in self.clusters.values():
            self._update_cluster_metrics(cluster)

        return mapping

    def get_cluster_stats(self) -> dict[str, Any]:
        """Get statistics about current clustering.

        Returns:
            Dictionary with clustering statistics

        """
        if not self.clusters:
            return {
                "num_clusters": 0,
                "total_crashes": 0,
                "avg_cluster_size": 0,
                "singleton_clusters": 0,
                "avg_cohesion": 0,
            }

        sizes = [c.metrics.size for c in self.clusters.values()]
        cohesions = [c.metrics.cohesion for c in self.clusters.values()]

        return {
            "num_clusters": len(self.clusters),
            "total_crashes": sum(sizes),
            "avg_cluster_size": sum(sizes) / len(sizes),
            "max_cluster_size": max(sizes),
            "min_cluster_size": min(sizes),
            "singleton_clusters": sum(1 for s in sizes if s == 1),
            "avg_cohesion": sum(cohesions) / len(cohesions),
            "method": self.config.method.name,
        }

    def export_clusters(self) -> list[dict[str, Any]]:
        """Export clusters for serialization.

        Returns:
            List of cluster dictionaries

        """
        return [
            {
                "cluster_id": c.cluster_id,
                "size": c.metrics.size,
                "members": c.members,
                "signatures": list(c.signatures),
                "representative_signature": c.representative.signature(),
                "crash_type": c.representative.crash_type,
                "cohesion": c.metrics.cohesion,
                "quality_score": c.metrics.quality_score(),
            }
            for c in self.clusters.values()
        ]


class IncrementalClusterer(StackTraceClusterer):
    """Clusterer with incremental updates and stability tracking.

    Extends base clusterer with:
    - Stability metrics across clustering iterations
    - Cluster merge/split detection
    - Confidence scoring for deduplication decisions
    """

    def __init__(self, config: ClustererConfig | None = None):
        """Initialize incremental clusterer."""
        super().__init__(config)
        self._iteration = 0
        self._previous_mapping: dict[str, str] = {}
        self._stability_history: list[float] = []

    def add_crash_with_confidence(
        self, crash_id: str, trace: StackTrace
    ) -> tuple[CrashCluster, bool, float]:
        """Add crash with deduplication confidence score.

        Args:
            crash_id: Unique crash identifier
            trace: Stack trace for the crash

        Returns:
            Tuple of (cluster, is_new, confidence)

        """
        cluster, is_new = self.add_crash(crash_id, trace)

        # Calculate confidence
        if is_new:
            # Low confidence for singleton - might merge later
            confidence = 0.5
        else:
            # Confidence based on similarity to representative
            similarity = self.compute_similarity(trace, cluster.representative)
            # And cluster cohesion
            confidence = (similarity + cluster.metrics.cohesion) / 2

        return cluster, is_new, confidence

    def compute_stability(self) -> float:
        """Compute clustering stability compared to previous iteration.

        Returns:
            Stability score between 0 and 1

        """
        if not self._previous_mapping:
            return 1.0

        current_mapping = {
            cid: c.cluster_id for c in self.clusters.values() for cid in c.members
        }

        if not current_mapping:
            return 1.0

        # Count unchanged assignments
        unchanged = sum(
            1
            for cid, cluster in current_mapping.items()
            if self._previous_mapping.get(cid) == cluster
        )

        return unchanged / len(current_mapping)

    def iterate(self) -> float:
        """Perform one clustering iteration and update stability.

        Returns:
            Stability score for this iteration

        """
        # Store current mapping
        self._previous_mapping = {
            cid: c.cluster_id for c in self.clusters.values() for cid in c.members
        }

        # Recluster
        self.recluster()

        # Compute stability
        stability = self.compute_stability()
        self._stability_history.append(stability)

        # Update cluster stability metrics
        for cluster in self.clusters.values():
            cluster.metrics.stability = stability

        self._iteration += 1
        return stability

    def get_stability_stats(self) -> dict[str, Any]:
        """Get stability statistics.

        Returns:
            Dictionary with stability metrics

        """
        if not self._stability_history:
            return {
                "iterations": 0,
                "current_stability": 1.0,
                "avg_stability": 1.0,
                "converged": True,
            }

        return {
            "iterations": self._iteration,
            "current_stability": self._stability_history[-1],
            "avg_stability": sum(self._stability_history)
            / len(self._stability_history),
            "min_stability": min(self._stability_history),
            "max_stability": max(self._stability_history),
            "converged": len(self._stability_history) > 2
            and all(s > 0.95 for s in self._stability_history[-3:]),
        }
