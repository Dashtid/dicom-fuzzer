"""Comprehensive tests for stack trace clustering.

Tests the StackTraceClusterer and related classes for
CASR/ECHO-style crash deduplication.
"""

import pytest

from dicom_fuzzer.core.stack_trace_clusterer import (
    ClustererConfig,
    ClusteringMethod,
    ClusterMetrics,
    CrashCluster,
    IncrementalClusterer,
    StackFrame,
    StackTrace,
    StackTraceClusterer,
)


class TestStackFrame:
    """Tests for StackFrame class."""

    def test_basic_creation(self):
        """Test basic frame creation."""
        frame = StackFrame(function="test_func", filename="test.py", lineno=42)

        assert frame.function == "test_func"
        assert frame.filename == "test.py"
        assert frame.lineno == 42
        assert not frame.is_system

    def test_normalized_name_simple(self):
        """Test simple function name normalization."""
        frame = StackFrame(function="my_function")
        assert frame.normalized_name() == "my_function"

    def test_normalized_name_with_templates(self):
        """Test normalization removes C++ templates."""
        frame = StackFrame(function="std::vector<int, std::allocator<int>>::push_back")
        normalized = frame.normalized_name()
        assert "<int, std::allocator<int>>" not in normalized
        assert "<>" in normalized

    def test_normalized_name_with_arguments(self):
        """Test normalization removes function arguments."""
        frame = StackFrame(function="foo(int x, char* y)")
        normalized = frame.normalized_name()
        assert "()" in normalized
        assert "int x" not in normalized

    def test_normalized_name_with_address(self):
        """Test normalization removes address suffix."""
        frame = StackFrame(function="malloc+0x123abc")
        normalized = frame.normalized_name()
        assert "+0x123abc" not in normalized

    def test_signature_generation(self):
        """Test frame signature generation."""
        frame1 = StackFrame(function="func", filename="/path/to/file.py")
        frame2 = StackFrame(function="func", filename="/other/path/file.py")

        # Same filename basename should give same signature
        assert frame1.signature() == frame2.signature()

    def test_signature_different_functions(self):
        """Test different functions have different signatures."""
        frame1 = StackFrame(function="func1", filename="file.py")
        frame2 = StackFrame(function="func2", filename="file.py")

        assert frame1.signature() != frame2.signature()


class TestStackTrace:
    """Tests for StackTrace class."""

    @pytest.fixture
    def sample_trace(self):
        """Create a sample stack trace."""
        return StackTrace(
            frames=[
                StackFrame(function="inner_func", filename="inner.py", lineno=10),
                StackFrame(function="middle_func", filename="middle.py", lineno=20),
                StackFrame(function="outer_func", filename="outer.py", lineno=30),
            ],
            crash_type="SIGSEGV",
        )

    def test_basic_creation(self, sample_trace):
        """Test basic trace creation."""
        assert len(sample_trace.frames) == 3
        assert sample_trace.crash_type == "SIGSEGV"

    def test_get_function_sequence(self, sample_trace):
        """Test function sequence extraction."""
        seq = sample_trace.get_function_sequence()
        assert seq == ["inner_func", "middle_func", "outer_func"]

    def test_get_function_sequence_with_depth(self, sample_trace):
        """Test function sequence with max depth."""
        seq = sample_trace.get_function_sequence(max_depth=2)
        assert len(seq) == 2
        assert seq == ["inner_func", "middle_func"]

    def test_get_user_frames_filters_system(self):
        """Test that system frames are filtered."""
        trace = StackTrace(
            frames=[
                StackFrame(function="user_func", is_system=False),
                StackFrame(function="libc_start", is_system=True),
                StackFrame(function="another_user", is_system=False),
            ]
        )

        user_frames = trace.get_user_frames()
        assert len(user_frames) == 2
        assert all(not f.is_system for f in user_frames)

    def test_signature_generation(self, sample_trace):
        """Test trace signature generation."""
        sig = sample_trace.signature()
        assert isinstance(sig, str)
        assert len(sig) == 16  # MD5 truncated to 16 chars

    def test_signature_consistency(self, sample_trace):
        """Test signature is consistent."""
        sig1 = sample_trace.signature()
        sig2 = sample_trace.signature()
        assert sig1 == sig2

    def test_different_traces_different_signatures(self):
        """Test different traces have different signatures."""
        trace1 = StackTrace(frames=[StackFrame(function="func1")])
        trace2 = StackTrace(frames=[StackFrame(function="func2")])

        assert trace1.signature() != trace2.signature()


class TestClusterMetrics:
    """Tests for ClusterMetrics class."""

    def test_default_values(self):
        """Test default metric values."""
        metrics = ClusterMetrics()

        assert metrics.size == 0
        assert metrics.stability == 1.0
        assert metrics.cohesion == 1.0
        assert metrics.separation == 0.0
        assert metrics.representative_confidence == 1.0

    def test_quality_score_calculation(self):
        """Test quality score calculation."""
        metrics = ClusterMetrics(
            cohesion=0.8,
            stability=0.9,
            separation=0.7,
            representative_confidence=0.95,
        )

        score = metrics.quality_score()
        # 0.8*0.4 + 0.9*0.3 + 0.7*0.2 + 0.95*0.1 = 0.32 + 0.27 + 0.14 + 0.095 = 0.825
        assert 0.82 < score < 0.83


class TestCrashCluster:
    """Tests for CrashCluster class."""

    @pytest.fixture
    def sample_cluster(self):
        """Create a sample cluster."""
        trace = StackTrace(frames=[StackFrame(function="crash_func")])
        return CrashCluster(
            cluster_id="test_cluster",
            representative=trace,
        )

    def test_basic_creation(self, sample_cluster):
        """Test basic cluster creation."""
        assert sample_cluster.cluster_id == "test_cluster"
        assert len(sample_cluster.members) == 0

    def test_add_member(self, sample_cluster):
        """Test adding members to cluster."""
        trace = StackTrace(frames=[StackFrame(function="crash_func")])
        sample_cluster.add_member("crash_1", trace)

        assert "crash_1" in sample_cluster.members
        assert sample_cluster.metrics.size == 1

    def test_add_multiple_members(self, sample_cluster):
        """Test adding multiple members."""
        for i in range(5):
            trace = StackTrace(frames=[StackFrame(function="crash_func")])
            sample_cluster.add_member(f"crash_{i}", trace)

        assert len(sample_cluster.members) == 5
        assert sample_cluster.metrics.size == 5


class TestClustererConfig:
    """Tests for ClustererConfig class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ClustererConfig()

        assert config.similarity_threshold == 0.7
        assert config.max_depth == 20
        assert config.weight_decay == 0.9
        assert config.min_frames == 2
        assert config.ignore_system_frames is True
        assert config.method == ClusteringMethod.WEIGHTED_LCS

    def test_custom_values(self):
        """Test custom configuration."""
        config = ClustererConfig(
            similarity_threshold=0.8,
            max_depth=10,
            method=ClusteringMethod.LCS,
        )

        assert config.similarity_threshold == 0.8
        assert config.max_depth == 10
        assert config.method == ClusteringMethod.LCS


class TestStackTraceClusterer:
    """Tests for StackTraceClusterer class."""

    @pytest.fixture
    def clusterer(self):
        """Create a clusterer instance."""
        return StackTraceClusterer()

    @pytest.fixture
    def python_trace(self):
        """Sample Python traceback."""
        return """Traceback (most recent call last):
  File "/app/main.py", line 42, in main
    process_data(data)
  File "/app/processor.py", line 100, in process_data
    parse_dicom(data)
  File "/app/parser.py", line 50, in parse_dicom
    raise ValueError("Invalid DICOM")
ValueError: Invalid DICOM"""

    @pytest.fixture
    def gdb_trace(self):
        """Sample GDB-style trace."""
        return """#0  0x00007fff8d4c3e48 in abort
#1  0x00007fff8d4c4d8c in __assert_fail at assert.c:92
#2  0x0000000100001234 in process_tag at parser.c:150
#3  0x0000000100002345 in parse_file at main.c:42"""

    def test_parse_python_trace(self, clusterer, python_trace):
        """Test parsing Python traceback."""
        trace = clusterer.parse_trace(python_trace)

        assert len(trace.frames) > 0
        func_names = [f.function for f in trace.frames]
        assert "main" in func_names or "process_data" in func_names

    def test_parse_gdb_trace(self, clusterer, gdb_trace):
        """Test parsing GDB-style trace."""
        trace = clusterer.parse_trace(gdb_trace)

        assert len(trace.frames) > 0
        func_names = [f.function for f in trace.frames]
        assert any("process_tag" in f or "parse_file" in f for f in func_names)

    def test_extract_crash_type_sigsegv(self, clusterer):
        """Test extracting SIGSEGV crash type."""
        trace = clusterer.parse_trace("Program received SIGSEGV at 0x1234")
        assert trace.crash_type == "SIGSEGV"

    def test_extract_crash_type_python_error(self, clusterer):
        """Test extracting Python error type."""
        trace = clusterer.parse_trace("ValueError: invalid input")
        assert trace.crash_type == "ValueError"

    def test_lcs_similarity_identical(self, clusterer):
        """Test LCS similarity for identical traces."""
        trace = StackTrace(
            frames=[
                StackFrame(function="func1"),
                StackFrame(function="func2"),
                StackFrame(function="func3"),
            ]
        )

        similarity = clusterer.compute_lcs_similarity(trace, trace)
        assert similarity == 1.0

    def test_lcs_similarity_different(self, clusterer):
        """Test LCS similarity for different traces."""
        trace1 = StackTrace(
            frames=[
                StackFrame(function="func1"),
                StackFrame(function="func2"),
            ]
        )
        trace2 = StackTrace(
            frames=[
                StackFrame(function="other1"),
                StackFrame(function="other2"),
            ]
        )

        similarity = clusterer.compute_lcs_similarity(trace1, trace2)
        assert similarity == 0.0

    def test_lcs_similarity_partial(self, clusterer):
        """Test LCS similarity for partially similar traces."""
        trace1 = StackTrace(
            frames=[
                StackFrame(function="unique1"),
                StackFrame(function="common"),
                StackFrame(function="unique2"),
            ]
        )
        trace2 = StackTrace(
            frames=[
                StackFrame(function="other1"),
                StackFrame(function="common"),
                StackFrame(function="other2"),
            ]
        )

        similarity = clusterer.compute_lcs_similarity(trace1, trace2)
        assert 0 < similarity < 1

    def test_weighted_similarity(self, clusterer):
        """Test weighted similarity computation."""
        trace1 = StackTrace(
            frames=[
                StackFrame(function="crash_point"),
                StackFrame(function="caller"),
            ]
        )
        trace2 = StackTrace(
            frames=[
                StackFrame(function="crash_point"),
                StackFrame(function="different_caller"),
            ]
        )

        similarity = clusterer.compute_weighted_similarity(trace1, trace2)
        # First frame matches exactly, second doesn't - should be > 0.5
        assert similarity > 0.5

    def test_add_crash_creates_cluster(self, clusterer):
        """Test that adding first crash creates new cluster."""
        trace = StackTrace(
            frames=[
                StackFrame(function="func1"),
                StackFrame(function="func2"),
            ]
        )

        cluster, is_new = clusterer.add_crash("crash_1", trace)

        assert is_new
        assert cluster is not None
        assert "crash_1" in cluster.members

    def test_add_similar_crash_joins_cluster(self, clusterer):
        """Test that similar crashes join same cluster."""
        trace1 = StackTrace(
            frames=[
                StackFrame(function="func1"),
                StackFrame(function="func2"),
            ]
        )
        trace2 = StackTrace(
            frames=[
                StackFrame(function="func1"),
                StackFrame(function="func2"),
            ]
        )

        cluster1, is_new1 = clusterer.add_crash("crash_1", trace1)
        cluster2, is_new2 = clusterer.add_crash("crash_2", trace2)

        assert is_new1
        assert not is_new2
        assert cluster1.cluster_id == cluster2.cluster_id

    def test_add_different_crash_creates_new_cluster(self, clusterer):
        """Test that different crashes create separate clusters."""
        trace1 = StackTrace(
            frames=[
                StackFrame(function="func1"),
                StackFrame(function="func2"),
            ]
        )
        trace2 = StackTrace(
            frames=[
                StackFrame(function="completely_different"),
                StackFrame(function="other_func"),
            ]
        )

        cluster1, is_new1 = clusterer.add_crash("crash_1", trace1)
        cluster2, is_new2 = clusterer.add_crash("crash_2", trace2)

        assert is_new1
        assert is_new2
        assert cluster1.cluster_id != cluster2.cluster_id

    def test_get_cluster_stats(self, clusterer):
        """Test cluster statistics."""
        # Add some crashes
        for i in range(5):
            trace = StackTrace(frames=[StackFrame(function=f"func_{i % 2}")])
            clusterer.add_crash(f"crash_{i}", trace)

        stats = clusterer.get_cluster_stats()

        assert stats["total_crashes"] == 5
        assert stats["num_clusters"] > 0
        assert "avg_cluster_size" in stats
        assert "method" in stats

    def test_export_clusters(self, clusterer):
        """Test cluster export."""
        trace = StackTrace(frames=[StackFrame(function="func")])
        clusterer.add_crash("crash_1", trace)
        clusterer.add_crash("crash_2", trace)

        exported = clusterer.export_clusters()

        assert len(exported) > 0
        assert "cluster_id" in exported[0]
        assert "members" in exported[0]
        assert "size" in exported[0]


class TestIncrementalClusterer:
    """Tests for IncrementalClusterer class."""

    @pytest.fixture
    def clusterer(self):
        """Create an incremental clusterer."""
        return IncrementalClusterer()

    def test_add_crash_with_confidence(self, clusterer):
        """Test adding crash returns confidence."""
        trace = StackTrace(
            frames=[
                StackFrame(function="func1"),
                StackFrame(function="func2"),
            ]
        )

        cluster, is_new, confidence = clusterer.add_crash_with_confidence(
            "crash_1", trace
        )

        assert cluster is not None
        assert is_new
        assert 0 <= confidence <= 1

    def test_confidence_increases_for_similar_crashes(self, clusterer):
        """Test confidence increases for similar crashes."""
        trace = StackTrace(
            frames=[
                StackFrame(function="func1"),
                StackFrame(function="func2"),
            ]
        )

        cluster1, _, conf1 = clusterer.add_crash_with_confidence("crash_1", trace)
        cluster2, _, conf2 = clusterer.add_crash_with_confidence("crash_2", trace)

        # Second crash joining existing cluster should have higher confidence
        assert conf2 > conf1

    def test_stability_computation(self, clusterer):
        """Test stability is computed correctly."""
        # Initial stability should be 1.0
        initial_stability = clusterer.compute_stability()
        assert initial_stability == 1.0

    def test_iterate_updates_stability(self, clusterer):
        """Test that iterate updates stability metrics."""
        # Add some crashes
        for i in range(3):
            trace = StackTrace(frames=[StackFrame(function=f"func_{i}")])
            clusterer.add_crash(f"crash_{i}", trace)

        stability = clusterer.iterate()

        assert 0 <= stability <= 1

    def test_stability_stats(self, clusterer):
        """Test stability statistics."""
        stats = clusterer.get_stability_stats()

        assert "iterations" in stats
        assert "current_stability" in stats
        assert "converged" in stats
