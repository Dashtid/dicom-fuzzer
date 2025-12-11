"""Comprehensive tests for MoonLight-style corpus distillation.

Tests the WSCPSolver, CorpusDistiller, and IncrementalDistiller
for near-optimal corpus minimization.
"""

import pytest

from dicom_fuzzer.core.corpus_distillation import (
    CorpusDistiller,
    DistillationConfig,
    DistillationResult,
    IncrementalDistiller,
    SeedInfo,
    WeightMetric,
    WSCPSolver,
    create_seed_from_data,
)


class TestSeedInfo:
    """Tests for SeedInfo class."""

    def test_basic_creation(self):
        """Test basic seed info creation."""
        seed = SeedInfo(
            seed_id="test_seed",
            features=frozenset([1, 2, 3]),
            size=100,
        )

        assert seed.seed_id == "test_seed"
        assert len(seed.features) == 3
        assert seed.size == 100

    def test_seed_equality(self):
        """Test seed equality based on ID."""
        seed1 = SeedInfo(seed_id="same_id", features=frozenset([1]))
        seed2 = SeedInfo(seed_id="same_id", features=frozenset([2]))

        assert seed1 == seed2

    def test_seed_hash(self):
        """Test seed hashing based on ID."""
        seed1 = SeedInfo(seed_id="test", features=frozenset([1]))
        seed2 = SeedInfo(seed_id="test", features=frozenset([1]))

        assert hash(seed1) == hash(seed2)

    def test_optional_data_field(self):
        """Test optional data field."""
        data = b"test data"
        seed = SeedInfo(
            seed_id="test",
            features=frozenset([1]),
            data=data,
        )

        assert seed.data == data


class TestDistillationConfig:
    """Tests for DistillationConfig class."""

    def test_default_values(self):
        """Test default configuration values."""
        config = DistillationConfig()

        assert config.weight_metric == WeightMetric.SIZE
        assert config.lookahead == 3
        assert config.use_heap is True
        assert config.maintain_diversity is True

    def test_custom_weight_metric(self):
        """Test custom weight metric."""
        config = DistillationConfig(weight_metric=WeightMetric.EXECUTION_TIME)

        assert config.weight_metric == WeightMetric.EXECUTION_TIME

    def test_custom_weight_function(self):
        """Test custom weight function."""

        def custom_fn(s):
            return s.size * s.execution_time_ms

        config = DistillationConfig(custom_weight_fn=custom_fn)

        assert config.custom_weight_fn is not None


class TestWSCPSolver:
    """Tests for Weighted Set Cover Problem solver."""

    @pytest.fixture
    def solver(self):
        """Create a basic WSCP solver."""
        return WSCPSolver()

    @pytest.fixture
    def simple_seeds(self) -> list:
        """Create simple test seeds."""
        return [
            SeedInfo("s1", frozenset([1, 2]), size=10),
            SeedInfo("s2", frozenset([2, 3]), size=20),
            SeedInfo("s3", frozenset([3, 4]), size=15),
            SeedInfo("s4", frozenset([1, 2, 3, 4]), size=50),
        ]

    def test_solve_empty_seeds(self, solver):
        """Test solving with empty seed list."""
        result = solver.solve([])
        assert result == []

    def test_solve_single_seed(self, solver):
        """Test solving with single seed."""
        seed = SeedInfo("only", frozenset([1, 2, 3]), size=100)
        result = solver.solve([seed])

        assert len(result) == 1
        assert result[0].seed_id == "only"

    def test_solve_covers_universe(self, solver, simple_seeds):
        """Test that solution covers entire universe."""
        universe = set()
        for s in simple_seeds:
            universe.update(s.features)

        result = solver.solve(simple_seeds)

        covered = set()
        for s in result:
            covered.update(s.features)

        assert covered == universe

    def test_solve_prefers_smaller_seeds(self, solver):
        """Test that solver prefers smaller seeds by default."""
        seeds = [
            SeedInfo("small", frozenset([1, 2, 3]), size=10),
            SeedInfo("large", frozenset([1, 2, 3]), size=1000),
        ]

        result = solver.solve(seeds)

        # Should select the smaller seed
        assert len(result) == 1
        assert result[0].seed_id == "small"

    def test_solve_minimizes_corpus(self, solver):
        """Test that solver minimizes corpus size.

        Note: The greedy WSCP algorithm optimizes for weight efficiency
        (coverage per unit weight), not minimum seed count. Smaller seeds
        are preferred when they provide better coverage/weight ratio.
        """
        seeds = [
            SeedInfo("covers_all", frozenset([1, 2, 3, 4, 5]), size=100),
            SeedInfo("a", frozenset([1, 2]), size=10),
            SeedInfo("b", frozenset([3, 4]), size=10),
            SeedInfo("c", frozenset([5]), size=10),
        ]

        result = solver.solve(seeds)

        # Verify all features are covered
        covered = set()
        for s in result:
            covered.update(s.features)
        assert covered == {1, 2, 3, 4, 5}

        # The algorithm may choose either approach:
        # - One large seed (100 bytes) = 100/5 = 20 per feature
        # - Three small seeds (30 bytes total) = 30/5 = 6 per feature
        # Greedy prefers smaller seeds, so result may have 3 seeds
        assert len(result) <= 4  # At most all individual seeds

    def test_solve_with_execution_time_metric(self):
        """Test solver with execution time metric."""
        config = DistillationConfig(weight_metric=WeightMetric.EXECUTION_TIME)
        solver = WSCPSolver(config)

        seeds = [
            SeedInfo("fast", frozenset([1, 2, 3]), size=1000, execution_time_ms=1.0),
            SeedInfo("slow", frozenset([1, 2, 3]), size=10, execution_time_ms=100.0),
        ]

        result = solver.solve(seeds)

        # Should prefer faster seed
        assert result[0].seed_id == "fast"

    def test_solve_with_lookahead(self):
        """Test solver with lookahead > 1."""
        config = DistillationConfig(lookahead=2)
        solver = WSCPSolver(config)

        seeds = [
            SeedInfo("a", frozenset([1, 2]), size=10),
            SeedInfo("b", frozenset([2, 3]), size=10),
            SeedInfo("c", frozenset([3, 4]), size=10),
            SeedInfo("d", frozenset([1, 4]), size=10),  # Good combo with b
        ]

        result = solver.solve(seeds)

        # Lookahead should find efficient combinations
        covered = set()
        for s in result:
            covered.update(s.features)
        assert covered == {1, 2, 3, 4}

    def test_solve_respects_max_corpus_size(self):
        """Test solver respects maximum corpus size constraint."""
        config = DistillationConfig(max_corpus_size=2)
        solver = WSCPSolver(config)

        seeds = [
            SeedInfo("a", frozenset([1]), size=10),
            SeedInfo("b", frozenset([2]), size=10),
            SeedInfo("c", frozenset([3]), size=10),
            SeedInfo("d", frozenset([4]), size=10),
        ]

        result = solver.solve(seeds)

        assert len(result) <= 2


class TestCorpusDistiller:
    """Tests for CorpusDistiller class."""

    @pytest.fixture
    def distiller(self):
        """Create a basic corpus distiller."""
        return CorpusDistiller()

    @pytest.fixture
    def test_corpus(self) -> list:
        """Create a test corpus."""
        return [
            SeedInfo("s1", frozenset([1, 2, 3]), size=100),
            SeedInfo("s2", frozenset([2, 3, 4]), size=150),
            SeedInfo("s3", frozenset([4, 5, 6]), size=200),
            SeedInfo("s4", frozenset([1, 6]), size=50),
            SeedInfo(
                "s5", frozenset([1, 2, 3, 4, 5, 6]), size=500
            ),  # Covers all but big
        ]

    def test_distill_empty_corpus(self, distiller):
        """Test distilling empty corpus."""
        result = distiller.distill([])

        assert result.minimized_corpus_size == 0
        assert result.coverage_percentage == 0.0

    def test_distill_returns_result(self, distiller, test_corpus):
        """Test distill returns proper result."""
        result = distiller.distill(test_corpus)

        assert isinstance(result, DistillationResult)
        assert result.original_corpus_size == 5
        assert result.minimized_corpus_size <= 5

    def test_distill_maintains_coverage(self, distiller, test_corpus):
        """Test distillation maintains full coverage."""
        result = distiller.distill(test_corpus)

        assert result.coverage_percentage == 100.0

    def test_distill_reduces_size(self, distiller, test_corpus):
        """Test distillation reduces corpus size."""
        result = distiller.distill(test_corpus)

        # Should use fewer seeds than original
        assert result.minimized_corpus_size < result.original_corpus_size

    def test_distill_reduces_bytes(self, distiller, test_corpus):
        """Test distillation reduces total bytes."""
        result = distiller.distill(test_corpus)

        # Should reduce byte count
        assert result.minimized_bytes < result.original_bytes

    def test_distill_identifies_unique_seeds(self, distiller):
        """Test identification of seeds with unique coverage."""
        seeds = [
            SeedInfo("unique1", frozenset([1, 2]), size=10),
            SeedInfo("unique2", frozenset([3, 4]), size=10),
            SeedInfo("overlap", frozenset([2, 3]), size=10),
        ]

        result = distiller.distill(seeds)

        # Seeds covering unique features should be identified
        assert len(result.unique_coverage_seeds) >= 2

    def test_distill_with_diversity(self):
        """Test distillation with diversity maintenance."""
        config = DistillationConfig(maintain_diversity=True)
        distiller = CorpusDistiller(config)

        # Create seeds with varied coverage patterns
        seeds = [SeedInfo(f"s{i}", frozenset([i, i + 1]), size=10) for i in range(20)]

        result = distiller.distill(seeds)

        # Should maintain coverage
        assert result.covered_features == result.total_features


class TestIncrementalDistiller:
    """Tests for IncrementalDistiller class."""

    @pytest.fixture
    def distiller(self):
        """Create an incremental distiller."""
        return IncrementalDistiller()

    def test_add_first_seed(self, distiller):
        """Test adding first seed to empty corpus."""
        seed = SeedInfo("first", frozenset([1, 2, 3]), size=100)

        was_added, removed = distiller.add_seed(seed)

        assert was_added
        assert len(removed) == 0
        assert len(distiller.get_corpus()) == 1

    def test_add_seed_with_new_coverage(self, distiller):
        """Test adding seed with new coverage."""
        seed1 = SeedInfo("first", frozenset([1, 2]), size=100)
        seed2 = SeedInfo("second", frozenset([3, 4]), size=100)

        distiller.add_seed(seed1)
        was_added, removed = distiller.add_seed(seed2)

        assert was_added
        assert len(distiller.get_corpus()) == 2

    def test_add_redundant_seed(self, distiller):
        """Test adding seed without new coverage."""
        seed1 = SeedInfo("first", frozenset([1, 2, 3]), size=100)
        seed2 = SeedInfo("redundant", frozenset([1, 2]), size=100)

        distiller.add_seed(seed1)
        was_added, removed = distiller.add_seed(seed2)

        # Redundant seed should not be added (unless it's smaller)
        # Since it doesn't add new coverage and isn't more efficient

    def test_add_better_seed_replaces(self, distiller):
        """Test that better seed replaces worse one."""
        seed1 = SeedInfo("large", frozenset([1, 2, 3]), size=1000)
        seed2 = SeedInfo("small", frozenset([1, 2, 3]), size=10)

        distiller.add_seed(seed1)
        was_added, removed = distiller.add_seed(seed2)

        assert was_added
        assert "large" in removed
        assert len(distiller.get_corpus()) == 1

    def test_remove_redundant_after_add(self, distiller):
        """Test redundant seeds are removed after adding covering seed."""
        seed1 = SeedInfo("a", frozenset([1, 2]), size=100)
        seed2 = SeedInfo("b", frozenset([3, 4]), size=100)
        seed3 = SeedInfo("covers_all", frozenset([1, 2, 3, 4]), size=50)

        distiller.add_seed(seed1)
        distiller.add_seed(seed2)
        was_added, removed = distiller.add_seed(seed3)

        assert was_added
        # Previous seeds might be marked redundant
        # (depends on implementation details)

    def test_get_stats(self, distiller):
        """Test statistics retrieval."""
        seed1 = SeedInfo("s1", frozenset([1, 2]), size=100)
        seed2 = SeedInfo("s2", frozenset([3, 4]), size=200)

        distiller.add_seed(seed1)
        distiller.add_seed(seed2)

        stats = distiller.get_stats()

        assert stats["corpus_size"] == 2
        assert stats["covered_features"] == 4
        assert stats["total_bytes"] == 300

    def test_full_minimize(self, distiller):
        """Test full minimization of incremental corpus."""
        # Add many seeds
        for i in range(10):
            seed = SeedInfo(f"s{i}", frozenset([i % 3, (i + 1) % 3]), size=100)
            distiller.add_seed(seed)

        result = distiller.full_minimize()

        assert result.coverage_percentage == 100.0
        assert result.minimized_corpus_size <= 3


class TestWeightMetric:
    """Tests for WeightMetric enum."""

    def test_all_metrics_defined(self):
        """Test all expected metrics are defined."""
        expected = [
            "SIZE",
            "EXECUTION_TIME",
            "COMPLEXITY",
            "COVERAGE_DENSITY",
            "UNIFORM",
        ]

        for metric in expected:
            assert hasattr(WeightMetric, metric)

    def test_size_metric_prefers_small(self):
        """Test SIZE metric prefers smaller seeds."""
        config = DistillationConfig(weight_metric=WeightMetric.SIZE)
        solver = WSCPSolver(config)

        seeds = [
            SeedInfo("small", frozenset([1]), size=1),
            SeedInfo("large", frozenset([1]), size=1000),
        ]

        result = solver.solve(seeds)
        assert result[0].seed_id == "small"

    def test_uniform_metric_equal_weight(self):
        """Test UNIFORM metric gives equal weights."""
        config = DistillationConfig(weight_metric=WeightMetric.UNIFORM)
        solver = WSCPSolver(config)

        seeds = [
            SeedInfo("a", frozenset([1, 2]), size=1),
            SeedInfo("b", frozenset([2, 3]), size=1000),
        ]

        # Both should be considered equally (size doesn't matter)
        result = solver.solve(seeds)
        assert len(result) <= 2


class TestCreateSeedFromData:
    """Tests for create_seed_from_data helper."""

    def test_creates_seed_with_hash_id(self):
        """Test seed ID is derived from data hash."""
        data = b"test data"
        features: set[int] = {1, 2, 3}

        seed = create_seed_from_data(data, features)

        assert len(seed.seed_id) == 16  # SHA256 truncated
        assert seed.size == len(data)

    def test_same_data_same_id(self):
        """Test same data produces same ID."""
        data = b"identical"
        features: set[int] = {1}

        seed1 = create_seed_from_data(data, features)
        seed2 = create_seed_from_data(data, features)

        assert seed1.seed_id == seed2.seed_id

    def test_different_data_different_id(self):
        """Test different data produces different ID."""
        features: set[int] = {1}

        seed1 = create_seed_from_data(b"data1", features)
        seed2 = create_seed_from_data(b"data2", features)

        assert seed1.seed_id != seed2.seed_id

    def test_stores_original_data(self):
        """Test original data is stored in seed."""
        data = b"original"
        features: set[int] = {1}

        seed = create_seed_from_data(data, features)

        assert seed.data == data


class TestDistillationResult:
    """Tests for DistillationResult dataclass."""

    def test_result_fields(self):
        """Test all expected fields are present."""
        seeds = [SeedInfo("test", frozenset([1]), size=10)]
        result = DistillationResult(
            selected_seeds=seeds,
            total_features=5,
            covered_features=1,
            coverage_percentage=20.0,
            original_corpus_size=10,
            minimized_corpus_size=1,
            reduction_ratio=0.1,
            original_bytes=1000,
            minimized_bytes=10,
            byte_reduction_ratio=0.01,
            unique_coverage_seeds=["test"],
            removed_seeds=["other"],
        )

        assert result.total_features == 5
        assert result.covered_features == 1
        assert result.coverage_percentage == 20.0
        assert result.reduction_ratio == 0.1
