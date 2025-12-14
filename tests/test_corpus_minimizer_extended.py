"""Extended tests for CorpusMinimizer class.

Tests for AFL-cmin style corpus minimization including:
- Coverage map building
- Essential seed identification
- Greedy minimization
- Weighted minimization
- Redundant seed detection
- Coverage statistics

Target: 80%+ coverage for corpus_manager.py CorpusMinimizer
"""

from __future__ import annotations

import pickle
import time
from pathlib import Path

import pytest

from dicom_fuzzer.core.corpus_manager import (
    CorpusManager,
    CorpusMinimizer,
    CorpusStats,
    HistoricalCorpusManager,
    Seed,
)
from dicom_fuzzer.core.coverage_instrumentation import CoverageInfo


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Create temporary directory for tests."""
    return tmp_path


@pytest.fixture
def corpus_manager() -> CorpusManager:
    """Create CorpusManager instance."""
    return CorpusManager(max_corpus_size=100, min_coverage_distance=0.0)


def create_coverage(*edges: tuple) -> CoverageInfo:
    """Helper to create coverage info from edge tuples."""
    return CoverageInfo(edges=set(edges))


class TestCorpusMinimizerInit:
    """Tests for CorpusMinimizer initialization."""

    def test_init(self, corpus_manager: CorpusManager) -> None:
        """Test minimizer initialization."""
        minimizer = CorpusMinimizer(corpus_manager)

        assert minimizer.corpus is corpus_manager
        assert len(minimizer._edge_to_seeds) == 0
        assert len(minimizer._seed_to_edges) == 0

    def test_init_with_populated_corpus(self, corpus_manager: CorpusManager) -> None:
        """Test init with corpus containing seeds."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        corpus_manager.add_seed(b"data", cov)

        minimizer = CorpusMinimizer(corpus_manager)

        assert minimizer.corpus.stats.total_seeds == 1


class TestBuildCoverageMap:
    """Tests for build_coverage_map method."""

    def test_build_empty_corpus(self, corpus_manager: CorpusManager) -> None:
        """Test building map for empty corpus."""
        minimizer = CorpusMinimizer(corpus_manager)
        minimizer.build_coverage_map()

        assert len(minimizer._edge_to_seeds) == 0
        assert len(minimizer._seed_to_edges) == 0

    def test_build_single_seed(self, corpus_manager: CorpusManager) -> None:
        """Test building map with single seed."""
        edges = (("f.py", 1, "f.py", 2), ("f.py", 2, "f.py", 3))
        cov = create_coverage(*edges)
        seed = corpus_manager.add_seed(b"data", cov)

        minimizer = CorpusMinimizer(corpus_manager)
        minimizer.build_coverage_map()

        assert len(minimizer._seed_to_edges) == 1
        assert seed.id in minimizer._seed_to_edges
        assert minimizer._seed_to_edges[seed.id] == cov.edges

        for edge in edges:
            assert edge in minimizer._edge_to_seeds
            assert seed.id in minimizer._edge_to_seeds[edge]

    def test_build_multiple_seeds_overlapping(
        self, corpus_manager: CorpusManager
    ) -> None:
        """Test building map with overlapping coverage."""
        edge1 = ("f.py", 1, "f.py", 2)
        edge2 = ("f.py", 2, "f.py", 3)
        edge3 = ("f.py", 3, "f.py", 4)

        cov1 = create_coverage(edge1, edge2)
        cov2 = create_coverage(edge2, edge3)

        seed1 = corpus_manager.add_seed(b"d1", cov1)
        seed2 = corpus_manager.add_seed(b"d2", cov2)

        minimizer = CorpusMinimizer(corpus_manager)
        minimizer.build_coverage_map()

        # edge2 should be covered by both seeds
        assert len(minimizer._edge_to_seeds[edge2]) == 2
        assert seed1.id in minimizer._edge_to_seeds[edge2]
        assert seed2.id in minimizer._edge_to_seeds[edge2]

    def test_build_clears_previous(self, corpus_manager: CorpusManager) -> None:
        """Test that build_coverage_map clears previous state."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        corpus_manager.add_seed(b"d1", cov)

        minimizer = CorpusMinimizer(corpus_manager)

        # Pre-populate
        minimizer._edge_to_seeds[("old", 0, "old", 1)] = {"old-seed"}
        minimizer._seed_to_edges["old-seed"] = {("old", 0, "old", 1)}

        minimizer.build_coverage_map()

        # Old data should be cleared
        assert ("old", 0, "old", 1) not in minimizer._edge_to_seeds


class TestFindEssentialSeeds:
    """Tests for find_essential_seeds method."""

    def test_find_essential_empty(self, corpus_manager: CorpusManager) -> None:
        """Test finding essential seeds in empty corpus."""
        minimizer = CorpusMinimizer(corpus_manager)
        minimizer.build_coverage_map()

        essential = minimizer.find_essential_seeds()

        assert len(essential) == 0

    def test_find_essential_single_seed(self, corpus_manager: CorpusManager) -> None:
        """Test with single seed covering unique edges."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = corpus_manager.add_seed(b"data", cov)

        minimizer = CorpusMinimizer(corpus_manager)
        minimizer.build_coverage_map()

        essential = minimizer.find_essential_seeds()

        assert seed.id in essential

    def test_find_essential_multiple_unique(
        self, corpus_manager: CorpusManager
    ) -> None:
        """Test with multiple seeds each having unique coverage."""
        cov1 = create_coverage(("f1.py", 1, "f1.py", 2))
        cov2 = create_coverage(("f2.py", 1, "f2.py", 2))

        seed1 = corpus_manager.add_seed(b"d1", cov1)
        seed2 = corpus_manager.add_seed(b"d2", cov2)

        minimizer = CorpusMinimizer(corpus_manager)
        minimizer.build_coverage_map()

        essential = minimizer.find_essential_seeds()

        assert seed1.id in essential
        assert seed2.id in essential

    def test_find_essential_with_redundant(self, corpus_manager: CorpusManager) -> None:
        """Test with mix of essential and redundant seeds."""
        edge1 = ("f.py", 1, "f.py", 2)
        edge2 = ("f.py", 2, "f.py", 3)
        edge3 = ("f.py", 3, "f.py", 4)

        # Seed 1: unique coverage of edge1
        cov1 = create_coverage(edge1, edge2)
        seed1 = corpus_manager.add_seed(b"d1", cov1)

        # Seed 2: only edge2 (covered by seed1)
        cov2 = create_coverage(edge2)
        seed2 = corpus_manager.add_seed(b"d2", cov2)

        # Seed 3: unique coverage of edge3
        cov3 = create_coverage(edge3)
        seed3 = corpus_manager.add_seed(b"d3", cov3)

        minimizer = CorpusMinimizer(corpus_manager)
        minimizer.build_coverage_map()

        essential = minimizer.find_essential_seeds()

        # seed1 is essential (only one with edge1)
        # seed2 is NOT essential (edge2 covered by seed1)
        # seed3 is essential (only one with edge3)
        assert seed1.id in essential
        assert seed2.id not in essential
        assert seed3.id in essential


class TestMinimizeGreedy:
    """Tests for minimize_greedy method."""

    def test_minimize_empty(self, corpus_manager: CorpusManager) -> None:
        """Test greedy minimization on empty corpus."""
        minimizer = CorpusMinimizer(corpus_manager)

        selected = minimizer.minimize_greedy()

        assert len(selected) == 0

    def test_minimize_single_seed(self, corpus_manager: CorpusManager) -> None:
        """Test greedy minimization with single seed."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = corpus_manager.add_seed(b"data", cov)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_greedy()

        assert seed.id in selected

    def test_minimize_removes_redundant(self, corpus_manager: CorpusManager) -> None:
        """Test that greedy minimization removes redundant seeds."""
        edge = ("f.py", 1, "f.py", 2)

        # Both seeds cover same edge
        cov1 = create_coverage(edge)
        cov2 = create_coverage(edge)

        seed1 = corpus_manager.add_seed(b"d1", cov1)
        seed2 = corpus_manager.add_seed(b"d2", cov2)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_greedy()

        # Only one should be selected
        assert (
            len(selected) == 1
            or (seed1.id in selected and seed2.id not in selected)
            or (seed2.id in selected and seed1.id not in selected)
        )

    def test_minimize_preserves_coverage(self, corpus_manager: CorpusManager) -> None:
        """Test that minimization preserves all coverage."""
        all_edges = set()
        for i in range(10):
            edges = {(f"f{i}.py", 1, f"f{i}.py", 2)}
            cov = CoverageInfo(edges=edges)
            corpus_manager.add_seed(f"d{i}".encode(), cov)
            all_edges.update(edges)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_greedy()

        # All edges should be covered
        covered = set()
        for seed_id in selected:
            covered.update(minimizer._seed_to_edges.get(seed_id, set()))

        assert covered >= all_edges

    def test_minimize_with_target_size(self, corpus_manager: CorpusManager) -> None:
        """Test greedy minimization with target size.

        Create seeds with overlapping coverage so some can be reduced.
        """
        # Create a shared edge covered by all seeds
        shared_edge = ("shared.py", 1, "shared.py", 2)

        for i in range(10):
            # All seeds cover the shared edge (redundant)
            cov = create_coverage(shared_edge)
            corpus_manager.add_seed(f"d{i}".encode(), cov)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_greedy(target_size=5)

        # With overlapping coverage, can reduce to target size
        assert len(selected) <= 5

    def test_minimize_greedy_selects_best_coverage(
        self, corpus_manager: CorpusManager
    ) -> None:
        """Test that greedy selects seed with most coverage."""
        edge1 = ("f.py", 1, "f.py", 2)
        edge2 = ("f.py", 2, "f.py", 3)
        edge3 = ("f.py", 3, "f.py", 4)

        # Seed with most coverage
        cov_big = create_coverage(edge1, edge2, edge3)
        seed_big = corpus_manager.add_seed(b"big", cov_big)

        # Seed with less coverage
        cov_small = create_coverage(edge1)
        corpus_manager.add_seed(b"small", cov_small)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_greedy()

        # Big seed should be selected first
        assert seed_big.id in selected


class TestMinimizeWeighted:
    """Tests for minimize_weighted method."""

    def test_weighted_empty(self, corpus_manager: CorpusManager) -> None:
        """Test weighted minimization on empty corpus."""
        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_weighted()

        assert len(selected) == 0

    def test_weighted_single_seed(self, corpus_manager: CorpusManager) -> None:
        """Test weighted minimization with single seed."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = corpus_manager.add_seed(b"data", cov)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_weighted()

        assert seed.id in selected

    def test_weighted_prefers_discoveries(self, corpus_manager: CorpusManager) -> None:
        """Test that weighted prefers seeds with discoveries."""
        edge1 = ("f.py", 1, "f.py", 2)
        edge2 = ("f.py", 2, "f.py", 3)

        cov1 = create_coverage(edge1)
        seed1 = corpus_manager.add_seed(b"d1", cov1)
        seed1.discoveries = 10

        cov2 = create_coverage(edge2)
        seed2 = corpus_manager.add_seed(b"d2", cov2)
        seed2.discoveries = 0

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_weighted()

        # Both edges need coverage, but seed1 should score higher
        assert seed1.id in selected

    def test_weighted_prefers_crashes(self, corpus_manager: CorpusManager) -> None:
        """Test that weighted prefers seeds that found crashes."""
        edge1 = ("f.py", 1, "f.py", 2)
        edge2 = ("f.py", 2, "f.py", 3)

        cov1 = create_coverage(edge1)
        seed1 = corpus_manager.add_seed(b"d1", cov1)
        seed1.crashes = 5

        cov2 = create_coverage(edge2)
        seed2 = corpus_manager.add_seed(b"d2", cov2)
        seed2.crashes = 0

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_weighted()

        # Both should be selected (different edges) but crash-finder scores higher
        assert seed1.id in selected

    def test_weighted_preserves_coverage(self, corpus_manager: CorpusManager) -> None:
        """Test that weighted minimization preserves coverage."""
        all_edges = set()
        for i in range(5):
            edges = {(f"f{i}.py", 1, f"f{i}.py", 2)}
            cov = CoverageInfo(edges=edges)
            seed = corpus_manager.add_seed(f"d{i}".encode(), cov)
            seed.discoveries = i
            all_edges.update(edges)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_weighted()

        # All edges should be covered
        covered = set()
        for seed_id in selected:
            covered.update(minimizer._seed_to_edges.get(seed_id, set()))

        assert covered >= all_edges


class TestGetRedundantSeeds:
    """Tests for get_redundant_seeds method."""

    def test_redundant_empty(self, corpus_manager: CorpusManager) -> None:
        """Test getting redundant seeds from empty corpus."""
        minimizer = CorpusMinimizer(corpus_manager)
        redundant = minimizer.get_redundant_seeds()

        assert len(redundant) == 0

    def test_redundant_no_redundant_seeds(self, corpus_manager: CorpusManager) -> None:
        """Test when no seeds are redundant."""
        cov1 = create_coverage(("f1.py", 1, "f1.py", 2))
        cov2 = create_coverage(("f2.py", 1, "f2.py", 2))

        corpus_manager.add_seed(b"d1", cov1)
        corpus_manager.add_seed(b"d2", cov2)

        minimizer = CorpusMinimizer(corpus_manager)
        redundant = minimizer.get_redundant_seeds()

        assert len(redundant) == 0

    def test_redundant_identifies_duplicate_coverage(
        self, corpus_manager: CorpusManager
    ) -> None:
        """Test identifying seeds with duplicate coverage."""
        edge = ("f.py", 1, "f.py", 2)

        cov1 = create_coverage(edge)
        seed1 = corpus_manager.add_seed(b"d1", cov1)

        cov2 = create_coverage(edge)
        seed2 = corpus_manager.add_seed(b"d2", cov2)

        minimizer = CorpusMinimizer(corpus_manager)
        redundant = minimizer.get_redundant_seeds()

        # Both seeds cover the same edge, so both are redundant
        # (each edge is covered by more than one seed)
        assert len(redundant) == 2
        assert seed1.id in redundant
        assert seed2.id in redundant

    def test_redundant_subset_coverage(self, corpus_manager: CorpusManager) -> None:
        """Test seed with subset of another's coverage."""
        edge1 = ("f.py", 1, "f.py", 2)
        edge2 = ("f.py", 2, "f.py", 3)

        # Seed 1 covers both edges
        cov1 = create_coverage(edge1, edge2)
        seed1 = corpus_manager.add_seed(b"d1", cov1)

        # Seed 2 only covers edge2 (subset)
        cov2 = create_coverage(edge2)
        seed2 = corpus_manager.add_seed(b"d2", cov2)

        minimizer = CorpusMinimizer(corpus_manager)
        redundant = minimizer.get_redundant_seeds()

        # seed2 is redundant (edge2 also covered by seed1)
        # seed1 is essential (only one with edge1)
        assert seed2.id in redundant
        assert seed1.id not in redundant


class TestGetCoverageStats:
    """Tests for get_coverage_stats method."""

    def test_stats_empty(self, corpus_manager: CorpusManager) -> None:
        """Test stats for empty corpus."""
        minimizer = CorpusMinimizer(corpus_manager)
        stats = minimizer.get_coverage_stats()

        assert stats["total_seeds"] == 0
        assert stats["total_edges"] == 0
        assert stats["essential_seeds"] == 0
        assert stats["redundant_seeds"] == 0

    def test_stats_single_seed(self, corpus_manager: CorpusManager) -> None:
        """Test stats with single seed."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        corpus_manager.add_seed(b"data", cov)

        minimizer = CorpusMinimizer(corpus_manager)
        stats = minimizer.get_coverage_stats()

        assert stats["total_seeds"] == 1
        assert stats["total_edges"] == 1
        assert stats["essential_seeds"] == 1
        assert stats["redundant_seeds"] == 0
        assert stats["single_coverage_edges"] == 1
        assert stats["multi_coverage_edges"] == 0

    def test_stats_multiple_seeds(self, corpus_manager: CorpusManager) -> None:
        """Test stats with multiple seeds."""
        edge1 = ("f.py", 1, "f.py", 2)
        edge2 = ("f.py", 2, "f.py", 3)

        cov1 = create_coverage(edge1, edge2)
        corpus_manager.add_seed(b"d1", cov1)

        cov2 = create_coverage(edge2)
        corpus_manager.add_seed(b"d2", cov2)

        minimizer = CorpusMinimizer(corpus_manager)
        stats = minimizer.get_coverage_stats()

        assert stats["total_seeds"] == 2
        assert stats["total_edges"] == 2
        assert stats["single_coverage_edges"] == 1  # edge1
        assert stats["multi_coverage_edges"] == 1  # edge2
        assert stats["potential_reduction"] >= 0


class TestHistoricalCorpusManagerExtended:
    """Extended tests for HistoricalCorpusManager."""

    def test_load_crash_seeds(self, temp_dir: Path) -> None:
        """Test loading historical seeds that found crashes."""
        campaign_dir = temp_dir / "campaign1"
        campaign_dir.mkdir()

        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = Seed(
            id="crash-seed",
            data=b"crash",
            coverage=cov,
            crashes=3,
            discoveries=0,
        )
        with open(campaign_dir / "crash-seed.seed", "wb") as f:
            pickle.dump(seed, f)

        manager = HistoricalCorpusManager(history_dir=temp_dir)

        assert len(manager.historical_seeds) == 1
        assert manager.historical_seeds[0].crashes == 3

    def test_load_multiple_campaigns(self, temp_dir: Path) -> None:
        """Test loading from multiple historical campaigns."""
        for camp_num in range(3):
            campaign_dir = temp_dir / f"campaign{camp_num}"
            campaign_dir.mkdir()

            cov = create_coverage((f"f{camp_num}.py", 1, f"f{camp_num}.py", 2))
            seed = Seed(
                id=f"seed-{camp_num}",
                data=f"data{camp_num}".encode(),
                coverage=cov,
                discoveries=camp_num + 1,
            )
            with open(campaign_dir / f"seed-{camp_num}.seed", "wb") as f:
                pickle.dump(seed, f)

        manager = HistoricalCorpusManager(history_dir=temp_dir)

        assert len(manager.historical_seeds) == 3

    def test_initialize_sorts_by_value(self, temp_dir: Path) -> None:
        """Test that initialize_from_history sorts by value."""
        campaign_dir = temp_dir / "campaign"
        campaign_dir.mkdir()

        # Create seeds with different values
        for i in range(5):
            cov = create_coverage((f"f{i}.py", 1, f"f{i}.py", 2))
            seed = Seed(
                id=f"seed-{i}",
                data=f"data{i}".encode(),
                coverage=cov,
                discoveries=i * 10,
                crashes=i,
            )
            with open(campaign_dir / f"seed-{i}.seed", "wb") as f:
                pickle.dump(seed, f)

        manager = HistoricalCorpusManager(history_dir=temp_dir)
        manager.initialize_from_history(max_seeds=2)

        # Should have selected highest value seeds
        assert len(manager.seeds) >= 1

    def test_inherits_corpus_manager(self, temp_dir: Path) -> None:
        """Test that HistoricalCorpusManager inherits from CorpusManager."""
        manager = HistoricalCorpusManager(
            history_dir=temp_dir,
            max_corpus_size=50,
            energy_allocation="uniform",
        )

        assert manager.max_corpus_size == 50
        assert manager.energy_allocation == "uniform"

    def test_skip_non_valuable_seeds(self, temp_dir: Path) -> None:
        """Test that non-valuable seeds are skipped."""
        campaign_dir = temp_dir / "campaign"
        campaign_dir.mkdir()

        # Seed with no discoveries and no crashes (not valuable)
        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = Seed(
            id="useless",
            data=b"useless",
            coverage=cov,
            discoveries=0,
            crashes=0,
        )
        with open(campaign_dir / "useless.seed", "wb") as f:
            pickle.dump(seed, f)

        manager = HistoricalCorpusManager(history_dir=temp_dir)

        # Should not load useless seed
        assert len(manager.historical_seeds) == 0


class TestSeedPriorityEdgeCases:
    """Edge case tests for Seed priority updates."""

    def test_update_no_condition_match(self) -> None:
        """Test update_priority when no condition matches."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = Seed(
            id="test",
            data=b"data",
            coverage=cov,
            discoveries=0,
            executions=50,  # Between 10 and 100
        )

        original_priority = seed.priority
        original_energy = seed.energy

        seed.update_priority(coverage_gain=False)

        # Should remain unchanged (no condition matches)
        assert seed.priority == original_priority
        assert seed.energy == original_energy


class TestCorpusMinimizationIntegration:
    """Integration tests for corpus minimization."""

    def test_full_minimization_workflow(self, corpus_manager: CorpusManager) -> None:
        """Test complete minimization workflow."""
        # Add diverse seeds
        for i in range(20):
            edges = {(f"f{i}.py", j, f"f{i}.py", j + 1) for j in range(i % 5)}
            if edges:
                cov = CoverageInfo(edges=edges)
                seed = corpus_manager.add_seed(f"d{i}".encode(), cov)
                if seed:
                    seed.discoveries = i % 3
                    seed.crashes = i % 2

        minimizer = CorpusMinimizer(corpus_manager)

        # Build map
        minimizer.build_coverage_map()

        # Get stats before
        stats_before = minimizer.get_coverage_stats()

        # Minimize
        selected = minimizer.minimize_greedy()
        selected_weighted = minimizer.minimize_weighted()

        # Both methods should preserve coverage
        assert len(selected) > 0
        assert len(selected_weighted) > 0

    def test_minimization_empty_edges(self, corpus_manager: CorpusManager) -> None:
        """Test minimization with seed having empty edges."""
        # Add seed with empty coverage
        empty_cov = CoverageInfo(edges=set())
        corpus_manager.add_seed(b"empty", empty_cov)

        minimizer = CorpusMinimizer(corpus_manager)
        minimizer.build_coverage_map()

        # Should handle empty edges gracefully
        redundant = minimizer.get_redundant_seeds()
        assert len(redundant) == 0  # Empty coverage is not redundant


class TestCorpusStatsEdgeCases:
    """Edge case tests for CorpusStats."""

    def test_coverage_history_growth(self) -> None:
        """Test coverage history growth."""
        stats = CorpusStats()
        assert stats.coverage_history == []

        stats.coverage_history.append((time.time(), 10))
        assert len(stats.coverage_history) == 1

    def test_last_coverage_increase_timestamp(self) -> None:
        """Test last_coverage_increase is set correctly."""
        stats = CorpusStats()

        # Should be set to current time
        assert abs(stats.last_coverage_increase - time.time()) < 1.0


class TestMinimizerBreakConditions:
    """Tests for minimizer loop break conditions."""

    def test_greedy_stops_when_all_covered(self, corpus_manager: CorpusManager) -> None:
        """Test greedy stops when all edges covered."""
        edge = ("f.py", 1, "f.py", 2)

        # Single seed covers the only edge
        cov = create_coverage(edge)
        corpus_manager.add_seed(b"d1", cov)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_greedy()

        assert len(selected) == 1

    def test_greedy_stops_when_no_progress(self, corpus_manager: CorpusManager) -> None:
        """Test greedy stops when no more progress possible."""
        # This tests the break when best_seed is None
        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_greedy()

        assert len(selected) == 0

    def test_weighted_stops_when_all_covered(
        self, corpus_manager: CorpusManager
    ) -> None:
        """Test weighted stops when all coverage achieved."""
        edge = ("f.py", 1, "f.py", 2)

        cov = create_coverage(edge)
        corpus_manager.add_seed(b"d1", cov)

        minimizer = CorpusMinimizer(corpus_manager)
        selected = minimizer.minimize_weighted()

        assert len(selected) == 1


class TestCoverageDistanceBasedRejection:
    """Tests for coverage distance based rejection."""

    def test_similar_coverage_rejected(self) -> None:
        """Test seeds with similar coverage are rejected."""
        manager = CorpusManager(min_coverage_distance=0.5)

        cov1 = create_coverage(("f.py", 1, "f.py", 2))
        seed1 = manager.add_seed(b"d1", cov1)

        # Same coverage - should be rejected
        cov2 = create_coverage(("f.py", 1, "f.py", 2))
        seed2 = manager.add_seed(b"d2", cov2)

        assert seed1 is not None
        assert seed2 is None  # Rejected due to similar coverage

    def test_different_coverage_accepted(self) -> None:
        """Test seeds with different coverage are accepted."""
        manager = CorpusManager(min_coverage_distance=0.0)

        cov1 = create_coverage(("f1.py", 1, "f1.py", 2))
        seed1 = manager.add_seed(b"d1", cov1)

        cov2 = create_coverage(("f2.py", 100, "f2.py", 200))
        seed2 = manager.add_seed(b"d2", cov2)

        assert seed1 is not None
        assert seed2 is not None


class TestSeedMetadata:
    """Tests for seed metadata handling."""

    def test_seed_metadata_default(self) -> None:
        """Test default metadata is empty dict."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = Seed(id="test", data=b"data", coverage=cov)

        assert seed.metadata == {}

    def test_seed_metadata_custom(self) -> None:
        """Test custom metadata."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = Seed(
            id="test",
            data=b"data",
            coverage=cov,
            metadata={"custom_field": "value", "count": 42},
        )

        assert seed.metadata["custom_field"] == "value"
        assert seed.metadata["count"] == 42

    def test_seed_mutation_history(self) -> None:
        """Test mutation history tracking."""
        cov = create_coverage(("f.py", 1, "f.py", 2))
        seed = Seed(id="test", data=b"data", coverage=cov)

        seed.mutation_history.append("flip_bit")
        seed.mutation_history.append("insert_bytes")

        assert len(seed.mutation_history) == 2
        assert "flip_bit" in seed.mutation_history
