"""Corpus Management for Coverage-Guided Fuzzing

Intelligent seed selection, prioritization, and corpus evolution
based on coverage feedback and historical learning.
"""

import heapq
import json
import pickle  # nosec B403 - pickle used for internal corpus serialization only (trusted data)
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from dicom_fuzzer.utils.hashing import short_hash

from .coverage_instrumentation import CoverageInfo, calculate_coverage_distance


class SeedPriority(Enum):
    """Priority levels for seed scheduling."""

    CRITICAL = 1  # Discovers new coverage
    HIGH = 2  # Recent coverage gains
    NORMAL = 3  # Standard seeds
    LOW = 4  # Well-explored seeds
    MINIMAL = 5  # Redundant/duplicate coverage


@dataclass
class Seed:
    """Represents a single seed in the corpus."""

    id: str
    data: bytes
    coverage: CoverageInfo
    priority: SeedPriority = SeedPriority.NORMAL
    energy: float = 1.0  # How many mutations to perform
    executions: int = 0
    discoveries: int = 0  # New coverage discoveries
    crashes: int = 0
    creation_time: float = field(default_factory=time.time)
    last_executed: float = field(default_factory=time.time)
    parent_id: str | None = None
    mutation_history: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __lt__(self, other: "Seed") -> bool:
        """Compare seeds by priority and energy."""
        if self.priority.value != other.priority.value:
            return self.priority.value < other.priority.value
        return self.energy > other.energy

    def calculate_hash(self) -> str:
        """Calculate unique hash for this seed."""
        return short_hash(self.data)

    def update_priority(self, coverage_gain: bool = False) -> None:
        """Update seed priority based on performance."""
        if coverage_gain:
            self.discoveries += 1
            self.priority = SeedPriority.CRITICAL
            self.energy *= 2  # Double energy for productive seeds
        elif self.discoveries > 0 and self.executions < 10:
            self.priority = SeedPriority.HIGH
        elif self.executions > 100 and self.discoveries == 0:
            self.priority = SeedPriority.LOW
            self.energy *= 0.5  # Reduce energy for unproductive seeds
        elif self.executions > 500:
            self.priority = SeedPriority.MINIMAL
            self.energy *= 0.1


@dataclass
class CorpusStats:
    """Statistics for corpus management."""

    total_seeds: int = 0
    unique_coverage_signatures: int = 0
    total_edges_covered: int = 0
    total_executions: int = 0
    coverage_plateaus: int = 0
    last_coverage_increase: float = field(default_factory=time.time)
    coverage_history: list[tuple[float, int]] = field(default_factory=list)


class CorpusManager:
    """Manages the seed corpus for coverage-guided fuzzing.

    Implements intelligent seed selection, prioritization, and minimization.
    """

    def __init__(
        self,
        max_corpus_size: int = 1000,
        min_coverage_distance: float = 0.1,
        energy_allocation: str = "adaptive",
    ):
        """Initialize corpus manager.

        Args:
            max_corpus_size: Maximum number of seeds to maintain
            min_coverage_distance: Minimum distance for considering seeds unique
            energy_allocation: Strategy for energy allocation ('uniform', 'adaptive', 'exp')

        """
        self.max_corpus_size = max_corpus_size
        self.min_coverage_distance = min_coverage_distance
        self.energy_allocation = energy_allocation

        # Corpus storage
        self.seeds: dict[str, Seed] = {}
        self.seed_queue: list[Seed] = []  # Priority queue
        self.coverage_map: dict[str, set[str]] = defaultdict(
            set
        )  # Coverage -> seed IDs

        # Coverage tracking
        self.global_coverage = CoverageInfo()
        self.unique_edges: set[tuple] = set()
        self.untouched_edges: set[tuple] = set()

        # Statistics
        self.stats = CorpusStats()

        # Historical learning
        self.mutation_success_rate: dict[str, float] = defaultdict(float)
        self.seed_genealogy: dict[str, list[str]] = defaultdict(
            list
        )  # Parent -> children

    def add_seed(
        self,
        data: bytes,
        coverage: CoverageInfo,
        parent_id: str | None = None,
        mutation_type: str | None = None,
    ) -> Seed | None:
        """Add a new seed to the corpus if it provides value.

        Args:
            data: Seed data
            coverage: Coverage information for this seed
            parent_id: ID of parent seed (for genealogy tracking)
            mutation_type: Type of mutation that created this seed

        Returns:
            Seed object if added, None if rejected

        """
        seed_hash = short_hash(data)

        # Check if seed already exists
        if seed_hash in self.seeds:
            existing_seed = self.seeds[seed_hash]
            existing_seed.executions += 1
            return None

        # Check if coverage is unique enough
        if not self._is_coverage_unique(coverage):
            return None

        # Create new seed
        seed = Seed(id=seed_hash, data=data, coverage=coverage, parent_id=parent_id)

        if mutation_type:
            seed.mutation_history.append(mutation_type)

        # Check for new coverage
        new_edges = coverage.edges - self.global_coverage.edges
        if new_edges:
            seed.priority = SeedPriority.CRITICAL
            seed.energy = 2.0  # High energy for new coverage
            self.global_coverage.merge(coverage)
            self.stats.last_coverage_increase = time.time()

            # Update mutation success rate
            if mutation_type:
                self.mutation_success_rate[mutation_type] += 1

        # Add to corpus
        self.seeds[seed_hash] = seed
        heapq.heappush(self.seed_queue, seed)

        # Track genealogy
        if parent_id:
            self.seed_genealogy[parent_id].append(seed_hash)

        # Update stats
        self.stats.total_seeds = len(self.seeds)
        self.stats.total_edges_covered = len(self.global_coverage.edges)

        # Enforce corpus size limit
        if len(self.seeds) > self.max_corpus_size:
            self._minimize_corpus()

        return seed

    def add_entry(self, entry: Any, dataset: Any = None) -> None:
        """Add a corpus entry (compatibility method for tests).

        Args:
            entry: CorpusEntry object with entry_id and dataset
            dataset: Optional dataset if entry doesn't have one

        """
        # Handle both old-style (entry only) and new-style (entry, dataset) calls
        if dataset is None and hasattr(entry, "dataset"):
            dataset_to_use = entry.dataset
        elif dataset is not None:
            dataset_to_use = dataset
        else:
            # Entry doesn't have dataset attribute, use as dataset
            dataset_to_use = entry

        # Serialize dataset to bytes
        import io

        from pydicom import Dataset

        if isinstance(dataset_to_use, Dataset):
            output = io.BytesIO()
            dataset_to_use.save_as(output, write_like_original=False)
            data = output.getvalue()
        else:
            data = b""  # Empty data

        # Create minimal coverage info
        coverage = CoverageInfo(edges=set())

        # Add as seed
        self.add_seed(data, coverage)

    def get_next_seed(self) -> Seed | None:
        """Get the next seed for fuzzing based on priority.

        Implements smart seed scheduling.
        """
        if not self.seed_queue:
            return None

        # Get seed with highest priority
        seed = heapq.heappop(self.seed_queue)

        # Update execution stats
        seed.executions += 1
        seed.last_executed = time.time()
        self.stats.total_executions += 1

        # Re-calculate priority and energy
        self._update_seed_energy(seed)

        # Re-add to queue if still valuable
        if seed.priority != SeedPriority.MINIMAL:
            heapq.heappush(self.seed_queue, seed)

        return seed

    def _is_coverage_unique(self, coverage: CoverageInfo) -> bool:
        """Check if coverage is unique enough to warrant keeping."""
        if not self.seeds:
            return True

        # Calculate minimum distance to existing seeds
        min_distance = float("inf")
        for existing_seed in self.seeds.values():
            distance = calculate_coverage_distance(coverage, existing_seed.coverage)
            min_distance = min(min_distance, distance)

        return min_distance >= self.min_coverage_distance

    def _update_seed_energy(self, seed: Seed) -> None:
        """Update seed energy based on allocation strategy."""
        if self.energy_allocation == "uniform":
            seed.energy = 1.0

        elif self.energy_allocation == "adaptive":
            # Adaptive energy based on productivity
            if seed.discoveries > 0:
                seed.energy = min(
                    10.0, 2.0 * (seed.discoveries / max(seed.executions, 1))
                )
            else:
                seed.energy = max(0.1, 1.0 / (seed.executions + 1))

        elif self.energy_allocation == "exp":
            # Exponential decay
            seed.energy = 2.0 ** (-seed.executions / 10)

        # Boost energy for seeds covering untouched edges
        if self._covers_untouched_edges(seed):
            seed.energy *= 2

    def _covers_untouched_edges(self, seed: Seed) -> bool:
        """Check if seed covers previously untouched edges."""
        seed_edges = seed.coverage.edges
        return bool(seed_edges & self.untouched_edges)

    def _minimize_corpus(self) -> None:
        """Minimize corpus to maintain size limit.

        Removes redundant seeds while preserving coverage.
        """
        # Sort seeds by value (priority, coverage contribution)
        seed_values = []
        for seed_id, seed in self.seeds.items():
            # Calculate value score
            unique_edges = seed.coverage.edges - self._get_coverage_without_seed(
                seed_id
            )
            value = len(unique_edges) / (seed.executions + 1)
            seed_values.append((value, seed_id))

        seed_values.sort(reverse=True)

        # Keep top seeds
        seeds_to_keep = {seed_id for _, seed_id in seed_values[: self.max_corpus_size]}

        # Remove low-value seeds
        seeds_to_remove = set(self.seeds.keys()) - seeds_to_keep
        for seed_id in seeds_to_remove:
            del self.seeds[seed_id]

        # Rebuild priority queue
        self.seed_queue = list(self.seeds.values())
        heapq.heapify(self.seed_queue)

    def _get_coverage_without_seed(self, seed_id: str) -> set[tuple]:
        """Get total coverage excluding a specific seed."""
        coverage = set()
        for sid, seed in self.seeds.items():
            if sid != seed_id:
                coverage.update(seed.coverage.edges)
        return coverage

    def mark_untouched_edges(self, edges: set[tuple]) -> None:
        """Mark edges as untouched (high priority for exploration)."""
        self.untouched_edges.update(edges)

    def update_seed_crash(self, seed_id: str) -> None:
        """Update seed statistics when it causes a crash."""
        if seed_id in self.seeds:
            self.seeds[seed_id].crashes += 1

    def get_mutation_weights(self) -> dict[str, float]:
        """Get mutation weights based on historical success."""
        total_success = sum(self.mutation_success_rate.values())
        if total_success == 0:
            return {}

        return {
            mutation: success / total_success
            for mutation, success in self.mutation_success_rate.items()
        }

    def get_corpus_stats(self) -> dict[str, Any]:
        """Get current corpus statistics."""
        # Check for coverage plateau
        if self.stats.coverage_history:
            recent_coverage = [cov for _, cov in self.stats.coverage_history[-10:]]
            if len(recent_coverage) >= 10 and len(set(recent_coverage)) == 1:
                self.stats.coverage_plateaus += 1

        self.stats.coverage_history.append(
            (time.time(), len(self.global_coverage.edges))
        )

        return {
            "total_seeds": self.stats.total_seeds,
            "unique_coverage_signatures": len(
                {s.coverage.get_coverage_hash() for s in self.seeds.values()}
            ),
            "total_edges_covered": self.stats.total_edges_covered,
            "total_executions": self.stats.total_executions,
            "coverage_plateaus": self.stats.coverage_plateaus,
            "time_since_coverage_increase": time.time()
            - self.stats.last_coverage_increase,
            "mutation_success_rates": dict(self.mutation_success_rate),
            "seed_priorities": {
                priority.name: sum(
                    1 for s in self.seeds.values() if s.priority == priority
                )
                for priority in SeedPriority
            },
        }

    def save_corpus(self, directory: Path) -> None:
        """Save corpus to disk for later use."""
        directory.mkdir(parents=True, exist_ok=True)

        # Save seeds
        for seed_id, seed in self.seeds.items():
            seed_path = directory / f"{seed_id}.seed"
            with open(seed_path, "wb") as f:
                # nosemgrep: python.lang.security.deserialization.avoid-pickle
                pickle.dump(seed, f)  # Internal corpus data, not user input

        # Save metadata
        metadata = {
            "stats": self.get_corpus_stats(),
            "mutation_success_rate": dict(self.mutation_success_rate),
            "global_coverage_hash": self.global_coverage.get_coverage_hash(),
        }

        with open(directory / "corpus_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2, default=str)

    def load_corpus(self, directory: Path) -> None:
        """Load corpus from disk."""
        if not directory.exists():
            return

        # Load seeds
        for seed_path in directory.glob("*.seed"):
            with open(seed_path, "rb") as f:
                # nosec B301 - pickle.load from internal corpus directory (trusted source)
                # nosemgrep: python.lang.security.deserialization.avoid-pickle
                seed = pickle.load(f)  # nosec
                self.seeds[seed.id] = seed
                self.global_coverage.merge(seed.coverage)

        # Rebuild priority queue
        self.seed_queue = list(self.seeds.values())
        heapq.heapify(self.seed_queue)

        # Load metadata
        metadata_path = directory / "corpus_metadata.json"
        if metadata_path.exists():
            with open(metadata_path) as f:
                metadata = json.load(f)
                self.mutation_success_rate.update(
                    metadata.get("mutation_success_rate", {})
                )

        self.stats.total_seeds = len(self.seeds)
        self.stats.total_edges_covered = len(self.global_coverage.edges)


class CorpusMinimizer:
    """AFL-cmin style corpus minimization.

    Reduces corpus size while preserving coverage by finding the minimal
    set of seeds that covers all discovered edges.

    Algorithm:
    1. Build edge -> seed mapping
    2. Greedily select seeds that cover the most uncovered edges
    3. Remove seeds that provide no unique coverage
    """

    def __init__(self, corpus: CorpusManager):
        """Initialize minimizer with a corpus.

        Args:
            corpus: The corpus manager to minimize

        """
        self.corpus = corpus
        self._edge_to_seeds: dict[tuple, set[str]] = defaultdict(set)
        self._seed_to_edges: dict[str, set[tuple]] = {}

    def build_coverage_map(self) -> None:
        """Build mappings between edges and seeds."""
        self._edge_to_seeds.clear()
        self._seed_to_edges.clear()

        for seed_id, seed in self.corpus.seeds.items():
            edges = seed.coverage.edges
            self._seed_to_edges[seed_id] = edges

            for edge in edges:
                self._edge_to_seeds[edge].add(seed_id)

    def find_essential_seeds(self) -> set[str]:
        """Find seeds that are the only ones covering certain edges.

        Returns:
            Set of essential seed IDs

        """
        essential = set()

        for _edge, seed_ids in self._edge_to_seeds.items():
            if len(seed_ids) == 1:
                # This seed is the only one covering this edge
                essential.update(seed_ids)

        return essential

    def minimize_greedy(self, target_size: int | None = None) -> list[str]:
        """Perform greedy corpus minimization.

        Args:
            target_size: Optional target corpus size

        Returns:
            List of seed IDs to keep

        """
        self.build_coverage_map()

        # Start with essential seeds
        selected = self.find_essential_seeds()
        covered_edges: set[tuple] = set()

        # Add coverage from essential seeds
        for seed_id in selected:
            covered_edges.update(self._seed_to_edges.get(seed_id, set()))

        # All edges we need to cover
        all_edges = set(self._edge_to_seeds.keys())
        uncovered = all_edges - covered_edges

        # Greedily add seeds that cover the most uncovered edges
        remaining_seeds = set(self.corpus.seeds.keys()) - selected

        while uncovered and remaining_seeds:
            # Find seed that covers most uncovered edges
            best_seed = None
            best_coverage = 0

            for seed_id in remaining_seeds:
                seed_edges = self._seed_to_edges.get(seed_id, set())
                coverage = len(seed_edges & uncovered)

                if coverage > best_coverage:
                    best_coverage = coverage
                    best_seed = seed_id

            if best_seed is None or best_coverage == 0:
                break

            # Select this seed
            selected.add(best_seed)
            remaining_seeds.remove(best_seed)
            covered_edges.update(self._seed_to_edges.get(best_seed, set()))
            uncovered = all_edges - covered_edges

            # Check target size
            if target_size and len(selected) >= target_size:
                break

        return list(selected)

    def minimize_weighted(self) -> list[str]:
        """Minimize corpus using weighted selection.

        Considers:
        - Coverage contribution
        - Execution time (prefer faster seeds)
        - Discovery history (prefer productive seeds)

        Returns:
            List of seed IDs to keep

        """
        self.build_coverage_map()

        # Calculate seed scores
        scores: dict[str, float] = {}

        for seed_id, seed in self.corpus.seeds.items():
            edges = self._seed_to_edges.get(seed_id, set())

            # Base score from unique coverage
            unique_edges = sum(
                1 for e in edges if len(self._edge_to_seeds.get(e, set())) == 1
            )

            # Bonus for discoveries
            discovery_bonus = seed.discoveries * 0.5

            # Penalty for slow seeds (normalized exec time)
            # We don't have avg_exec_time stored, so skip this

            # Bonus for crash-finding
            crash_bonus = seed.crashes * 2

            scores[seed_id] = unique_edges + discovery_bonus + crash_bonus

        # Sort by score and greedily select
        sorted_seeds = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        selected = set()
        covered_edges: set[tuple] = set()
        all_edges = set(self._edge_to_seeds.keys())

        for seed_id, _ in sorted_seeds:
            seed_edges = self._seed_to_edges.get(seed_id, set())
            new_coverage = seed_edges - covered_edges

            if new_coverage:
                selected.add(seed_id)
                covered_edges.update(seed_edges)

            if covered_edges >= all_edges:
                break

        return list(selected)

    def get_redundant_seeds(self) -> list[str]:
        """Find seeds that provide no unique coverage.

        Returns:
            List of redundant seed IDs that can be safely removed

        """
        self.build_coverage_map()

        redundant = []

        for seed_id in self.corpus.seeds:
            edges = self._seed_to_edges.get(seed_id, set())

            # Check if all edges are covered by other seeds
            is_redundant = all(
                len(self._edge_to_seeds.get(e, set())) > 1 for e in edges
            )

            if is_redundant and edges:  # Don't mark seeds with no coverage
                redundant.append(seed_id)

        return redundant

    def get_coverage_stats(self) -> dict[str, int]:
        """Get statistics about corpus coverage.

        Returns:
            Dictionary with coverage statistics

        """
        self.build_coverage_map()

        essential = self.find_essential_seeds()
        redundant = self.get_redundant_seeds()

        # Edge frequency distribution
        single_coverage = sum(
            1 for seeds in self._edge_to_seeds.values() if len(seeds) == 1
        )
        multi_coverage = sum(
            1 for seeds in self._edge_to_seeds.values() if len(seeds) > 1
        )

        return {
            "total_seeds": len(self.corpus.seeds),
            "total_edges": len(self._edge_to_seeds),
            "essential_seeds": len(essential),
            "redundant_seeds": len(redundant),
            "single_coverage_edges": single_coverage,
            "multi_coverage_edges": multi_coverage,
            "potential_reduction": len(redundant),
        }


class HistoricalCorpusManager(CorpusManager):
    """Enhanced corpus manager with historical learning.

    Uses data from previous fuzzing campaigns to improve seed selection.
    """

    def __init__(self, history_dir: Path | None = None, **kwargs: Any) -> None:
        """Initialize with historical data."""
        super().__init__(**kwargs)
        self.history_dir = history_dir
        self.historical_seeds: list[Seed] = []

        if history_dir and history_dir.exists():
            self._load_historical_data()

    def _load_historical_data(self) -> None:
        """Load historical fuzzing results."""
        if self.history_dir is None:
            return
        for campaign_dir in self.history_dir.iterdir():
            if campaign_dir.is_dir():
                corpus_manager = CorpusManager()
                corpus_manager.load_corpus(campaign_dir)

                # Extract valuable seeds
                for seed in corpus_manager.seeds.values():
                    if seed.discoveries > 0 or seed.crashes > 0:
                        self.historical_seeds.append(seed)

    def initialize_from_history(self, max_seeds: int = 100) -> None:
        """Initialize corpus with best historical seeds."""
        # Sort by value (discoveries and crashes)
        valuable_seeds = sorted(
            self.historical_seeds,
            key=lambda s: (s.discoveries * 10 + s.crashes),
            reverse=True,
        )

        # Add top seeds to corpus
        for seed in valuable_seeds[:max_seeds]:
            self.add_seed(seed.data, seed.coverage)
