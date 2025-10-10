"""
Coverage-Guided Fuzzing - Corpus Management

LEARNING OBJECTIVE: This module demonstrates how to manage a corpus of interesting
test cases for coverage-guided fuzzing.

CONCEPT: The corpus is like a library of valuable test cases. Each test case in
the corpus has discovered unique code paths. We keep mutating these cases to find
even more interesting inputs.

WHY: The corpus is the "memory" of our fuzzer. Without it, we'd forget which
inputs were valuable. With it, we build on previous discoveries.
"""

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pydicom
from pydicom.dataset import Dataset

from dicom_fuzzer.core.coverage_tracker import CoverageSnapshot
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CorpusEntry:
    """
    Represents a single test case in the corpus.

    CONCEPT: Each entry is like a record card that stores not just the test case,
    but also metadata about why it's valuable (coverage, crashes, etc.).

    Attributes:
        entry_id: Unique identifier for this corpus entry
        dataset: The DICOM dataset (test case)
        coverage: Coverage snapshot for this test case
        fitness_score: How valuable this test case is (0.0 to 1.0)
        generation: Which generation this test case is from
        parent_id: ID of the parent test case (if mutated from another)
        crash_triggered: Whether this test case caused a crash
        timestamp: When this entry was added
        metadata: Additional metadata
    """

    entry_id: str
    dataset: Dataset
    coverage: Optional[CoverageSnapshot] = None
    fitness_score: float = 0.0
    generation: int = 0
    parent_id: Optional[str] = None
    crash_triggered: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert entry to dictionary (for JSON serialization).

        Note: DICOM dataset is stored separately as .dcm file
        """
        return {
            "entry_id": self.entry_id,
            "fitness_score": self.fitness_score,
            "generation": self.generation,
            "parent_id": self.parent_id,
            "crash_triggered": self.crash_triggered,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "coverage_lines": (
                len(self.coverage.lines_covered) if self.coverage else 0
            ),
        }


class CorpusManager:
    """
    Manages the corpus of interesting test cases for coverage-guided fuzzing.

    LEARNING: The corpus manager is like a curator of a museum. It decides which
    test cases are worth keeping, which should be prioritized, and which can be
    discarded.

    CONCEPT: We keep a "working set" of the most interesting test cases and
    continuously mutate them to explore new code paths.

    WHY: A good corpus manager dramatically improves fuzzing efficiency by
    focusing effort on valuable test cases.
    """

    def __init__(
        self,
        corpus_dir: Path,
        max_corpus_size: int = 1000,
        min_fitness_threshold: float = 0.1,
    ):
        """
        Initialize the corpus manager.

        Args:
            corpus_dir: Directory to store corpus entries
            max_corpus_size: Maximum number of entries to keep
            min_fitness_threshold: Minimum fitness score to keep an entry
        """
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        self.max_corpus_size = max_corpus_size
        self.min_fitness_threshold = min_fitness_threshold

        # Corpus storage
        self.corpus: Dict[str, CorpusEntry] = {}
        self.coverage_map: Dict[str, Set[str]] = {}  # coverage_hash -> entry_ids

        # Statistics
        self.total_added = 0
        self.total_rejected = 0
        self.total_evicted = 0

        # Load existing corpus if available
        self._load_corpus()

        logger.info(
            "Corpus manager initialized",
            corpus_dir=str(self.corpus_dir),
            max_size=self.max_corpus_size,
            existing_entries=len(self.corpus),
        )

    def add_entry(
        self,
        entry_id: str,
        dataset: Dataset,
        coverage: Optional[CoverageSnapshot] = None,
        parent_id: Optional[str] = None,
        crash_triggered: bool = False,
    ) -> bool:
        """
        Add a test case to the corpus.

        CONCEPT: We only add test cases that provide value - either new coverage,
        or crash-triggering capabilities.

        Args:
            entry_id: Unique identifier for this entry
            dataset: DICOM dataset to add
            coverage: Coverage snapshot for this test case
            parent_id: Parent entry ID if this is a mutation
            crash_triggered: Whether this test case caused a crash

        Returns:
            True if entry was added, False if rejected
        """
        # Calculate fitness score
        fitness = self._calculate_fitness(dataset, coverage, crash_triggered)

        # Check if this meets minimum threshold
        if fitness < self.min_fitness_threshold and not crash_triggered:
            self.total_rejected += 1
            logger.debug(
                f"Rejected corpus entry {entry_id}",
                fitness=fitness,
                threshold=self.min_fitness_threshold,
            )
            return False

        # Check for duplicate coverage
        if coverage:
            cov_hash = coverage.coverage_hash()
            if cov_hash in self.coverage_map:
                # We already have a test case with this coverage
                existing_ids = self.coverage_map[cov_hash]
                if existing_ids:
                    # Keep the one with higher fitness
                    existing_entry = self.corpus[list(existing_ids)[0]]
                    if existing_entry.fitness_score >= fitness:
                        self.total_rejected += 1
                        logger.debug(
                            f"Rejected duplicate coverage {entry_id}",
                            existing_entry=list(existing_ids)[0],
                        )
                        return False

        # Determine generation
        generation = 0
        if parent_id and parent_id in self.corpus:
            generation = self.corpus[parent_id].generation + 1

        # Create entry
        entry = CorpusEntry(
            entry_id=entry_id,
            dataset=dataset.copy(),
            coverage=coverage,
            fitness_score=fitness,
            generation=generation,
            parent_id=parent_id,
            crash_triggered=crash_triggered,
        )

        # Add to corpus
        self.corpus[entry_id] = entry

        # Update coverage map
        if coverage:
            cov_hash = coverage.coverage_hash()
            if cov_hash not in self.coverage_map:
                self.coverage_map[cov_hash] = set()
            self.coverage_map[cov_hash].add(entry_id)

        self.total_added += 1

        # Save to disk
        self._save_entry(entry)

        logger.info(
            "Added corpus entry",
            entry_id=entry_id,
            fitness=fitness,
            generation=generation,
            crash=crash_triggered,
        )

        # Check if we need to evict
        if len(self.corpus) > self.max_corpus_size:
            self._evict_lowest_fitness()

        return True

    def get_best_entries(self, count: int = 10) -> List[CorpusEntry]:
        """
        Get the highest fitness entries from the corpus.

        CONCEPT: We prioritize mutating the most valuable test cases.
        These are the ones most likely to lead to new discoveries.

        Args:
            count: Number of entries to return

        Returns:
            List of top entries sorted by fitness (highest first)
        """
        sorted_entries = sorted(
            self.corpus.values(), key=lambda e: e.fitness_score, reverse=True
        )
        return sorted_entries[:count]

    def get_random_entry(self) -> Optional[CorpusEntry]:
        """
        Get a random entry from the corpus.

        CONCEPT: Sometimes randomness helps explore different paths.

        Returns:
            Random corpus entry, or None if corpus is empty
        """
        if not self.corpus:
            return None

        import random

        entry_id = random.choice(list(self.corpus.keys()))
        return self.corpus[entry_id]

    def get_entry(self, entry_id: str) -> Optional[CorpusEntry]:
        """Get a specific entry by ID."""
        return self.corpus.get(entry_id)

    def _calculate_fitness(
        self, dataset: Dataset, coverage: Optional[CoverageSnapshot], crash: bool
    ) -> float:
        """
        Calculate fitness score for a test case.

        CONCEPT: Fitness is a measure of how valuable a test case is.
        Crash-triggering cases are most valuable. Cases with new coverage
        are also valuable. The more unique coverage, the better.

        Args:
            dataset: DICOM dataset
            coverage: Coverage snapshot
            crash: Whether this caused a crash

        Returns:
            Fitness score from 0.0 (worthless) to 1.0 (extremely valuable)
        """
        # Crashes are extremely valuable
        if crash:
            return 1.0

        # No coverage data = low value
        if not coverage:
            return 0.1

        # Calculate based on coverage
        base_fitness = 0.3

        # Bonus for unique coverage
        if coverage.lines_covered:
            # More lines = higher fitness
            coverage_bonus = min(len(coverage.lines_covered) / 1000.0, 0.4)
            base_fitness += coverage_bonus

        # Bonus for branches
        if coverage.branches_covered:
            branch_bonus = min(len(coverage.branches_covered) / 100.0, 0.3)
            base_fitness += branch_bonus

        return min(base_fitness, 1.0)

    def _evict_lowest_fitness(self):
        """
        Remove the lowest fitness entries when corpus is too large.

        CONCEPT: We have limited resources, so we keep only the best test cases.
        This is like pruning a garden - removing weaker plants so stronger ones
        can thrive.
        """
        if len(self.corpus) <= self.max_corpus_size:
            return

        # Sort by fitness
        sorted_entries = sorted(self.corpus.items(), key=lambda x: x[1].fitness_score)

        # Calculate how many to evict
        num_to_evict = len(self.corpus) - self.max_corpus_size

        # Evict lowest fitness entries
        for entry_id, entry in sorted_entries[:num_to_evict]:
            # Remove from disk
            entry_path = self.corpus_dir / f"{entry_id}.dcm"
            if entry_path.exists():
                entry_path.unlink()

            # Remove from coverage map
            if entry.coverage:
                cov_hash = entry.coverage.coverage_hash()
                if cov_hash in self.coverage_map:
                    self.coverage_map[cov_hash].discard(entry_id)
                    if not self.coverage_map[cov_hash]:
                        del self.coverage_map[cov_hash]

            # Remove from corpus
            del self.corpus[entry_id]
            self.total_evicted += 1

        logger.info(f"Evicted {num_to_evict} low-fitness entries from corpus")

    def _save_entry(self, entry: CorpusEntry):
        """Save a corpus entry to disk."""
        # Save DICOM dataset
        dcm_path = self.corpus_dir / f"{entry.entry_id}.dcm"
        try:
            entry.dataset.save_as(dcm_path, write_like_original=False)
        except Exception as e:
            logger.error(f"Failed to save corpus entry {entry.entry_id}: {e}")
            return

        # Save metadata
        meta_path = self.corpus_dir / f"{entry.entry_id}.json"
        try:
            with open(meta_path, "w") as f:
                json.dump(entry.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metadata for {entry.entry_id}: {e}")

    def _load_corpus(self):
        """Load corpus from disk."""
        if not self.corpus_dir.exists():
            return

        loaded = 0
        for dcm_file in self.corpus_dir.glob("*.dcm"):
            try:
                entry_id = dcm_file.stem
                meta_file = dcm_file.with_suffix(".json")

                # Load dataset
                dataset = pydicom.dcmread(dcm_file)

                # Load metadata if available
                metadata = {}
                if meta_file.exists():
                    with open(meta_file) as f:
                        metadata = json.load(f)

                # Create entry
                entry = CorpusEntry(
                    entry_id=entry_id,
                    dataset=dataset,
                    fitness_score=metadata.get("fitness_score", 0.5),
                    generation=metadata.get("generation", 0),
                    parent_id=metadata.get("parent_id"),
                    crash_triggered=metadata.get("crash_triggered", False),
                )

                self.corpus[entry_id] = entry
                loaded += 1

            except Exception as e:
                logger.warning(f"Failed to load corpus entry {dcm_file}: {e}")

        if loaded > 0:
            logger.info(f"Loaded {loaded} corpus entries from disk")

    def get_statistics(self) -> Dict[str, Any]:
        """Get corpus statistics."""
        return {
            "total_entries": len(self.corpus),
            "max_size": self.max_corpus_size,
            "total_added": self.total_added,
            "total_rejected": self.total_rejected,
            "total_evicted": self.total_evicted,
            "unique_coverage_patterns": len(self.coverage_map),
            "avg_fitness": (
                sum(e.fitness_score for e in self.corpus.values()) / len(self.corpus)
                if self.corpus
                else 0.0
            ),
            "max_generation": (
                max(e.generation for e in self.corpus.values()) if self.corpus else 0
            ),
        }

    def clear(self):
        """Clear all corpus entries."""
        # Remove files
        if self.corpus_dir.exists():
            shutil.rmtree(self.corpus_dir)
            self.corpus_dir.mkdir(parents=True, exist_ok=True)

        # Clear in-memory data
        self.corpus.clear()
        self.coverage_map.clear()
        self.total_added = 0
        self.total_rejected = 0
        self.total_evicted = 0

        logger.info("Corpus cleared")
