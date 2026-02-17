"""Corpus Management for DICOM Fuzzing.

Manages a collection of test cases (seeds) for fuzzing. Supports lazy loading
of DICOM datasets and tracking of fitness scores for seed selection.
"""

import copy
import json
import shutil
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pydicom
from pydicom.dataset import Dataset

from dicom_fuzzer.core.corpus.coverage_types import CoverageSnapshot
from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CorpusEntry(SerializableMixin):
    """Represents a single test case in the corpus.

    OPTIMIZATION: Uses lazy loading for datasets - stores the path and only loads
    the DICOM data when actually accessed. This reduces memory by 50-70% and speeds
    up corpus initialization by 3-5x.

    Attributes:
        entry_id: Unique identifier for this corpus entry
        dataset: The DICOM dataset (test case) - lazy-loaded from _dataset_path
        coverage: Coverage snapshot for this test case
        fitness_score: How valuable this test case is (0.0 to 1.0)
        generation: Which generation this test case is from
        parent_id: ID of the parent test case (if mutated from another)
        crash_triggered: Whether this test case caused a crash
        timestamp: When this entry was added
        metadata: Additional metadata
        _dataset_path: Internal path to DICOM file for lazy loading
        _dataset_cache: Internal cached dataset after first load

    """

    entry_id: str
    dataset: Dataset | None = None
    coverage: CoverageSnapshot | None = None
    fitness_score: float = 0.0
    generation: int = 0
    parent_id: str | None = None
    crash_triggered: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=dict)

    _dataset_path: Path | None = field(default=None, repr=False)
    _dataset_cache: Dataset | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Handle lazy loading initialization."""
        if self.dataset is not None:
            # Dataset provided directly - cache it
            self._dataset_cache = self.dataset

    def get_dataset(self) -> Dataset | None:
        """Lazy-load dataset on first access.

        Returns:
            Dataset: The DICOM dataset, loaded from disk if needed

        """
        # Return cached dataset if available
        if self._dataset_cache is not None:
            return self._dataset_cache

        # Load from path if available
        if self._dataset_path is not None and self._dataset_path.exists():
            try:
                self._dataset_cache = pydicom.dcmread(self._dataset_path)
                logger.debug(f"Lazy-loaded dataset for entry {self.entry_id}")
                return self._dataset_cache
            except Exception as e:
                logger.error(
                    f"Failed to lazy-load dataset from {self._dataset_path}: {e}"
                )
                return None

        # No dataset available
        return None

    def set_dataset(self, dataset: Dataset, path: Path | None = None) -> None:
        """Set the dataset for this entry.

        Args:
            dataset: The DICOM dataset to store
            path: Optional path where dataset is/will be stored on disk

        """
        self._dataset_cache = dataset
        if path:
            self._dataset_path = path

    @property
    def data(self) -> bytes:
        """Get the dataset as bytes for mutation.

        Used by coverage-guided mutation to access raw DICOM bytes.

        Returns:
            Serialized DICOM dataset as bytes

        """
        import io

        dataset = self.get_dataset()
        if dataset is None:
            return b""

        # Serialize dataset to bytes
        output = io.BytesIO()
        dataset.save_as(output, write_like_original=False)
        return output.getvalue()

    def _custom_serialization(self, data: dict[str, Any]) -> dict[str, Any]:
        """Add computed fields and exclude dataset from serialization.

        Note: DICOM dataset is stored separately as .dcm file
        """
        # Add computed coverage_lines field
        data["coverage_lines"] = (
            len(self.coverage.lines_covered) if self.coverage else 0
        )

        # Exclude dataset and lazy-loading fields from serialization
        data.pop("dataset", None)
        data.pop("_dataset_path", None)
        data.pop("_dataset_cache", None)

        # Exclude coverage snapshot (too large, stored separately)
        data.pop("coverage", None)

        return data


class CorpusManager:
    """Manages the corpus of interesting test cases for coverage-guided fuzzing.

    Keeps a working set of the most interesting test cases and continuously
    mutates them to explore new code paths.
    """

    def __init__(
        self,
        corpus_dir: Path,
        max_corpus_size: int = 1000,
        min_fitness_threshold: float = 0.1,
    ):
        """Initialize the corpus manager.

        Args:
            corpus_dir: Directory to store corpus entries
            max_corpus_size: Maximum number of entries to keep
            min_fitness_threshold: Minimum fitness score to keep an entry

        """
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        self.max_corpus_size = max_corpus_size
        self.min_fitness_threshold = min_fitness_threshold

        # Thread safety lock for corpus operations
        self._lock = threading.RLock()

        # Corpus storage (protected by _lock)
        self.corpus: dict[str, CorpusEntry] = {}
        self.coverage_map: dict[str, set[str]] = {}  # coverage_hash -> entry_ids

        # Statistics (protected by _lock)
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

    def _extract_corpus_entry_fields(
        self,
        entry: CorpusEntry,
        coverage: CoverageSnapshot | None,
        parent_id: str | None,
        crash_triggered: bool,
    ) -> tuple[str, Dataset | None, CoverageSnapshot | None, str | None, bool]:
        """Extract fields from CorpusEntry for backward compatibility."""
        entry_id = entry.entry_id
        dataset = entry.dataset
        coverage = entry.coverage if hasattr(entry, "coverage") else coverage
        if hasattr(entry, "metadata") and entry.metadata:
            parent_id = entry.metadata.get("parent_id", parent_id)
            crash_triggered = entry.metadata.get("crash_triggered", crash_triggered)
        return entry_id, dataset, coverage, parent_id, crash_triggered

    def _is_duplicate_coverage(
        self, coverage: CoverageSnapshot, fitness: float, entry_id: str
    ) -> bool:
        """Check if we already have a better entry with this coverage."""
        cov_hash = coverage.coverage_hash()
        if cov_hash not in self.coverage_map:
            return False
        existing_ids = self.coverage_map[cov_hash]
        if not existing_ids:
            return False
        existing_entry = self.corpus[list(existing_ids)[0]]
        if existing_entry.fitness_score >= fitness:
            self.total_rejected += 1
            logger.debug(
                f"Rejected duplicate coverage {entry_id}",
                existing_entry=list(existing_ids)[0],
            )
            return True
        return False

    def add_entry(
        self,
        entry_id: str | CorpusEntry,
        dataset: Dataset | None = None,
        coverage: CoverageSnapshot | None = None,
        parent_id: str | None = None,
        crash_triggered: bool = False,
    ) -> bool:
        """Add a test case to the corpus.

        Only adds test cases that provide value -- either new coverage or
        crash-triggering capabilities.

        Supports both new API (individual parameters) and old API (CorpusEntry object).

        Args:
            entry_id: Unique identifier OR CorpusEntry object
            dataset: DICOM dataset to add (optional if entry_id is CorpusEntry)
            coverage: Coverage snapshot for this test case
            parent_id: Parent entry ID if this is a mutation
            crash_triggered: Whether this test case caused a crash

        Returns:
            True if entry was added, False if rejected

        """
        if isinstance(entry_id, CorpusEntry):
            entry_id, dataset, coverage, parent_id, crash_triggered = (
                self._extract_corpus_entry_fields(
                    entry_id, coverage, parent_id, crash_triggered
                )
            )

        if dataset is None:
            raise ValueError("dataset is required")

        fitness = self._calculate_fitness(dataset, coverage, crash_triggered)

        with self._lock:
            if fitness < self.min_fitness_threshold and not crash_triggered:
                self.total_rejected += 1
                logger.debug(
                    f"Rejected corpus entry {entry_id}",
                    fitness=fitness,
                    threshold=self.min_fitness_threshold,
                )
                return False

            if coverage and self._is_duplicate_coverage(coverage, fitness, entry_id):
                return False

            # Determine generation
            generation = 0
            if parent_id and parent_id in self.corpus:
                generation = self.corpus[parent_id].generation + 1

            # Create entry
            # CRITICAL: Use deepcopy to ensure the stored dataset is completely independent
            # of the original. Shallow copy (dataset.copy()) may share nested structures
            # like sequences, which could be corrupted if the original is modified.
            entry = CorpusEntry(
                entry_id=entry_id,
                dataset=copy.deepcopy(dataset),
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

    def get_best_entries(self, count: int = 10) -> list[CorpusEntry]:
        """Get the highest fitness entries from the corpus.

        Args:
            count: Number of entries to return

        Returns:
            List of top entries sorted by fitness (highest first)

        """
        with self._lock:
            sorted_entries = sorted(
                self.corpus.values(), key=lambda e: e.fitness_score, reverse=True
            )
            return sorted_entries[:count]

    def get_best_seed(self) -> CorpusEntry | None:
        """Get the best seed for mutation.

        Returns:
            Best corpus entry, or None if corpus is empty

        """
        best = self.get_best_entries(count=1)
        return best[0] if best else None

    def get_random_entry(self) -> CorpusEntry | None:
        """Get a random entry from the corpus.

        Returns:
            Random corpus entry, or None if corpus is empty

        """
        import random

        with self._lock:
            if not self.corpus:
                return None

            # nosec B311 - random.choice is acceptable for fuzzing seed selection (non-cryptographic)
            entry_id = random.choice(list(self.corpus.keys()))  # nosec
            return self.corpus[entry_id]

    def get_entry(self, entry_id: str) -> CorpusEntry | None:
        """Get a specific entry by ID."""
        with self._lock:
            return self.corpus.get(entry_id)

    def size(self) -> int:
        """Get the current size of the corpus.

        Returns:
            Number of entries in the corpus

        """
        with self._lock:
            return len(self.corpus)

    def _calculate_fitness(
        self, dataset: Dataset, coverage: CoverageSnapshot | None, crash: bool
    ) -> float:
        """Calculate fitness score for a test case.

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

    def _evict_lowest_fitness(self) -> None:
        """Remove the lowest fitness entries when corpus is too large."""
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

    def _save_entry(self, entry: CorpusEntry) -> None:
        """Save a corpus entry to disk."""
        # Save DICOM dataset
        dcm_path = self.corpus_dir / f"{entry.entry_id}.dcm"
        try:
            dataset = entry.get_dataset()
            if dataset is None:
                logger.error(f"Cannot save entry {entry.entry_id}: dataset is None")
                return

            dataset.save_as(dcm_path, write_like_original=False)

            entry._dataset_path = dcm_path
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

    def _load_corpus(self) -> None:
        """Load corpus metadata from disk with lazy dataset loading."""
        if not self.corpus_dir.exists():
            return

        loaded = 0
        for dcm_file in self.corpus_dir.glob("*.dcm"):
            try:
                entry_id = dcm_file.stem
                meta_file = dcm_file.with_suffix(".json")

                with open(dcm_file, "rb") as f:
                    preamble = f.read(132)  # 128 bytes preamble + 4 bytes 'DICM'
                    if len(preamble) < 132 or preamble[128:132] != b"DICM":
                        logger.warning(
                            f"Invalid DICOM file (missing header): {dcm_file}"
                        )
                        continue

                # Load metadata if available
                metadata = {}
                if meta_file.exists():
                    with open(meta_file) as f:
                        metadata = json.load(f)

                # Create entry with lazy loading
                entry = CorpusEntry(
                    entry_id=entry_id,
                    dataset=None,  # Will be lazy-loaded
                    fitness_score=metadata.get("fitness_score", 0.5),
                    generation=metadata.get("generation", 0),
                    parent_id=metadata.get("parent_id"),
                    crash_triggered=metadata.get("crash_triggered", False),
                    _dataset_path=dcm_file,  # Store path for lazy loading
                )

                self.corpus[entry_id] = entry
                loaded += 1

            except Exception as e:
                logger.warning(f"Failed to load corpus entry {dcm_file}: {e}")

        if loaded > 0:
            logger.info(
                f"Loaded {loaded} corpus entries from disk (lazy loading enabled)"
            )

    def get_statistics(self) -> dict[str, Any]:
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

    def clear(self) -> None:
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
