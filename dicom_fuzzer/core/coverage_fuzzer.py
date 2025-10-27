"""Coverage-Guided Fuzzing - Main Orchestrator

LEARNING OBJECTIVE: This module demonstrates how to build a complete coverage-guided
fuzzer that intelligently explores code paths.

CONCEPT: This is the "brain" of coverage-guided fuzzing. It coordinates the coverage
tracker, corpus manager, and mutation strategies to systematically explore the target
application and find bugs.

WHY: This represents state-of-the-art fuzzing technology used by tools like AFL,
libFuzzer, and Hongfuzz. It's dramatically more effective than random fuzzing.
"""

import random
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydicom.dataset import Dataset

from dicom_fuzzer.core.corpus import CorpusEntry, CorpusManager
from dicom_fuzzer.core.coverage_tracker import CoverageSnapshot, CoverageTracker
from dicom_fuzzer.core.mutator import DicomMutator, MutationSeverity
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FuzzingCampaignStats:
    """Statistics for a fuzzing campaign.

    CONCEPT: Like a scoreboard that tracks our fuzzing progress and effectiveness.

    Attributes:
        campaign_id: Unique identifier for this campaign
        start_time: When the campaign started
        total_iterations: Total number of fuzzing iterations
        unique_crashes: Number of unique crashes found
        corpus_size: Current corpus size
        total_coverage: Total lines of code covered
        executions_per_second: Fuzzing throughput
        interesting_inputs_found: Number of inputs that increased coverage

    """

    campaign_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    start_time: datetime = field(default_factory=lambda: datetime.now(UTC))
    total_iterations: int = 0
    unique_crashes: int = 0
    corpus_size: int = 0
    total_coverage: int = 0
    executions_per_second: float = 0.0
    interesting_inputs_found: int = 0
    avg_fitness: float = 0.0

    def update_from_campaign(self, campaign: "CoverageGuidedFuzzer"):
        """Update stats from a fuzzing campaign."""
        elapsed = (datetime.now(UTC) - self.start_time).total_seconds()
        self.executions_per_second = (
            self.total_iterations / elapsed if elapsed > 0 else 0.0
        )
        corpus_stats = campaign.corpus_manager.get_statistics()
        self.corpus_size = corpus_stats["total_entries"]
        self.avg_fitness = corpus_stats["avg_fitness"]


class CoverageGuidedFuzzer:
    """Coverage-guided fuzzer for DICOM files.

    LEARNING: This is a complete, production-quality coverage-guided fuzzer.
    It implements the same principles as professional fuzzing tools.

    CONCEPT: The fuzzer maintains a corpus of interesting inputs, tracks which
    code paths have been explored, and intelligently mutates the corpus to
    discover new paths and bugs.

    HOW IT WORKS:
    1. Start with seed inputs (initial DICOM files)
    2. Execute each input and track coverage
    3. Keep inputs that discover new coverage
    4. Mutate interesting inputs to explore more paths
    5. Repeat until we've explored everything or found bugs

    WHY: This approach finds bugs 10-100x faster than random fuzzing because
    it learns from feedback and focuses effort on productive mutations.
    """

    def __init__(
        self,
        corpus_dir: Path,
        target_function: Callable | None = None,
        max_corpus_size: int = 1000,
        mutation_severity: MutationSeverity = MutationSeverity.MODERATE,
    ):
        """Initialize the coverage-guided fuzzer.

        Args:
            corpus_dir: Directory to store corpus
            target_function: Function to fuzz (takes Dataset, returns any)
            max_corpus_size: Maximum corpus size
            mutation_severity: Default mutation severity

        """
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.coverage_tracker = CoverageTracker(
            target_modules=["core", "strategies", "utils"]
        )
        self.corpus_manager = CorpusManager(
            corpus_dir=self.corpus_dir, max_corpus_size=max_corpus_size
        )
        self.mutator = DicomMutator()

        # Configuration
        self.target_function = target_function
        self.mutation_severity = mutation_severity

        # Statistics
        self.stats = FuzzingCampaignStats()
        self.crashes: list[dict[str, Any]] = []

        logger.info(
            "Coverage-guided fuzzer initialized",
            corpus_dir=str(self.corpus_dir),
            max_corpus_size=max_corpus_size,
        )

    def add_seed(self, dataset: Dataset, seed_id: str | None = None) -> str:
        """Add a seed input to the corpus.

        CONCEPT: Seeds are initial test cases that we know work. We'll mutate
        these to explore the input space.

        Args:
            dataset: DICOM dataset to use as seed
            seed_id: Optional identifier for this seed

        Returns:
            Entry ID for the seed

        """
        if seed_id is None:
            seed_id = f"seed_{uuid.uuid4().hex[:8]}"

        # Execute seed to get initial coverage
        coverage = None
        if self.target_function:
            coverage = self._execute_with_coverage(dataset, seed_id)

        # Add to corpus
        self.corpus_manager.add_entry(
            entry_id=seed_id,
            dataset=dataset,
            coverage=coverage,
            crash_triggered=False,
        )

        logger.info("Added seed to corpus", seed_id=seed_id)
        return seed_id

    def fuzz_iteration(self) -> CorpusEntry | None:
        """Perform one fuzzing iteration.

        CONCEPT: Each iteration picks an interesting input, mutates it,
        executes the mutation, and evaluates if it's worth keeping.

        Returns:
            New corpus entry if interesting, None otherwise

        """
        # Select input to mutate
        parent = self._select_input()
        if not parent:
            logger.warning("No corpus entries available for fuzzing")
            return None

        # Mutate it
        mutated_dataset = self._mutate_input(parent.dataset)

        # Generate entry ID
        entry_id = f"gen{parent.generation + 1}_{uuid.uuid4().hex[:8]}"

        # Execute and track coverage
        coverage = None
        crash = False

        try:
            if self.target_function:
                coverage = self._execute_with_coverage(mutated_dataset, entry_id)
        except Exception as e:
            # This mutation triggered a crash!
            crash = True
            self._record_crash(entry_id, parent.entry_id, mutated_dataset, e)

        # Check if this is interesting
        is_interesting = False
        if crash:
            is_interesting = True
        elif coverage and self.coverage_tracker.is_interesting(coverage):
            is_interesting = True
            self.stats.interesting_inputs_found += 1

        # Add to corpus if interesting
        if is_interesting:
            added = self.corpus_manager.add_entry(
                entry_id=entry_id,
                dataset=mutated_dataset,
                coverage=coverage,
                parent_id=parent.entry_id,
                crash_triggered=crash,
            )

            if added:
                logger.info(
                    "Added interesting input to corpus",
                    entry_id=entry_id,
                    crash=crash,
                    parent=parent.entry_id,
                )
                return self.corpus_manager.get_entry(entry_id)

        self.stats.total_iterations += 1
        return None

    def fuzz(
        self,
        iterations: int = 1000,
        show_progress: bool = True,
        stop_on_crash: bool = False,
    ) -> FuzzingCampaignStats:
        """Run fuzzing campaign.

        CONCEPT: A fuzzing campaign is a series of iterations that systematically
        explores the input space looking for bugs.

        Args:
            iterations: Number of fuzzing iterations to perform
            show_progress: Whether to print progress updates
            stop_on_crash: Whether to stop when a crash is found

        Returns:
            Campaign statistics

        """
        logger.info(
            "Starting fuzzing campaign",
            iterations=iterations,
            corpus_size=len(self.corpus_manager.corpus),
        )

        for i in range(iterations):
            # Perform fuzzing iteration
            new_entry = self.fuzz_iteration()

            # Check for crashes
            if new_entry and new_entry.crash_triggered and stop_on_crash:
                logger.warning(
                    "Stopping campaign due to crash",
                    iteration=i + 1,
                    entry_id=new_entry.entry_id,
                )
                break

            # Progress updates
            if show_progress and (i + 1) % 100 == 0:
                self.stats.update_from_campaign(self)
                logger.info(
                    "Fuzzing progress",
                    iteration=i + 1,
                    corpus_size=self.stats.corpus_size,
                    crashes=self.stats.unique_crashes,
                    coverage=len(self.coverage_tracker.global_coverage),
                    exec_per_sec=f"{self.stats.executions_per_second:.1f}",
                )

        # Final statistics
        self.stats.update_from_campaign(self)
        self.stats.total_coverage = len(self.coverage_tracker.global_coverage)

        logger.info(
            "Fuzzing campaign completed",
            total_iterations=self.stats.total_iterations,
            unique_crashes=self.stats.unique_crashes,
            final_corpus_size=self.stats.corpus_size,
            total_coverage=self.stats.total_coverage,
        )

        return self.stats

    def _select_input(self) -> CorpusEntry | None:
        """Select an input from the corpus to mutate.

        CONCEPT: We use a weighted selection strategy:
        - 80% of time: Pick high-fitness entries (exploit)
        - 20% of time: Pick random entries (explore)

        This balances exploitation (focusing on good inputs) with
        exploration (trying diverse inputs).

        Returns:
            Corpus entry to mutate

        """
        if not self.corpus_manager.corpus:
            return None

        # 80% exploit, 20% explore
        if random.random() < 0.8:
            # Exploit: Pick from top entries
            best_entries = self.corpus_manager.get_best_entries(count=10)
            if best_entries:
                return random.choice(best_entries)

        # Explore: Random selection
        return self.corpus_manager.get_random_entry()

    def _mutate_input(self, dataset: Dataset) -> Dataset:
        """Mutate an input using the DICOM mutator.

        CONCEPT: We apply multiple mutation strategies to create
        diverse variants of the input.

        Args:
            dataset: Dataset to mutate

        Returns:
            Mutated dataset

        """
        # Start mutation session
        self.mutator.start_session(dataset)

        # Apply random number of mutations (1-5)
        num_mutations = random.randint(1, 5)

        mutated = self.mutator.apply_mutations(
            dataset, num_mutations=num_mutations, severity=self.mutation_severity
        )

        return mutated

    def _execute_with_coverage(
        self, dataset: Dataset, test_case_id: str
    ) -> CoverageSnapshot | None:
        """Execute target function with coverage tracking.

        Args:
            dataset: DICOM dataset to execute
            test_case_id: Identifier for this test case

        Returns:
            Coverage snapshot

        """
        snapshot = None

        with self.coverage_tracker.trace_execution(test_case_id):
            if self.target_function:
                # Execute the target
                self.target_function(dataset)

        # Get the coverage snapshot from the tracker
        if self.coverage_tracker.coverage_history:
            snapshot = self.coverage_tracker.coverage_history[-1]

        return snapshot

    def _record_crash(
        self, entry_id: str, parent_id: str, dataset: Dataset, exception: Exception
    ):
        """Record a crash for analysis.

        CONCEPT: Crashes are the most valuable finds in fuzzing.
        We record all crash details for later analysis.

        Args:
            entry_id: ID of the crashing input
            parent_id: ID of the parent input
            dataset: The crashing DICOM dataset
            exception: The exception that was raised

        """
        crash_record = {
            "crash_id": entry_id,
            "parent_id": parent_id,
            "exception_type": type(exception).__name__,
            "exception_message": str(exception),
            "timestamp": datetime.now(UTC).isoformat(),
        }

        self.crashes.append(crash_record)
        self.stats.unique_crashes += 1

        logger.error(
            "Crash detected!",
            crash_id=entry_id,
            parent=parent_id,
            exception=type(exception).__name__,
            message=str(exception)[:100],
        )

    def get_report(self) -> str:
        """Generate a fuzzing campaign report.

        Returns:
            Human-readable report

        """
        self.stats.update_from_campaign(self)

        coverage_stats = self.coverage_tracker.get_statistics()
        corpus_stats = self.corpus_manager.get_statistics()

        report = f"""
Coverage-Guided Fuzzing Campaign Report
{"=" * 60}

Campaign ID: {self.stats.campaign_id}
Duration: {(datetime.now(UTC) - self.stats.start_time).total_seconds():.1f}s

Execution Statistics:
  Total Iterations:        {self.stats.total_iterations}
  Executions/Second:       {self.stats.executions_per_second:.1f}

Coverage Statistics:
  Total Lines Covered:     {self.stats.total_coverage}
  Interesting Inputs:      {self.stats.interesting_inputs_found}
  Coverage Efficiency:     {coverage_stats["efficiency"]:.1%}

Corpus Statistics:
  Current Size:            {corpus_stats["total_entries"]}
  Max Generation:          {corpus_stats["max_generation"]}
  Average Fitness:         {corpus_stats["avg_fitness"]:.2f}
  Total Added:             {corpus_stats["total_added"]}
  Total Rejected:          {corpus_stats["total_rejected"]}

Crashes Found:
  Unique Crashes:          {self.stats.unique_crashes}

{self.coverage_tracker.get_coverage_report()}
        """

        return report.strip()

    def reset(self):
        """Reset fuzzer state (keeps corpus)."""
        self.coverage_tracker.reset()
        self.stats = FuzzingCampaignStats()
        self.crashes.clear()
        logger.info("Fuzzer state reset")
