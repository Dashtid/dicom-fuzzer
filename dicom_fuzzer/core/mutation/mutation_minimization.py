"""Mutation Minimization - Find Minimal Crash-Triggering Input

This module implements delta debugging and other minimization strategies
to find the smallest set of mutations that still triggers a crash.

Goal: Given a crash caused by N mutations, find the minimal subset
(ideally 1 mutation) that still causes the same crash.

This helps identify the root cause vulnerability.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pydicom
from pydicom.dataset import Dataset
from pydicom.tag import BaseTag

from dicom_fuzzer.core.session.fuzzing_session import MutationRecord


@dataclass
class MinimizationResult:
    """Result of mutation minimization."""

    original_mutation_count: int
    minimized_mutation_count: int
    minimal_mutations: list[MutationRecord]
    test_iterations: int
    still_crashes: bool
    minimization_ratio: float


class MutationMinimizer:
    """Minimize mutations required to trigger a crash.

    Uses delta debugging algorithm to systematically reduce
    the mutation set while preserving the crash.
    """

    def __init__(
        self,
        crash_tester: Callable[[Dataset], bool],
        max_iterations: int = 50,
    ):
        """Initialize mutation minimizer.

        Args:
            crash_tester: Function that tests if dataset crashes (returns True if crash)
            max_iterations: Maximum minimization iterations

        """
        self.crash_tester = crash_tester
        self.max_iterations = max_iterations
        self.test_count = 0

    def minimize(
        self,
        original_dataset: Dataset,
        mutations: list[MutationRecord],
        strategy: str = "delta_debug",
    ) -> MinimizationResult:
        """Minimize mutations to find minimal crash-triggering set.

        Args:
            original_dataset: Original DICOM dataset before mutations
            mutations: List of mutations that were applied
            strategy: Minimization strategy ("delta_debug", "linear", "binary")

        Returns:
            MinimizationResult with minimal mutation set

        """
        self.test_count = 0

        if strategy == "delta_debug":
            minimal = self._delta_debugging(original_dataset, mutations)
        elif strategy == "linear":
            minimal = self._linear_minimization(original_dataset, mutations)
        elif strategy == "binary":
            minimal = self._binary_minimization(original_dataset, mutations)
        else:
            raise ValueError(f"Unknown minimization strategy: {strategy}")

        # Verify minimal set still crashes
        test_dataset = self._apply_mutations(original_dataset, minimal)
        still_crashes = self.crash_tester(test_dataset)

        return MinimizationResult(
            original_mutation_count=len(mutations),
            minimized_mutation_count=len(minimal),
            minimal_mutations=minimal,
            test_iterations=self.test_count,
            still_crashes=still_crashes,
            minimization_ratio=(len(mutations) - len(minimal)) / len(mutations)
            if len(mutations) > 0
            else 0.0,
        )

    def _try_subsets(
        self, original: Dataset, subsets: list[list[MutationRecord]]
    ) -> list[MutationRecord] | None:
        """Try each subset to find one that crashes. Returns crashing subset or None."""
        for subset in subsets:
            if not subset:
                continue
            test_dataset = self._apply_mutations(original, subset)
            self.test_count += 1
            if self.crash_tester(test_dataset):
                return subset
        return None

    def _try_complements(
        self, original: Dataset, subsets: list[list[MutationRecord]], current_len: int
    ) -> list[MutationRecord] | None:
        """Try complement sets. Returns crashing complement or None."""
        for i in range(len(subsets)):
            complement = [m for j, sub in enumerate(subsets) for m in sub if j != i]
            if len(complement) < current_len:
                test_dataset = self._apply_mutations(original, complement)
                self.test_count += 1
                if self.crash_tester(test_dataset):
                    return complement
        return None

    def _delta_debugging(
        self, original: Dataset, mutations: list[MutationRecord]
    ) -> list[MutationRecord]:
        """Delta debugging algorithm.

        Systematically reduces mutation set by testing subsets.

        Args:
            original: Original dataset
            mutations: Full mutation list

        Returns:
            Minimal mutation list that still triggers crash

        """
        current_set = mutations.copy()
        n = 2

        while len(current_set) > 1 and self.test_count < self.max_iterations:
            subsets = self._split_list(current_set, n)

            result = self._try_subsets(original, subsets)
            if result is not None:
                current_set = result
                n = max(2, n - 1)
                continue

            result = self._try_complements(original, subsets, len(current_set))
            if result is not None:
                current_set = result
                n = max(2, n - 1)
                continue

            if n >= len(current_set):
                break
            n = min(len(current_set), n * 2)

        return current_set

    def _linear_minimization(
        self, original: Dataset, mutations: list[MutationRecord]
    ) -> list[MutationRecord]:
        """Linear minimization - try removing each mutation one at a time.

        Faster but less effective than delta debugging.

        Args:
            original: Original dataset
            mutations: Full mutation list

        Returns:
            Minimal mutation list

        """
        minimal = mutations.copy()

        # Try removing each mutation
        i = 0
        while i < len(minimal) and self.test_count < self.max_iterations:
            # Try without this mutation
            test_mutations = minimal[:i] + minimal[i + 1 :]
            test_dataset = self._apply_mutations(original, test_mutations)
            self.test_count += 1

            if self.crash_tester(test_dataset):
                # Still crashes without this mutation - remove it
                minimal = test_mutations
                # Don't increment i, check same position again
            else:
                # Need this mutation - keep it
                i += 1

        return minimal

    def _binary_minimization(
        self, original: Dataset, mutations: list[MutationRecord]
    ) -> list[MutationRecord]:
        """Binary search minimization.

        Test halves of the mutation set.

        Args:
            original: Original dataset
            mutations: Full mutation list

        Returns:
            Minimal mutation list

        """
        current = mutations.copy()

        while len(current) > 1 and self.test_count < self.max_iterations:
            mid = len(current) // 2

            # Try first half
            first_half = current[:mid]
            test_dataset = self._apply_mutations(original, first_half)
            self.test_count += 1

            if self.crash_tester(test_dataset):
                current = first_half
                continue

            # Try second half
            second_half = current[mid:]
            test_dataset = self._apply_mutations(original, second_half)
            self.test_count += 1

            if self.crash_tester(test_dataset):
                current = second_half
                continue

            # Both halves needed - try linear on this set
            return self._linear_minimization(original, current)

        return current

    def _apply_mutations(
        self, dataset: Dataset, mutations: list[MutationRecord]
    ) -> Dataset:
        """Apply list of mutations to dataset.

        Replays recorded mutations to recreate the mutated state.
        This is essential for delta debugging to work correctly.

        Args:
            dataset: Original dataset
            mutations: Mutations to apply

        Returns:
            Mutated dataset

        """
        # Use Dataset.copy() if available - it's optimized for DICOM and 2-3x faster than deepcopy
        # Fall back to deepcopy for mock objects or non-pydicom datasets
        if hasattr(dataset, "copy"):
            mutated = dataset.copy()
        else:
            mutated = copy.deepcopy(dataset)

        # Apply each mutation based on recorded parameters
        for mutation in mutations:
            try:
                self._apply_single_mutation(mutated, mutation)
            except Exception as e:
                # Log but continue - partial mutation set may still trigger crash
                import logging

                mutation_id = getattr(mutation, "mutation_id", "unknown")
                logging.getLogger(__name__).debug(
                    f"Failed to apply mutation {mutation_id}: {e}"
                )

        return mutated

    def _parse_tag(self, tag_str: str) -> BaseTag | None:
        """Parse tag string to pydicom Tag, returning None on failure."""
        try:
            clean = tag_str.strip("()").replace(",", "")
            return pydicom.tag.Tag(int(clean[:4], 16), int(clean[4:], 16))
        except (ValueError, IndexError):
            return None

    def _apply_modify_mutation(
        self, dataset: Dataset, tag: BaseTag, value: object
    ) -> None:
        """Apply modify/replace/flip_bits/insert mutation."""
        if value is not None and tag in dataset:
            try:
                dataset[tag].value = value
            except (ValueError, TypeError):
                if isinstance(value, str):
                    dataset[tag].value = value.encode("utf-8", errors="replace")

    def _apply_corrupt_mutation(
        self, dataset: Dataset, tag: BaseTag, value: object
    ) -> None:
        """Apply corruption mutation."""
        if tag in dataset and value is not None:
            try:
                dataset[tag].value = value
            except (ValueError, TypeError):
                dataset[tag].value = b"\x00" * 8

    def _apply_single_mutation(
        self, dataset: Dataset, mutation: MutationRecord
    ) -> None:
        """Apply a single recorded mutation to dataset in-place.

        Args:
            dataset: Dataset to mutate (modified in-place)
            mutation: Mutation record to replay

        """
        if not mutation.target_tag:
            return

        tag = self._parse_tag(mutation.target_tag)
        if tag is None:
            return

        mutation_type = mutation.mutation_type.lower()

        if mutation_type == "delete":
            if tag in dataset:
                del dataset[tag]
        elif mutation_type in ("modify", "replace", "flip_bits", "insert"):
            self._apply_modify_mutation(dataset, tag, mutation.mutated_value)
        elif mutation_type == "corrupt":
            self._apply_corrupt_mutation(dataset, tag, mutation.mutated_value)

    def _split_list(
        self, lst: list[MutationRecord], n: int
    ) -> list[list[MutationRecord]]:
        """Split list into n roughly equal parts.

        Args:
            lst: List to split
            n: Number of parts

        Returns:
            List of sublists

        """
        if n <= 0 or n > len(lst):
            return [lst]

        chunk_size = len(lst) // n
        remainder = len(lst) % n

        chunks = []
        start = 0

        for i in range(n):
            # Distribute remainder across first chunks
            size = chunk_size + (1 if i < remainder else 0)
            if size > 0:
                chunks.append(lst[start : start + size])
                start += size

        return chunks


class CrashMinimizationOrchestrator:
    """Orchestrate crash minimization across multiple crashes.

    Prioritizes crashes and manages minimization workflow.
    """

    def __init__(self, viewer_path: Path, timeout: int = 5):
        """Initialize minimization orchestrator.

        Args:
            viewer_path: Path to viewer executable for testing
            timeout: Timeout for crash tests

        """
        self.viewer_path = viewer_path
        self.timeout = timeout

    def minimize_crash(
        self,
        crash_id: str,
        source_file: Path,
        mutations: list[MutationRecord],
        strategy: str = "delta_debug",
    ) -> MinimizationResult:
        """Minimize mutations for a specific crash.

        Args:
            crash_id: Crash identifier
            source_file: Original DICOM file
            mutations: Mutations that caused crash
            strategy: Minimization strategy

        Returns:
            MinimizationResult

        """
        # Load original dataset
        original_ds = pydicom.dcmread(str(source_file), force=True)

        # Create crash tester function
        def test_crash(dataset: Dataset) -> bool:
            """Test if dataset crashes viewer."""
            import subprocess
            import tempfile

            # Save dataset to temp file
            with tempfile.NamedTemporaryFile(suffix=".dcm", delete=False) as tmp_file:
                tmp_path = Path(tmp_file.name)

            try:
                pydicom.dcmwrite(str(tmp_path), dataset, write_like_original=False)

                # Test with viewer
                proc = subprocess.Popen(
                    [str(self.viewer_path), str(tmp_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                try:
                    proc.communicate(timeout=self.timeout)
                    # Crash if non-zero exit code
                    return proc.returncode != 0
                except subprocess.TimeoutExpired:
                    proc.kill()
                    # Timeout counts as crash (DoS)
                    return True

            except Exception:
                # Error writing/testing - assume no crash
                return False
            finally:
                # Cleanup temp file
                if tmp_path.exists():
                    tmp_path.unlink()

        # Run minimization
        minimizer = MutationMinimizer(test_crash, max_iterations=50)
        result = minimizer.minimize(original_ds, mutations, strategy=strategy)

        return result

    def batch_minimize(
        self,
        crashes: list[tuple[str, Path, list[MutationRecord]]],
        strategy: str = "delta_debug",
        max_crashes: int | None = None,
    ) -> dict[str, MinimizationResult]:
        """Minimize multiple crashes in batch.

        Args:
            crashes: List of (crash_id, source_file, mutations) tuples
            strategy: Minimization strategy
            max_crashes: Maximum number of crashes to minimize

        Returns:
            Dictionary mapping crash_id to MinimizationResult

        """
        results = {}

        # Prioritize crashes with more mutations (more potential for minimization)
        sorted_crashes = sorted(crashes, key=lambda x: len(x[2]), reverse=True)

        if max_crashes:
            sorted_crashes = sorted_crashes[:max_crashes]

        for crash_id, source_file, mutations in sorted_crashes:
            result = self.minimize_crash(crash_id, source_file, mutations, strategy)
            results[crash_id] = result

        return results
