"""Study Minimizer - Delta debugging for 3D DICOM studies.

Finds minimal set of slices that trigger a crash using binary reduction
and individual slice testing.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from dicom_fuzzer.utils.logger import get_logger

if TYPE_CHECKING:
    from dicom_fuzzer.core.target_runner import TargetRunner

logger = get_logger(__name__)


@dataclass
class MinimizedStudy:
    """Result of study minimization."""

    original_study: Path
    minimized_study: Path
    original_slice_count: int
    minimal_slice_count: int
    trigger_slice: Path | None  # Single slice that triggers crash (if found)
    reduction_ratio: float  # minimal/original
    minimization_time_seconds: float
    iterations: int
    crash_reproducible: bool
    notes: list[str] = field(default_factory=list)

    @property
    def is_single_slice_bug(self) -> bool:
        """Check if bug is triggered by a single slice."""
        return self.trigger_slice is not None

    @property
    def is_multi_slice_bug(self) -> bool:
        """Check if bug requires multiple slices to trigger."""
        return self.minimal_slice_count > 1 and self.trigger_slice is None


@dataclass
class MinimizationConfig:
    """Configuration for study minimization."""

    max_iterations: int = 100
    timeout_per_test: float = 30.0
    preserve_series_structure: bool = True
    verify_final_result: bool = True
    cleanup_temp_dirs: bool = True


class StudyMinimizer:
    """Minimizes 3D DICOM studies to find minimal crash-triggering subset.

    Uses a modified delta debugging algorithm:
    1. Binary reduction: Split study in half, test each half
    2. Complement testing: If half crashes, test if other half is needed
    3. Individual testing: Find single trigger slice if possible

    Usage:
        minimizer = StudyMinimizer(target_runner)
        result = minimizer.minimize(
            study_dir=Path("./crash_study"),
            output_dir=Path("./minimized"),
        )
    """

    def __init__(
        self,
        crash_test_func: Callable[[Path], bool],
        config: MinimizationConfig | None = None,
    ):
        """Initialize study minimizer.

        Args:
            crash_test_func: Function that tests if a study directory crashes.
                             Returns True if crash detected, False otherwise.
            config: Minimization configuration

        """
        self.crash_test_func = crash_test_func
        self.config = config or MinimizationConfig()
        self._temp_dirs: list[Path] = []
        self._iteration_count = 0

    def minimize(
        self,
        study_dir: Path,
        output_dir: Path,
    ) -> MinimizedStudy:
        """Minimize a study to find the smallest crash-triggering subset.

        Args:
            study_dir: Directory containing DICOM slices
            output_dir: Directory to save minimized study

        Returns:
            MinimizedStudy with minimization results

        """
        start_time = datetime.now()
        self._iteration_count = 0
        notes: list[str] = []

        # Get all DICOM files in study
        slices = self._get_slices(study_dir)
        original_count = len(slices)

        if original_count == 0:
            raise ValueError(f"No DICOM files found in {study_dir}")

        logger.info(
            f"Starting study minimization: {original_count} slices in {study_dir}"
        )

        # Verify crash reproduces with full study
        if not self._test_crash(study_dir):
            logger.warning("Crash does not reproduce with full study")
            return MinimizedStudy(
                original_study=study_dir,
                minimized_study=study_dir,
                original_slice_count=original_count,
                minimal_slice_count=original_count,
                trigger_slice=None,
                reduction_ratio=1.0,
                minimization_time_seconds=0.0,
                iterations=0,
                crash_reproducible=False,
                notes=["Crash not reproducible with full study"],
            )

        notes.append("Crash verified with full study")

        try:
            # Phase 1: Binary reduction
            logger.info("Phase 1: Binary reduction")
            minimal_slices = self._binary_reduce(slices)
            notes.append(
                f"Binary reduction: {original_count} -> {len(minimal_slices)} slices"
            )

            # Phase 2: Find trigger slice
            logger.info("Phase 2: Finding trigger slice")
            trigger_slice = self._find_trigger_slice(minimal_slices)

            if trigger_slice:
                notes.append(f"Single trigger slice found: {trigger_slice.name}")
                minimal_slices = [trigger_slice]

            # Create output directory with minimal slices
            output_dir.mkdir(parents=True, exist_ok=True)
            for slice_path in minimal_slices:
                shutil.copy2(slice_path, output_dir / slice_path.name)

            # Verify final result
            if self.config.verify_final_result:
                if not self._test_crash(output_dir):
                    notes.append("[!] WARNING: Final minimized study does not crash")
                    logger.warning("Final minimized study does not reproduce crash")
                else:
                    notes.append("Final result verified: crash reproduces")

            # Calculate results
            duration = (datetime.now() - start_time).total_seconds()
            minimal_count = len(minimal_slices)
            reduction_ratio = (
                minimal_count / original_count if original_count > 0 else 1.0
            )

            logger.info(
                f"Minimization complete: {original_count} -> {minimal_count} slices "
                f"({reduction_ratio:.1%} of original, {self._iteration_count} iterations)"
            )

            return MinimizedStudy(
                original_study=study_dir,
                minimized_study=output_dir,
                original_slice_count=original_count,
                minimal_slice_count=minimal_count,
                trigger_slice=trigger_slice,
                reduction_ratio=reduction_ratio,
                minimization_time_seconds=duration,
                iterations=self._iteration_count,
                crash_reproducible=True,
                notes=notes,
            )

        finally:
            # Cleanup temp directories
            if self.config.cleanup_temp_dirs:
                self._cleanup_temp_dirs()

    def _get_slices(self, study_dir: Path) -> list[Path]:
        """Get sorted list of DICOM slices in study directory.

        Args:
            study_dir: Study directory

        Returns:
            Sorted list of DICOM file paths

        """
        # Common DICOM extensions
        extensions = {".dcm", ".dicom", ".dic", ""}
        slices = []

        for f in study_dir.iterdir():
            if f.is_file():
                if f.suffix.lower() in extensions or not f.suffix:
                    slices.append(f)

        # Sort by name (usually contains instance number)
        return sorted(slices, key=lambda p: p.name)

    def _test_crash(self, study_dir: Path) -> bool:
        """Test if a study directory triggers a crash.

        Args:
            study_dir: Directory to test

        Returns:
            True if crash detected

        """
        self._iteration_count += 1

        if self._iteration_count > self.config.max_iterations:
            logger.warning(f"Max iterations ({self.config.max_iterations}) reached")
            return False

        try:
            return self.crash_test_func(study_dir)
        except Exception as e:
            logger.warning(f"Error testing {study_dir}: {e}")
            return False

    def _create_temp_study(self, slices: list[Path]) -> Path:
        """Create temporary study directory with given slices.

        Args:
            slices: List of slice paths to include

        Returns:
            Path to temporary study directory

        """
        temp_dir = Path(tempfile.mkdtemp(prefix="minimize_"))
        self._temp_dirs.append(temp_dir)

        for slice_path in slices:
            shutil.copy2(slice_path, temp_dir / slice_path.name)

        return temp_dir

    def _binary_reduce(self, slices: list[Path]) -> list[Path]:
        """Apply binary reduction to find minimal slice set.

        Delta debugging algorithm:
        1. Split slices in half
        2. Test each half
        3. If a half crashes, recurse on that half
        4. Otherwise, try removing each half while keeping other

        Args:
            slices: Current slice set

        Returns:
            Minimal slice set that still crashes

        """
        if len(slices) <= 1:
            return slices

        # Split in half
        mid = len(slices) // 2
        first_half = slices[:mid]
        second_half = slices[mid:]

        logger.debug(f"Testing halves: {len(first_half)} + {len(second_half)} slices")

        # Test first half
        first_temp = self._create_temp_study(first_half)
        if self._test_crash(first_temp):
            logger.debug(f"First half crashes ({len(first_half)} slices)")
            return self._binary_reduce(first_half)

        # Test second half
        second_temp = self._create_temp_study(second_half)
        if self._test_crash(second_temp):
            logger.debug(f"Second half crashes ({len(second_half)} slices)")
            return self._binary_reduce(second_half)

        # Neither half crashes alone - need elements from both
        # Try incremental reduction
        logger.debug("Neither half crashes alone - trying incremental reduction")
        return self._incremental_reduce(slices)

    def _incremental_reduce(self, slices: list[Path]) -> list[Path]:
        """Try removing one slice at a time to find minimal set.

        Args:
            slices: Current slice set

        Returns:
            Minimal slice set

        """
        current = list(slices)

        i = 0
        while i < len(current) and len(current) > 1:
            # Try removing slice i
            test_set = current[:i] + current[i + 1 :]
            test_temp = self._create_temp_study(test_set)

            if self._test_crash(test_temp):
                # Can remove this slice
                logger.debug(
                    f"Removed slice {current[i].name}, {len(test_set)} remaining"
                )
                current = test_set
                # Don't increment i - next slice is now at position i
            else:
                # Cannot remove this slice
                i += 1

            if self._iteration_count >= self.config.max_iterations:
                break

        return current

    def _find_trigger_slice(self, slices: list[Path]) -> Path | None:
        """Find single slice that triggers crash (if exists).

        Tests each slice individually to find if crash is caused
        by a single malformed slice.

        Args:
            slices: Minimal slice set

        Returns:
            Single trigger slice if found, None otherwise

        """
        if len(slices) == 1:
            # Already down to one slice
            return slices[0]

        logger.debug(f"Testing {len(slices)} slices individually")

        for slice_path in slices:
            temp_dir = self._create_temp_study([slice_path])

            if self._test_crash(temp_dir):
                logger.info(f"Found trigger slice: {slice_path.name}")
                return slice_path

            if self._iteration_count >= self.config.max_iterations:
                break

        logger.debug("No single trigger slice found - crash requires multiple slices")
        return None

    def _cleanup_temp_dirs(self) -> None:
        """Clean up temporary directories."""
        for temp_dir in self._temp_dirs:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception as e:
                logger.debug(f"Cleanup failed for {temp_dir}: {e}")
        self._temp_dirs.clear()


def create_crash_test_from_runner(
    target_runner: TargetRunner,
    study_arg_format: str = "{study_dir}",
) -> Callable[[Path], bool]:
    """Create a crash test function from a TargetRunner.

    Args:
        target_runner: TargetRunner instance
        study_arg_format: Format string for study directory argument

    Returns:
        Function that tests if a study crashes

    """
    from dicom_fuzzer.core.target_runner import ExecutionStatus

    def test_crash(study_dir: Path) -> bool:
        # Get first slice to test (or use directory as argument)
        slices = list(study_dir.glob("*.dcm")) + list(study_dir.glob("*"))
        slices = [s for s in slices if s.is_file()]

        if not slices:
            return False

        # Test first slice (some apps load entire series from one file)
        result = target_runner.execute_test(slices[0])
        return result.result == ExecutionStatus.CRASH

    return test_crash


def minimize_crashing_study(
    study_dir: Path,
    output_dir: Path,
    target_runner: TargetRunner,
    config: MinimizationConfig | None = None,
) -> MinimizedStudy:
    """Convenience function to minimize a crashing study.

    Args:
        study_dir: Directory containing crash-triggering study
        output_dir: Directory to save minimized study
        target_runner: TargetRunner configured for target application
        config: Minimization configuration

    Returns:
        MinimizedStudy result

    """
    crash_test = create_crash_test_from_runner(target_runner)
    minimizer = StudyMinimizer(crash_test, config)
    return minimizer.minimize(study_dir, output_dir)
