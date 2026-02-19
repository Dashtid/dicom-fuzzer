"""Corpus Minimization Utility.

Minimizes corpus by removing redundant inputs and stripping unnecessary data.
Keeps only inputs that contribute unique coverage.
"""

import shutil
from pathlib import Path
from typing import Any

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

# DICOM tags to strip for corpus optimization
# These contain bulk data that isn't relevant for metadata/parser fuzzing
# Tags to strip for pixel data reduction
_PIXEL_DATA_TAGS = [
    (0x7FE0, 0x0010),  # PixelData
    (0x7FE0, 0x0008),  # FloatPixelData
    (0x7FE0, 0x0009),  # DoubleFloatPixelData
    (0x7FE0, 0x0001),  # ExtendedOffsetTable
    (0x7FE0, 0x0002),  # ExtendedOffsetTableLengths
]
_WAVEFORM_TAG = (0x5400, 0x0100)

# Public constant: all bulk data tags (pixel + waveform)
# Overlay data (groups 6000-601E) handled separately via OVERLAY_GROUP range
STRIP_TAGS = [*_PIXEL_DATA_TAGS, _WAVEFORM_TAG]

# Overlay data group range
OVERLAY_GROUP_START = 0x6000
OVERLAY_GROUP_END = 0x601E


def _delete_tag_if_present(ds: Any, tag: tuple[int, int]) -> None:
    """Delete a tag from dataset if present."""
    if tag in ds:
        del ds[tag]


def _strip_tags(ds: Any, strip_overlays: bool, strip_waveforms: bool) -> None:
    """Strip pixel data and optional bulk data tags from dataset."""
    # Strip pixel data tags
    for tag in _PIXEL_DATA_TAGS:
        _delete_tag_if_present(ds, tag)

    # Strip overlay data (ALL elements in groups 6000-601E)
    # DICOM overlay groups contain multiple elements (OverlayData, OverlayRows,
    # OverlayColumns, OverlayOrigin, etc.) - we strip all of them
    if strip_overlays:
        tags_to_remove = [
            elem.tag
            for elem in ds
            if OVERLAY_GROUP_START <= elem.tag.group <= OVERLAY_GROUP_END
        ]
        for tag in tags_to_remove:
            del ds[tag]

    # Strip waveform data
    if strip_waveforms:
        _delete_tag_if_present(ds, _WAVEFORM_TAG)

    # Clean file_meta if present
    if hasattr(ds, "file_meta"):
        _delete_tag_if_present(ds.file_meta, (0x7FE0, 0x0010))


def strip_pixel_data(
    input_path: Path,
    output_path: Path,
    strip_overlays: bool = True,
    strip_waveforms: bool = True,
) -> tuple[bool, int]:
    """Strip pixel data and bulk data from DICOM file.

    This optimization reduces corpus file sizes by 90%+ for image files,
    dramatically improving fuzzing throughput for parser-focused testing.

    Args:
        input_path: Source DICOM file
        output_path: Destination for stripped file
        strip_overlays: Also strip overlay data (default: True)
        strip_waveforms: Also strip waveform data (default: True)

    Returns:
        Tuple of (success: bool, bytes_saved: int)

    """
    try:
        import pydicom

        ds = pydicom.dcmread(str(input_path), force=True)
        original_size = input_path.stat().st_size

        _strip_tags(ds, strip_overlays, strip_waveforms)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        ds.save_as(str(output_path), write_like_original=False)

        bytes_saved = original_size - output_path.stat().st_size
        return True, bytes_saved

    except Exception as e:
        logger.debug("Failed to strip pixel data", file=input_path.name, error=str(e))
        return _fallback_copy(input_path, output_path)


def _fallback_copy(input_path: Path, output_path: Path) -> tuple[bool, int]:
    """Fall back to copying original file."""
    try:
        shutil.copy2(input_path, output_path)
        return True, 0
    except Exception:
        return False, 0


def optimize_corpus(
    corpus_dir: Path,
    output_dir: Path,
    strip_pixels: bool = True,
    strip_overlays: bool = True,
    strip_waveforms: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Optimize corpus by stripping bulk data from DICOM files.

    Creates a size-optimized corpus for faster fuzzing. Particularly useful
    for parser-focused testing where pixel data isn't relevant.

    Args:
        corpus_dir: Source corpus directory
        output_dir: Output directory for optimized corpus
        strip_pixels: Strip PixelData (default: True)
        strip_overlays: Strip OverlayData (default: True)
        strip_waveforms: Strip WaveformData (default: True)
        dry_run: Don't actually write files, just report savings

    Returns:
        Dictionary with optimization statistics

    """
    stats = {
        "files_processed": 0,
        "files_optimized": 0,
        "files_skipped": 0,
        "original_size_mb": 0.0,
        "optimized_size_mb": 0.0,
        "bytes_saved": 0,
        "reduction_percent": 0.0,
    }

    if not corpus_dir.exists():
        logger.error("Corpus directory not found", corpus_dir=str(corpus_dir))
        return stats

    # Find all DICOM files
    dicom_files = list(corpus_dir.glob("**/*.dcm"))
    dicom_files.extend(corpus_dir.glob("**/*.dicom"))

    if not dicom_files:
        logger.warning("No DICOM files found", corpus_dir=str(corpus_dir))
        return stats

    logger.info("Optimizing corpus", file_count=len(dicom_files))

    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    total_original = 0
    total_optimized = 0

    for dicom_file in dicom_files:
        stats["files_processed"] += 1
        file_size = dicom_file.stat().st_size
        total_original += file_size

        # Compute relative path for output
        rel_path = dicom_file.relative_to(corpus_dir)
        output_path = output_dir / rel_path

        if dry_run:
            # Just estimate the savings
            stats["files_optimized"] += 1
            # Estimate 90% reduction for image files
            estimated_new_size = int(file_size * 0.1)
            total_optimized += estimated_new_size
            stats["bytes_saved"] += file_size - estimated_new_size
        else:
            # Only strip if at least one stripping option is enabled
            if strip_pixels or strip_overlays or strip_waveforms:
                success, bytes_saved = strip_pixel_data(
                    dicom_file,
                    output_path,
                    strip_overlays=strip_overlays,
                    strip_waveforms=strip_waveforms,
                )
            else:
                # No stripping requested, just copy the file
                output_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dicom_file, output_path)
                success = True
                bytes_saved = 0

            if success:
                stats["files_optimized"] += 1
                stats["bytes_saved"] += bytes_saved
                new_size = output_path.stat().st_size
                total_optimized += new_size
            else:
                stats["files_skipped"] += 1
                total_optimized += file_size

    stats["original_size_mb"] = total_original / (1024 * 1024)
    stats["optimized_size_mb"] = total_optimized / (1024 * 1024)

    if total_original > 0:
        stats["reduction_percent"] = 100 * stats["bytes_saved"] / total_original

    logger.info(
        "Corpus optimization complete",
        original_size_mb=round(stats["original_size_mb"], 2),
        optimized_size_mb=round(stats["optimized_size_mb"], 2),
        reduction_percent=round(stats["reduction_percent"], 1),
    )

    return stats


def minimize_corpus_for_campaign(
    corpus_dir: Path,
    output_dir: Path,
    coverage_tracker: Any | None = None,
    max_corpus_size: int | None = 1000,
) -> list[Path]:
    """Minimize corpus before fuzzing campaign.

    Keeps only inputs that contribute unique coverage and removes
    redundant seeds that don't add new code paths.

    Args:
        corpus_dir: Directory containing seed corpus
        output_dir: Directory to save minimized corpus
        coverage_tracker: Optional coverage tracker for measuring uniqueness
        max_corpus_size: Maximum number of seeds to keep

    Returns:
        List of paths to minimized corpus files

    """
    if not corpus_dir.exists():
        logger.error("Corpus directory not found", corpus_dir=str(corpus_dir))
        return []

    # Get all seed files
    seed_files = list(corpus_dir.glob("*.dcm"))
    if not seed_files:
        logger.warning("No DICOM files found in corpus", corpus_dir=str(corpus_dir))
        return []

    logger.info("Minimizing corpus", seed_count=len(seed_files))

    # Sort by file size (smaller files first - faster to process)
    seed_files.sort(key=lambda f: f.stat().st_size)

    minimized_corpus = []
    total_coverage: set[str] = set()

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    for seed_file in seed_files:
        # If we have coverage tracker, check if seed adds new coverage
        if coverage_tracker:
            try:
                new_coverage = coverage_tracker.get_coverage_for_input(seed_file)

                # Keep only if it adds new coverage
                unique_coverage = new_coverage - total_coverage
                if unique_coverage:
                    minimized_corpus.append(seed_file)
                    total_coverage |= new_coverage
                    logger.debug(
                        "Kept seed",
                        file=seed_file.name,
                        unique_edges=len(unique_coverage),
                    )
                else:
                    logger.debug("Skipped seed, no new coverage", file=seed_file.name)

            except Exception as e:
                logger.warning(
                    "Error processing seed", file=seed_file.name, error=str(e)
                )
                # Keep seed if we can't determine coverage
                minimized_corpus.append(seed_file)

        else:
            # No coverage tracker - keep all seeds (just copy)
            minimized_corpus.append(seed_file)

        # Respect max corpus size
        if max_corpus_size and len(minimized_corpus) >= max_corpus_size:
            logger.info("Reached max corpus size", max_corpus_size=max_corpus_size)
            break

    # Copy minimized corpus to output directory
    copied_files = []
    for seed in minimized_corpus:
        dest = output_dir / seed.name
        shutil.copy2(seed, dest)
        copied_files.append(dest)

    reduction_pct = (
        100 * (len(seed_files) - len(minimized_corpus)) / len(seed_files)
        if seed_files
        else 0
    )

    logger.info(
        "Corpus minimized",
        original_seeds=len(seed_files),
        minimized_seeds=len(minimized_corpus),
        reduction_percent=round(reduction_pct, 1),
    )

    if coverage_tracker:
        logger.info("Total unique coverage", edges=len(total_coverage))

    return copied_files


class MoonLightMinimizer:
    """MoonLight-style corpus minimization using weighted set cover.

    Implements near-optimal corpus distillation based on the MoonLight algorithm.
    This approach delivers smaller corpora (3x to 100x) compared to afl-cmin.

    References:
    - MoonLight: Effective Fuzzing with Near-Optimal Corpus Distillation
    - https://arxiv.org/abs/1905.13055

    The algorithm:
    1. Collect coverage information for each seed
    2. Use weighted set cover to find minimal seed set
    3. Weight by file size and execution time for faster fuzzing

    """

    def __init__(
        self,
        weight_by_size: bool = True,
        weight_by_time: bool = True,
        size_weight: float = 0.5,
        time_weight: float = 0.5,
    ) -> None:
        """Initialize MoonLight minimizer.

        Args:
            weight_by_size: Consider file size in selection
            weight_by_time: Consider execution time in selection
            size_weight: Weight factor for file size (0-1)
            time_weight: Weight factor for execution time (0-1)

        """
        self.weight_by_size = weight_by_size
        self.weight_by_time = weight_by_time
        self.size_weight = size_weight
        self.time_weight = time_weight
        self._coverage_cache: dict[Path, set[str]] = {}
        self._time_cache: dict[Path, float] = {}

    def compute_seed_weight(self, seed: Path) -> float:
        """Compute weight for a seed (lower is better).

        Args:
            seed: Path to seed file

        Returns:
            Weight value (lower = more preferred)

        """
        weight = 1.0

        if self.weight_by_size:
            # Prefer smaller files (faster to process)
            size_kb = seed.stat().st_size / 1024
            # Normalize size: 1KB = 1.0, 1MB = 1000
            size_factor = max(1.0, size_kb)
            weight *= size_factor**self.size_weight

        if self.weight_by_time and seed in self._time_cache:
            # Prefer faster-executing seeds
            exec_time = self._time_cache[seed]
            # Normalize time: 1ms = 1.0, 1s = 1000
            time_factor = max(1.0, exec_time * 1000)
            weight *= time_factor**self.time_weight

        return weight

    def get_coverage(self, seed: Path) -> set[str]:
        """Get coverage for a seed (with caching).

        Args:
            seed: Path to seed file

        Returns:
            Set of coverage edge identifiers

        """
        if seed in self._coverage_cache:
            return self._coverage_cache[seed]

        # Default: use file hash as "coverage" for basic dedup
        import hashlib

        content = seed.read_bytes()
        h = hashlib.sha256(content).hexdigest()
        coverage = {f"hash:{h}"}
        self._coverage_cache[seed] = coverage
        return coverage

    def set_coverage(self, seed: Path, coverage: set[str]) -> None:
        """Set coverage information for a seed.

        Args:
            seed: Path to seed file
            coverage: Set of coverage edge identifiers

        """
        self._coverage_cache[seed] = coverage

    def set_execution_time(self, seed: Path, time_seconds: float) -> None:
        """Set execution time for a seed.

        Args:
            seed: Path to seed file
            time_seconds: Execution time in seconds

        """
        self._time_cache[seed] = time_seconds

    def _find_best_seed(
        self,
        remaining_seeds: list[Path],
        seed_coverage: dict[Path, set[str]],
        covered: set[str],
    ) -> tuple[Path | None, int]:
        """Find best seed to add based on weighted set cover score.

        Returns:
            Tuple of (best_seed, new_coverage_count) or (None, 0) if no seed adds coverage.

        """
        best_seed = None
        best_score = float("inf")
        best_new_coverage = 0

        for seed in remaining_seeds:
            new_coverage = seed_coverage[seed] - covered
            if not new_coverage:
                continue

            weight = self.compute_seed_weight(seed)
            score = weight / len(new_coverage)

            if score < best_score or (
                score == best_score and len(new_coverage) > best_new_coverage
            ):
                best_seed = seed
                best_score = score
                best_new_coverage = len(new_coverage)

        return best_seed, best_new_coverage

    def minimize(
        self,
        seeds: list[Path],
        target_coverage: set[str] | None = None,
    ) -> list[Path]:
        """Minimize seed corpus using weighted set cover.

        Args:
            seeds: List of seed file paths
            target_coverage: Optional target coverage to achieve

        Returns:
            Minimized list of seeds

        """
        if not seeds:
            return []

        seed_coverage: dict[Path, set[str]] = {
            seed: self.get_coverage(seed) for seed in seeds
        }

        if target_coverage is None:
            target_coverage = set().union(*seed_coverage.values())

        if not target_coverage:
            return seeds[:1] if seeds else []

        selected: list[Path] = []
        covered: set[str] = set()
        remaining_seeds = list(seeds)

        while covered != target_coverage and remaining_seeds:
            best_seed, _ = self._find_best_seed(remaining_seeds, seed_coverage, covered)
            if best_seed is None:
                break

            selected.append(best_seed)
            covered |= seed_coverage[best_seed]
            remaining_seeds.remove(best_seed)

        logger.info(
            "MoonLight minimization complete",
            original_seeds=len(seeds),
            selected_seeds=len(selected),
            reduction_percent=round(100 * (len(seeds) - len(selected)) / len(seeds), 1),
        )
        logger.debug(
            "Coverage preserved",
            covered=len(covered),
            total=len(target_coverage),
        )

        return selected

    def minimize_corpus_dir(
        self,
        corpus_dir: Path,
        output_dir: Path,
        coverage_file: Path | None = None,
    ) -> dict[str, Any]:
        """Minimize a corpus directory.

        Args:
            corpus_dir: Source corpus directory
            output_dir: Output directory for minimized corpus
            coverage_file: Optional JSON file with coverage data

        Returns:
            Statistics dictionary

        """
        stats = {
            "original_count": 0,
            "minimized_count": 0,
            "original_size_mb": 0.0,
            "minimized_size_mb": 0.0,
            "coverage_preserved": 0,
            "total_coverage": 0,
        }

        # Find seeds
        seeds = list(corpus_dir.glob("*.dcm"))
        seeds.extend(corpus_dir.glob("*.bin"))
        stats["original_count"] = len(seeds)
        stats["original_size_mb"] = sum(s.stat().st_size for s in seeds) / (1024 * 1024)

        if not seeds:
            return stats

        # Load coverage data if provided
        if coverage_file and coverage_file.exists():
            import json

            with open(coverage_file) as f:
                coverage_data = json.load(f)

            for seed_name, edges in coverage_data.items():
                seed_path = corpus_dir / seed_name
                if seed_path.exists():
                    self.set_coverage(seed_path, set(edges))

        # Minimize
        minimized = self.minimize(seeds)
        stats["minimized_count"] = len(minimized)

        # Copy to output
        output_dir.mkdir(parents=True, exist_ok=True)
        for seed in minimized:
            shutil.copy2(seed, output_dir / seed.name)

        stats["minimized_size_mb"] = sum(s.stat().st_size for s in minimized) / (
            1024 * 1024
        )

        # Coverage stats
        all_coverage: set[str] = set()
        minimized_coverage: set[str] = set()
        for seed in seeds:
            all_coverage |= self.get_coverage(seed)
        for seed in minimized:
            minimized_coverage |= self.get_coverage(seed)

        stats["total_coverage"] = len(all_coverage)
        stats["coverage_preserved"] = len(minimized_coverage)

        return stats


class CoverageAwarePrioritizer:
    """Prioritize seeds based on coverage contribution.

    Seeds that discover new coverage are prioritized higher,
    enabling more efficient fuzzing campaigns.
    """

    def __init__(self) -> None:
        self._coverage_history: dict[Path, set[str]] = {}
        self._discovery_order: list[Path] = []
        self._priority_scores: dict[Path, float] = {}

    def record_coverage(self, seed: Path, coverage: set[str]) -> bool:
        """Record coverage for a seed.

        Args:
            seed: Path to seed file
            coverage: Set of coverage edges

        Returns:
            True if seed discovered new coverage

        """
        # Check for new coverage
        all_previous = set()
        for prev_cov in self._coverage_history.values():
            all_previous |= prev_cov

        new_coverage = coverage - all_previous
        self._coverage_history[seed] = coverage

        if new_coverage:
            self._discovery_order.append(seed)
            # Higher priority for more new coverage
            self._priority_scores[seed] = len(new_coverage)
            return True
        else:
            self._priority_scores[seed] = 0
            return False

    def get_prioritized_seeds(self, seeds: list[Path]) -> list[Path]:
        """Get seeds sorted by priority (most interesting first).

        Args:
            seeds: List of seed paths

        Returns:
            Sorted list with highest priority seeds first

        """

        def priority_key(seed: Path) -> tuple[float, int]:
            # Primary: discovery score (higher = better)
            # Secondary: discovery order (earlier = better, so negate)
            score = self._priority_scores.get(seed, 0)
            order = (
                self._discovery_order.index(seed)
                if seed in self._discovery_order
                else len(self._discovery_order)
            )
            return (-score, order)

        return sorted(seeds, key=priority_key)

    def get_interesting_seeds(self) -> list[Path]:
        """Get seeds that discovered new coverage."""
        return list(self._discovery_order)

    def get_statistics(self) -> dict[str, Any]:
        """Get prioritization statistics."""
        return {
            "total_seeds": len(self._coverage_history),
            "interesting_seeds": len(self._discovery_order),
            "total_coverage": len(
                set().union(*self._coverage_history.values())
                if self._coverage_history
                else set()
            ),
        }


def validate_corpus_quality(corpus_dir: Path) -> dict[str, Any]:
    """Validate corpus quality and provide statistics.

    Args:
        corpus_dir: Directory containing corpus

    Returns:
        Dictionary with corpus quality metrics

    """
    metrics = {
        "total_files": 0,
        "total_size_mb": 0.0,
        "avg_file_size_kb": 0.0,
        "min_size_kb": 0.0,
        "max_size_kb": 0.0,
        "valid_dicom": 0,
        "corrupted": 0,
    }

    if not corpus_dir.exists():
        return metrics

    seed_files = list(corpus_dir.glob("*.dcm"))
    metrics["total_files"] = len(seed_files)

    if not seed_files:
        return metrics

    # Calculate size statistics
    sizes = [f.stat().st_size for f in seed_files]
    total_size = sum(sizes)
    metrics["total_size_mb"] = total_size / (1024 * 1024)
    metrics["avg_file_size_kb"] = (total_size / len(sizes)) / 1024
    metrics["min_size_kb"] = min(sizes) / 1024
    metrics["max_size_kb"] = max(sizes) / 1024

    # Validate DICOM files
    try:
        import pydicom

        for seed_file in seed_files:
            try:
                pydicom.dcmread(str(seed_file), force=True, stop_before_pixels=True)
                metrics["valid_dicom"] += 1
            except Exception:
                metrics["corrupted"] += 1
    except ImportError:
        logger.warning("pydicom not available - skipping DICOM validation")

    return metrics
