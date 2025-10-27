"""Corpus Minimization Utility

CONCEPT: Minimize corpus before fuzzing to remove redundant inputs.
Keeps only inputs that contribute unique coverage to improve fuzzing efficiency.

RESEARCH: "Before the fuzzing session can begin, seed corpus minimization is
performed to ensure that the fuzzer initializes faster and easier with a
smaller corpus." (2025 Best Practices)
"""

import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)


def minimize_corpus_for_campaign(
    corpus_dir: Path,
    output_dir: Path,
    coverage_tracker=None,
    max_corpus_size: int | None = 1000,
) -> list[Path]:
    """Minimize corpus before fuzzing campaign.

    CONCEPT: Keep only inputs that contribute unique coverage.
    Remove redundant seeds that don't add new code paths.

    Args:
        corpus_dir: Directory containing seed corpus
        output_dir: Directory to save minimized corpus
        coverage_tracker: Optional coverage tracker for measuring uniqueness
        max_corpus_size: Maximum number of seeds to keep

    Returns:
        List of paths to minimized corpus files

    """
    if not corpus_dir.exists():
        logger.error(f"Corpus directory not found: {corpus_dir}")
        return []

    # Get all seed files
    seed_files = list(corpus_dir.glob("*.dcm"))
    if not seed_files:
        logger.warning(f"No DICOM files found in corpus: {corpus_dir}")
        return []

    logger.info(f"Minimizing corpus: {len(seed_files)} seeds")

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
                        f"Kept {seed_file.name}: +{len(unique_coverage)} unique edges"
                    )
                else:
                    logger.debug(f"Skipped {seed_file.name}: no new coverage")

            except Exception as e:
                logger.warning(f"Error processing {seed_file.name}: {e}")
                # Keep seed if we can't determine coverage
                minimized_corpus.append(seed_file)

        else:
            # No coverage tracker - keep all seeds (just copy)
            minimized_corpus.append(seed_file)

        # Respect max corpus size
        if max_corpus_size and len(minimized_corpus) >= max_corpus_size:
            logger.info(f"Reached max corpus size ({max_corpus_size})")
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
        f"Corpus minimized: {len(seed_files)} -> {len(minimized_corpus)} seeds "
        f"({reduction_pct:.1f}% reduction)"
    )

    if coverage_tracker:
        logger.info(f"Total unique coverage: {len(total_coverage)} edges")

    return copied_files


def validate_corpus_quality(corpus_dir: Path) -> dict:
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
