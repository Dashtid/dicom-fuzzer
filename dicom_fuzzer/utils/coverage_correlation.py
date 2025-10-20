"""
Coverage Correlation Analysis

CONCEPT: Correlate crashes with coverage data to identify vulnerable
code paths and prioritize security fixes.

SECURITY INSIGHT: Shows which code paths lead to crashes, helping
developers focus on high-risk areas.

RESEARCH: "Examining which lines are executed is helpful for understanding
the effectiveness of your fuzzer." (2025 Best Practices)
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CoverageInsight:
    """
    Coverage insights for a specific code path or function.

    Tracks how often a path is hit and whether it leads to crashes.
    """

    identifier: str  # Function name, file:line, or basic block ID
    total_hits: int = 0
    crash_hits: int = 0
    safe_hits: int = 0
    crash_rate: float = 0.0
    unique_crashes: Set[str] = field(default_factory=set)

    def update_crash_rate(self):
        """Recalculate crash rate based on current hits."""
        if self.total_hits == 0:
            self.crash_rate = 0.0
        else:
            self.crash_rate = self.crash_hits / self.total_hits


@dataclass
class CrashCoverageCorrelation:
    """
    Correlation between crashes and coverage data.

    Identifies which code paths are most strongly associated with crashes.
    """

    # Coverage unique to crashes (only hit when crashing)
    crash_only_coverage: Dict[str, Set[str]] = field(default_factory=dict)

    # Coverage correlation scores
    coverage_insights: Dict[str, CoverageInsight] = field(default_factory=dict)

    # Most dangerous paths (highest crash rate)
    dangerous_paths: List[Tuple[str, float]] = field(default_factory=list)

    # Functions associated with crashes
    vulnerable_functions: Set[str] = field(default_factory=set)


def correlate_crashes_with_coverage(
    crashes: List,
    coverage_data: Dict[str, Set[str]],
    safe_inputs: Optional[List[str]] = None,
) -> CrashCoverageCorrelation:
    """
    Correlate crashes with coverage to identify vulnerable code paths.

    CONCEPT: Analyze which code paths are disproportionately hit during
    crashes vs safe executions. This reveals dangerous code areas.

    Args:
        crashes: List of crash records (must have test_case_path attribute)
        coverage_data: Dict mapping test file path -> set of coverage IDs
        safe_inputs: Optional list of safe test inputs for comparison

    Returns:
        CrashCoverageCorrelation with vulnerability insights
    """
    correlation = CrashCoverageCorrelation()

    # Build coverage insights
    coverage_tracker = defaultdict(CoverageInsight)

    # Track safe coverage (baseline)
    safe_coverage: Set[str] = set()
    if safe_inputs:
        for safe_input in safe_inputs:
            if safe_input in coverage_data:
                safe_coverage |= coverage_data[safe_input]

    # Process each crash
    for crash in crashes:
        # Get coverage for crash-triggering input
        crash_input = str(crash.test_case_path)
        if crash_input not in coverage_data:
            logger.warning(f"No coverage data for crash input: {crash_input}")
            continue

        crash_coverage = coverage_data[crash_input]

        # Update coverage insights for each hit
        for coverage_id in crash_coverage:
            if coverage_id not in coverage_tracker:
                coverage_tracker[coverage_id] = CoverageInsight(identifier=coverage_id)

            insight = coverage_tracker[coverage_id]
            insight.total_hits += 1
            insight.crash_hits += 1
            insight.unique_crashes.add(crash.crash_id)

        # Find coverage unique to this crash
        crash_only = crash_coverage - safe_coverage
        if crash_only:
            correlation.crash_only_coverage[crash.crash_id] = crash_only
            logger.debug(f"Crash {crash.crash_id}: {len(crash_only)} unique code paths")

    # Update safe hits
    for safe_input in safe_inputs or []:
        if safe_input not in coverage_data:
            continue

        for coverage_id in coverage_data[safe_input]:
            if coverage_id not in coverage_tracker:
                coverage_tracker[coverage_id] = CoverageInsight(identifier=coverage_id)

            insight = coverage_tracker[coverage_id]
            insight.total_hits += 1
            insight.safe_hits += 1

    # Calculate crash rates
    for insight in coverage_tracker.values():
        insight.update_crash_rate()

    correlation.coverage_insights = dict(coverage_tracker)

    # Identify dangerous paths (high crash rate)
    dangerous = [
        (identifier, insight.crash_rate)
        for identifier, insight in coverage_tracker.items()
        if insight.crash_rate > 0.5  # >50% crash rate
        and insight.total_hits >= 3  # Minimum sample size
    ]

    # Sort by crash rate descending
    dangerous.sort(key=lambda x: x[1], reverse=True)
    correlation.dangerous_paths = dangerous

    # Extract vulnerable functions
    correlation.vulnerable_functions = _extract_functions_from_coverage(dangerous)

    logger.info(
        f"Coverage correlation complete: {len(dangerous)} dangerous paths identified"
    )

    return correlation


def _extract_functions_from_coverage(
    dangerous_paths: List[Tuple[str, float]],
) -> Set[str]:
    """
    Extract function names from coverage identifiers.

    Args:
        dangerous_paths: List of (coverage_id, crash_rate) tuples

    Returns:
        Set of function names
    """
    functions = set()

    for coverage_id, _ in dangerous_paths:
        # Coverage ID format varies: "file.py:123", "function_name", "module.function"
        # Try to extract function name

        if ":" in coverage_id:
            # Format: "file.py:line" or "file.py:function"
            parts = coverage_id.split(":")
            if len(parts) >= 2:
                # Try to get function name from second part
                func_part = parts[1]
                if not func_part.isdigit():  # Not a line number
                    functions.add(func_part)

        elif "." in coverage_id:
            # Format: "module.function"
            function_name = coverage_id.split(".")[-1]
            functions.add(function_name)

        else:
            # Assume it's a function name
            functions.add(coverage_id)

    return functions


def generate_correlation_report(
    correlation: CrashCoverageCorrelation, top_n: int = 20
) -> str:
    """
    Generate human-readable coverage correlation report.

    Args:
        correlation: Correlation results
        top_n: Number of top dangerous paths to show

    Returns:
        Formatted report string
    """
    report = []

    report.append("=" * 80)
    report.append("CRASH-COVERAGE CORRELATION REPORT")
    report.append("=" * 80)
    report.append("")

    # Summary statistics
    total_insights = len(correlation.coverage_insights)
    dangerous_count = len(correlation.dangerous_paths)

    report.append(f"Total Coverage Points Analyzed: {total_insights:,}")
    report.append(
        f"Dangerous Paths Found:          {dangerous_count:,} (>{50}% crash rate)"
    )
    report.append(
        f"Vulnerable Functions:           {len(correlation.vulnerable_functions)}"
    )
    report.append("")

    # Top dangerous paths
    if correlation.dangerous_paths:
        report.append("TOP DANGEROUS CODE PATHS:")
        report.append("-" * 80)
        report.append(f"{'Rank':<6} {'Crash Rate':<12} {'Hits':<8} {'Coverage ID':<50}")
        report.append("-" * 80)

        for i, (coverage_id, crash_rate) in enumerate(
            correlation.dangerous_paths[:top_n], 1
        ):
            insight = correlation.coverage_insights[coverage_id]
            report.append(
                f"{i:<6} {crash_rate * 100:>6.1f}%     "
                f"{insight.total_hits:<8} {coverage_id:<50}"
            )

        report.append("")

    # Vulnerable functions
    if correlation.vulnerable_functions:
        report.append("VULNERABLE FUNCTIONS:")
        report.append("-" * 80)
        for func in sorted(correlation.vulnerable_functions)[:top_n]:
            report.append(f"  - {func}")
        report.append("")

    # Crash-only coverage summary
    total_crash_only = 0
    if correlation.crash_only_coverage:
        total_crash_only = sum(
            len(paths) for paths in correlation.crash_only_coverage.values()
        )
        report.append("CRASH-ONLY CODE PATHS:")
        report.append("-" * 80)
        report.append(f"Code paths only executed during crashes: {total_crash_only:,}")
        report.append(
            f"Crashes with unique paths:                {len(correlation.crash_only_coverage):,}"
        )
        report.append("")

    # Recommendations
    report.append("RECOMMENDATIONS:")
    report.append("-" * 80)

    if dangerous_count > 0:
        report.append(
            f"  [!] Prioritize reviewing {dangerous_count} dangerous code paths"
        )
        report.append("  [!] Focus on functions with >80% crash rate")
        report.append("  [!] Add defensive checks to crash-prone paths")
    else:
        report.append("  [+] No highly dangerous code paths detected")

    if total_crash_only > 0:
        report.append(f"  [!] Investigate {total_crash_only} crash-only code paths")
        report.append("  [!] These may indicate error handling issues")

    report.append("")
    report.append("=" * 80)

    return "\n".join(report)


def identify_crash_prone_modules(
    correlation: CrashCoverageCorrelation,
) -> Dict[str, int]:
    """
    Identify modules/files with most crash-prone code.

    Args:
        correlation: Correlation results

    Returns:
        Dict mapping module name -> dangerous path count
    """
    module_counts = defaultdict(int)

    for coverage_id, crash_rate in correlation.dangerous_paths:
        # Extract module/file name
        if ":" in coverage_id:
            # Format: "file.py:line" or "file.py:function"
            module = coverage_id.split(":")[0]
        elif "." in coverage_id:
            # Format: "module.function"
            parts = coverage_id.split(".")
            module = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]
        else:
            module = "unknown"

        module_counts[module] += 1

    return dict(module_counts)


def get_safe_coverage(coverage_data: Dict[str, Set[str]]) -> Set[str]:
    """
    Get coverage from inputs that didn't crash.

    CONCEPT: Baseline "safe" coverage for comparison with crash coverage.

    Args:
        coverage_data: Dict mapping test file -> coverage set

    Returns:
        Set of coverage IDs from safe executions
    """
    # Simple implementation: union of all coverage
    # In practice, you'd filter to only non-crash inputs
    safe_coverage = set()
    for coverage_set in coverage_data.values():
        safe_coverage |= coverage_set

    return safe_coverage
