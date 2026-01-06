"""Coverage Correlation Analysis

CONCEPT: Correlate crashes with coverage data to identify vulnerable
code paths and prioritize security fixes.

SECURITY INSIGHT: Shows which code paths lead to crashes, helping
developers focus on high-risk areas.

RESEARCH: "Examining which lines are executed is helpful for understanding
the effectiveness of your fuzzer." (2025 Best Practices)
"""

from collections import defaultdict
from dataclasses import dataclass, field

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CoverageInsight:
    """Coverage insights for a specific code path or function.

    Tracks how often a path is hit and whether it leads to crashes.
    """

    identifier: str  # Function name, file:line, or basic block ID
    total_hits: int = 0
    crash_hits: int = 0
    safe_hits: int = 0
    crash_rate: float = 0.0
    unique_crashes: set[str] = field(default_factory=set)

    def update_crash_rate(self) -> None:
        """Recalculate crash rate based on current hits."""
        if self.total_hits == 0:
            self.crash_rate = 0.0
        else:
            self.crash_rate = self.crash_hits / self.total_hits


@dataclass
class CrashCoverageCorrelation:
    """Correlation between crashes and coverage data.

    Identifies which code paths are most strongly associated with crashes.
    """

    # Coverage unique to crashes (only hit when crashing)
    crash_only_coverage: dict[str, set[str]] = field(default_factory=dict)

    # Coverage correlation scores
    coverage_insights: dict[str, CoverageInsight] = field(default_factory=dict)

    # Most dangerous paths (highest crash rate)
    dangerous_paths: list[tuple[str, float]] = field(default_factory=list)

    # Functions associated with crashes
    vulnerable_functions: set[str] = field(default_factory=set)


def _build_safe_coverage(
    safe_inputs: list[str] | None, coverage_data: dict[str, set[str]]
) -> set[str]:
    """Build baseline coverage from safe inputs."""
    safe_coverage: set[str] = set()
    if safe_inputs:
        for safe_input in safe_inputs:
            if safe_input in coverage_data:
                safe_coverage |= coverage_data[safe_input]
    return safe_coverage


def _process_crash(
    crash: object,
    coverage_data: dict[str, set[str]],
    coverage_tracker: dict[str, CoverageInsight],
    safe_coverage: set[str],
    correlation: CrashCoverageCorrelation,
) -> None:
    """Process a single crash and update coverage tracking."""
    crash_input = str(crash.test_case_path)  # type: ignore[attr-defined]
    if crash_input not in coverage_data:
        logger.warning(f"No coverage data for crash input: {crash_input}")
        return

    crash_coverage = coverage_data[crash_input]
    crash_id = crash.crash_id  # type: ignore[attr-defined]

    for coverage_id in crash_coverage:
        if coverage_id not in coverage_tracker:
            coverage_tracker[coverage_id] = CoverageInsight(identifier=coverage_id)
        insight = coverage_tracker[coverage_id]
        insight.total_hits += 1
        insight.crash_hits += 1
        insight.unique_crashes.add(crash_id)

    crash_only = crash_coverage - safe_coverage
    if crash_only:
        correlation.crash_only_coverage[crash_id] = crash_only
        logger.debug(f"Crash {crash_id}: {len(crash_only)} unique code paths")


def _update_safe_hits(
    safe_inputs: list[str] | None,
    coverage_data: dict[str, set[str]],
    coverage_tracker: dict[str, CoverageInsight],
) -> None:
    """Update coverage tracker with safe input hits."""
    for safe_input in safe_inputs or []:
        if safe_input not in coverage_data:
            continue
        for coverage_id in coverage_data[safe_input]:
            if coverage_id not in coverage_tracker:
                coverage_tracker[coverage_id] = CoverageInsight(identifier=coverage_id)
            insight = coverage_tracker[coverage_id]
            insight.total_hits += 1
            insight.safe_hits += 1


def _identify_dangerous_paths(
    coverage_tracker: dict[str, CoverageInsight],
) -> list[tuple[str, float]]:
    """Identify and sort dangerous code paths by crash rate."""
    for insight in coverage_tracker.values():
        insight.update_crash_rate()

    dangerous = [
        (identifier, insight.crash_rate)
        for identifier, insight in coverage_tracker.items()
        if insight.crash_rate > 0.5 and insight.total_hits >= 3
    ]
    dangerous.sort(key=lambda x: x[1], reverse=True)
    return dangerous


def correlate_crashes_with_coverage(
    crashes: list,
    coverage_data: dict[str, set[str]],
    safe_inputs: list[str] | None = None,
) -> CrashCoverageCorrelation:
    """Correlate crashes with coverage to identify vulnerable code paths.

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
    coverage_tracker: dict[str, CoverageInsight] = defaultdict(
        lambda: CoverageInsight(identifier="")
    )

    safe_coverage = _build_safe_coverage(safe_inputs, coverage_data)

    for crash in crashes:
        _process_crash(
            crash, coverage_data, coverage_tracker, safe_coverage, correlation
        )

    _update_safe_hits(safe_inputs, coverage_data, coverage_tracker)

    correlation.coverage_insights = dict(coverage_tracker)
    correlation.dangerous_paths = _identify_dangerous_paths(coverage_tracker)
    correlation.vulnerable_functions = _extract_functions_from_coverage(
        correlation.dangerous_paths
    )

    logger.info(
        f"Coverage correlation complete: "
        f"{len(correlation.dangerous_paths)} dangerous paths identified"
    )

    return correlation


def _extract_functions_from_coverage(
    dangerous_paths: list[tuple[str, float]],
) -> set[str]:
    """Extract function names from coverage identifiers.

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
    """Generate human-readable coverage correlation report.

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
) -> dict[str, int]:
    """Identify modules/files with most crash-prone code.

    Args:
        correlation: Correlation results

    Returns:
        Dict mapping module name -> dangerous path count

    """
    module_counts: dict[str, int] = defaultdict(int)

    for coverage_id, _crash_rate in correlation.dangerous_paths:
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


def get_safe_coverage(coverage_data: dict[str, set[str]]) -> set[str]:
    """Get coverage from inputs that didn't crash.

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
