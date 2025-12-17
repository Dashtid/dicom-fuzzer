"""Coverage Correlation - Link Crashes to Code Coverage

Correlates fuzzing results with code coverage data to identify:
- Which code paths trigger crashes
- Uncovered code that might contain vulnerabilities
- Coverage-guided fuzzing prioritization
"""

import json
from pathlib import Path
from typing import Any


class CoverageCorrelator:
    """Correlate crashes with code coverage data."""

    def __init__(self, coverage_file: Path | None = None):
        """Initialize coverage correlator.

        Args:
            coverage_file: Path to coverage.json file from coverage.py

        """
        self.coverage_file = coverage_file or Path("reports/coverage/.coverage")
        self.coverage_data: dict[str, Any] = {}
        self.data_points: list[dict[str, Any]] = []  # For incremental data collection

        if self.coverage_file.exists():
            self._load_coverage()

    def _load_coverage(self) -> None:
        """Load coverage data from file."""
        try:
            # Coverage.py stores data in JSON format
            with open(self.coverage_file, encoding="utf-8") as f:
                self.coverage_data = json.load(f)
        except Exception as e:
            # Try alternate format or coverage file doesn't exist yet
            # This is expected during first run before coverage is collected
            import structlog

            logger = structlog.get_logger()
            logger.debug(
                "coverage_file_not_loaded", file=str(self.coverage_file), reason=str(e)
            )

    def correlate_crashes(
        self, crashes: list[dict[str, Any]], fuzzing_session: dict[str, Any]
    ) -> dict[str, Any]:
        """Correlate crashes with coverage data.

        Args:
            crashes: List of crash records
            fuzzing_session: Fuzzing session data

        Returns:
            Correlation analysis dictionary

        """
        results: dict[str, Any] = {
            "crashes_with_coverage": [],
            "coverage_hotspots": {},  # Code areas with many crashes
            "uncovered_mutations": [],  # Mutations that didn't trigger coverage
            "coverage_guided_recommendations": [],
        }

        # Analyze each crash
        for crash in crashes:
            crash_analysis = self._analyze_crash_coverage(crash, fuzzing_session)
            if crash_analysis:
                results["crashes_with_coverage"].append(crash_analysis)

        # Identify hotspots (code areas with multiple crashes)
        results["coverage_hotspots"] = self._identify_hotspots(
            results["crashes_with_coverage"]
        )

        # Generate recommendations
        results["coverage_guided_recommendations"] = self._generate_recommendations(
            results
        )

        return results

    def _analyze_crash_coverage(
        self, crash: dict[str, Any], session: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Analyze coverage for a specific crash.

        Args:
            crash: Crash record
            session: Fuzzing session data

        Returns:
            Coverage analysis or None

        """
        # Get file that caused crash
        file_id = crash.get("fuzzed_file_id")
        if not file_id:
            return None

        # Get mutations for this file
        fuzzed_files = session.get("fuzzed_files", {})
        file_record = fuzzed_files.get(file_id)

        if not file_record:
            return None

        mutations = file_record.get("mutations", [])

        return {
            "crash_id": crash["crash_id"],
            "file_id": file_id,
            "mutations_count": len(mutations),
            "mutation_types": list(
                {m.get("mutation_type", "unknown") for m in mutations}
            ),
            "severity": crash.get("severity"),
            "crash_type": crash.get("crash_type"),
        }

    def _identify_hotspots(
        self, crash_coverage: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Identify code areas with multiple crashes.

        Args:
            crash_coverage: List of crash coverage analyses

        Returns:
            Hotspot dictionary

        """
        hotspots: dict[str, Any] = {}

        # Group by mutation types
        for analysis in crash_coverage:
            for mut_type in analysis.get("mutation_types", []):
                if mut_type not in hotspots:
                    hotspots[mut_type] = {
                        "crash_count": 0,
                        "crashes": [],
                        "severity_distribution": {},
                    }

                hotspots[mut_type]["crash_count"] += 1
                hotspots[mut_type]["crashes"].append(analysis["crash_id"])

                severity = analysis.get("severity", "unknown")
                hotspots[mut_type]["severity_distribution"][severity] = (
                    hotspots[mut_type]["severity_distribution"].get(severity, 0) + 1
                )

        # Sort by crash count
        return dict(
            sorted(hotspots.items(), key=lambda x: x[1]["crash_count"], reverse=True)
        )

    def _generate_recommendations(self, results: dict[str, Any]) -> list[str]:
        """Generate coverage-guided fuzzing recommendations.

        Args:
            results: Correlation results

        Returns:
            List of recommendations

        """
        recommendations = []

        hotspots = results.get("coverage_hotspots", {})

        if hotspots:
            top_hotspot = list(hotspots.items())[0]
            mut_type, data = top_hotspot

            recommendations.append(
                f"Focus on {mut_type} mutations - caused {data['crash_count']} crashes"
            )

            critical = data["severity_distribution"].get("critical", 0)
            if critical > 0:
                recommendations.append(
                    f"CRITICAL: {critical} critical vulnerabilities found in {mut_type} area"
                )

        # Recommend mutation strategies
        if len(hotspots) > 3:
            recommendations.append(
                f"Diversify mutation strategies - {len(hotspots)} different areas showing vulnerabilities"
            )

        return recommendations

    def add_data_point(
        self, mutation_type: str, coverage: float, crash_found: bool
    ) -> None:
        """Add a data point for incremental correlation analysis.

        Args:
            mutation_type: Type of mutation applied
            coverage: Coverage percentage achieved (0.0-1.0)
            crash_found: Whether a crash was triggered

        """
        self.data_points.append(
            {
                "mutation_type": mutation_type,
                "coverage": coverage,
                "crash_found": crash_found,
            }
        )

    def analyze(self) -> dict[str, Any]:
        """Analyze collected data points for mutation effectiveness.

        Returns:
            Analysis dictionary with mutation effectiveness and coverage trends

        """
        if not self.data_points:
            return {"mutation_effectiveness": {}, "coverage_trends": {}}

        # Group by mutation type
        mutation_stats = {}
        for point in self.data_points:
            mut_type = point["mutation_type"]
            if mut_type not in mutation_stats:
                mutation_stats[mut_type] = {
                    "total_runs": 0,
                    "crashes": 0,
                    "total_coverage": 0.0,
                    "avg_coverage": 0.0,
                    "crash_rate": 0.0,
                }

            stats = mutation_stats[mut_type]
            stats["total_runs"] += 1
            if point["crash_found"]:
                stats["crashes"] += 1
            stats["total_coverage"] += point["coverage"]

        # Calculate averages
        for stats in mutation_stats.values():
            stats["avg_coverage"] = stats["total_coverage"] / stats["total_runs"]
            stats["crash_rate"] = stats["crashes"] / stats["total_runs"]
            del stats["total_coverage"]  # Remove intermediate value

        # Coverage trends (overall)
        total_coverage = sum(p["coverage"] for p in self.data_points)
        avg_coverage = total_coverage / len(self.data_points)
        total_crashes = sum(1 for p in self.data_points if p["crash_found"])

        coverage_trends = {
            "average_coverage": avg_coverage,
            "total_data_points": len(self.data_points),
            "total_crashes": total_crashes,
            "overall_crash_rate": total_crashes / len(self.data_points),
        }

        return {
            "mutation_effectiveness": mutation_stats,
            "coverage_trends": coverage_trends,
        }

    def get_recommendations(self) -> list[str]:
        """Get fuzzing recommendations based on collected data.

        Returns:
            List of recommendation strings

        """
        analysis = self.analyze()
        recommendations = []

        mutation_stats = analysis.get("mutation_effectiveness", {})
        if not mutation_stats:
            return ["Collect more data to generate recommendations"]

        # Find most effective mutation (highest crash rate)
        best_mutation = max(
            mutation_stats.items(), key=lambda x: x[1]["crash_rate"], default=None
        )

        if best_mutation:
            mut_type, stats = best_mutation
            crash_rate = stats["crash_rate"] * 100
            recommendations.append(
                f"Focus on {mut_type} mutations - {crash_rate:.1f}% crash rate "
                f"({stats['crashes']}/{stats['total_runs']} runs)"
            )

        # Find best coverage
        best_coverage = max(
            mutation_stats.items(), key=lambda x: x[1]["avg_coverage"], default=None
        )

        if best_coverage and best_coverage != best_mutation:
            mut_type, stats = best_coverage
            avg_cov = stats["avg_coverage"] * 100
            recommendations.append(
                f"{mut_type} mutations achieve best coverage ({avg_cov:.1f}% average)"
            )

        # Overall trends
        trends = analysis.get("coverage_trends", {})
        overall_crash_rate = trends.get("overall_crash_rate", 0) * 100
        if overall_crash_rate > 50:
            recommendations.append(
                f"High crash rate detected ({overall_crash_rate:.1f}%) - consider more stability testing"
            )

        return recommendations


def correlate_session_coverage(
    session_file: Path, coverage_file: Path | None = None
) -> dict:
    """Correlate entire fuzzing session with coverage.

    Args:
        session_file: Path to session JSON
        coverage_file: Path to coverage data

    Returns:
        Correlation analysis

    """
    with open(session_file, encoding="utf-8") as f:
        session_data = json.load(f)

    correlator = CoverageCorrelator(coverage_file)
    crashes = session_data.get("crashes", [])

    return correlator.correlate_crashes(crashes, session_data)
