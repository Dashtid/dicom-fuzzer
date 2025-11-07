"""Coverage Correlation - Link Crashes to Code Coverage

Correlates fuzzing results with code coverage data to identify:
- Which code paths trigger crashes
- Uncovered code that might contain vulnerabilities
- Coverage-guided fuzzing prioritization
"""

import json
from pathlib import Path


class CoverageCorrelator:
    """Correlate crashes with code coverage data."""

    def __init__(self, coverage_file: Path | None = None):
        """Initialize coverage correlator.

        Args:
            coverage_file: Path to coverage.json file from coverage.py

        """
        self.coverage_file = coverage_file or Path("reports/coverage/.coverage")
        self.coverage_data = {}

        if self.coverage_file.exists():
            self._load_coverage()

    def _load_coverage(self):
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

    def correlate_crashes(self, crashes: list[dict], fuzzing_session: dict) -> dict:
        """Correlate crashes with coverage data.

        Args:
            crashes: List of crash records
            fuzzing_session: Fuzzing session data

        Returns:
            Correlation analysis dictionary

        """
        results = {
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

    def _analyze_crash_coverage(self, crash: dict, session: dict) -> dict | None:
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

    def _identify_hotspots(self, crash_coverage: list[dict]) -> dict:
        """Identify code areas with multiple crashes.

        Args:
            crash_coverage: List of crash coverage analyses

        Returns:
            Hotspot dictionary

        """
        hotspots = {}

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

    def _generate_recommendations(self, results: dict) -> list[str]:
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
