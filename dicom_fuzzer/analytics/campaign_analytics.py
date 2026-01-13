"""Campaign Analytics Engine - Statistical Analysis for Fuzzing Campaigns

This module provides advanced statistical analysis for DICOM fuzzing campaigns:
- Coverage correlation (which mutations find which bugs)
- Trend analysis (crash discovery rate over time)
- Performance profiling (mutations/sec, memory usage)
- Strategy effectiveness scoring
- Multi-session campaign tracking

CONCEPT: Analytics transform raw fuzzing data into actionable insights:
- Which strategies are most effective?
- What coverage patterns correlate with crashes?
- How does crash discovery rate change over time?
- Where should fuzzing resources be allocated?

Based on 2025 best practices from FuzzManager (Mozilla) and modern ML-based
fuzzing analytics (coverage-guided mutation selection).
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from dicom_fuzzer.core.series_reporter import Series3DReport
from dicom_fuzzer.core.statistics import MutationStatistics


@dataclass
class CoverageCorrelation:
    """Correlation between mutation strategies and code coverage.

    Tracks which mutations lead to which code paths being executed,
    helping identify high-value mutation strategies.
    """

    strategy: str
    coverage_increase: float  # Percentage increase in coverage
    unique_paths: int  # Number of unique code paths discovered
    crash_correlation: float  # Correlation coefficient with crashes (0-1)
    sample_size: int  # Number of mutations analyzed

    def correlation_score(self) -> float:
        """Calculate overall correlation score (0-1).

        Higher score = strategy is more effective at finding bugs.
        """
        # Weighted scoring:
        # - 40% coverage increase
        # - 30% crash correlation
        # - 30% unique paths (normalized)

        normalized_paths = min(self.unique_paths / 100.0, 1.0)  # Cap at 100 paths

        score = (
            0.4 * min(self.coverage_increase / 100.0, 1.0)
            + 0.3 * self.crash_correlation
            + 0.3 * normalized_paths
        )

        return max(0.0, min(1.0, score))


@dataclass
class TrendAnalysis:
    """Time-series analysis of fuzzing campaign progress.

    Tracks how crash discovery and coverage change over time,
    helping identify when to stop fuzzing or adjust strategies.
    """

    campaign_name: str
    start_time: datetime
    end_time: datetime
    total_duration: timedelta

    # Time-series data
    crashes_over_time: list[tuple[datetime, int]] = field(default_factory=list)
    coverage_over_time: list[tuple[datetime, float]] = field(default_factory=list)
    mutations_over_time: list[tuple[datetime, int]] = field(default_factory=list)

    def crash_discovery_rate(self) -> float:
        """Calculate crash discovery rate (crashes per hour).

        Returns:
            Crashes found per hour of fuzzing

        """
        if not self.crashes_over_time or self.total_duration.total_seconds() == 0:
            return 0.0

        total_crashes = sum(count for _, count in self.crashes_over_time)
        hours = self.total_duration.total_seconds() / 3600

        return total_crashes / hours if hours > 0 else 0.0

    def coverage_growth_rate(self) -> float:
        """Calculate coverage growth rate (% per hour).

        Returns:
            Percentage increase in coverage per hour

        """
        if len(self.coverage_over_time) < 2 or self.total_duration.total_seconds() == 0:
            return 0.0

        initial_coverage = self.coverage_over_time[0][1]
        final_coverage = self.coverage_over_time[-1][1]

        if initial_coverage == 0:
            return 0.0

        coverage_increase = final_coverage - initial_coverage
        hours = self.total_duration.total_seconds() / 3600

        return (
            (coverage_increase / initial_coverage * 100) / hours if hours > 0 else 0.0
        )

    def is_plateauing(
        self, threshold_hours: float = 1.0, min_rate: float = 0.1
    ) -> bool:
        """Detect if fuzzing campaign has plateaued (diminishing returns).

        Args:
            threshold_hours: Hours to analyze for plateau detection
            min_rate: Minimum acceptable crash discovery rate

        Returns:
            True if campaign has plateaued (should consider stopping)

        """
        if not self.crashes_over_time or len(self.crashes_over_time) < 2:
            return False

        # Guard against invalid threshold
        if threshold_hours <= 0:
            return False

        # Analyze recent time window
        threshold_delta = timedelta(hours=threshold_hours)
        recent_time = self.end_time - threshold_delta

        recent_crashes = [
            count
            for timestamp, count in self.crashes_over_time
            if timestamp >= recent_time
        ]

        if not recent_crashes:
            return True  # No crashes in recent window

        # Calculate recent crash rate
        recent_total = sum(recent_crashes)
        recent_rate = recent_total / threshold_hours

        return recent_rate < min_rate


@dataclass
class PerformanceMetrics:
    """Performance profiling for fuzzing campaigns.

    Tracks system resource usage and throughput metrics.
    """

    mutations_per_second: float
    peak_memory_mb: float
    avg_memory_mb: float
    cpu_utilization: float  # Percentage (0-100)
    disk_io_mb_per_sec: float
    cache_hit_rate: float  # Percentage (0-100)

    def throughput_score(self) -> float:
        """Calculate overall throughput score (0-1).

        Higher score = better performance optimization.
        """
        # Normalize metrics to 0-1 range
        # Target: 100 mutations/sec, 80% cache hit, 80% CPU

        mutation_score = min(self.mutations_per_second / 100.0, 1.0)
        cache_score = self.cache_hit_rate / 100.0
        cpu_score = self.cpu_utilization / 100.0

        # Weighted average
        return 0.5 * mutation_score + 0.3 * cache_score + 0.2 * cpu_score


class CampaignAnalyzer:
    """Analyzes fuzzing campaigns to provide actionable insights.

    Integrates with existing statistics tracking and provides:
    - Coverage correlation analysis
    - Trend detection
    - Performance profiling
    - Strategy recommendations
    """

    def __init__(self, campaign_name: str = "DICOM Fuzzing"):
        """Initialize campaign analyzer.

        Args:
            campaign_name: Name of the fuzzing campaign

        """
        self.campaign_name = campaign_name
        self.coverage_data: dict[str, CoverageCorrelation] = {}
        self.trend_data: TrendAnalysis | None = None
        self.performance_data: PerformanceMetrics | None = None

    def analyze_strategy_effectiveness(
        self, report: Series3DReport, mutation_stats: list[MutationStatistics]
    ) -> dict[str, dict[str, float]]:
        """Analyze effectiveness of mutation strategies.

        Args:
            report: Series3D report with mutation data
            mutation_stats: List of mutation statistics

        Returns:
            Dictionary mapping strategy names to effectiveness metrics:
            - effectiveness_score: Overall score (0-1)
            - crashes_per_mutation: Crash rate
            - coverage_contribution: Coverage increase
            - time_efficiency: Mutations per second

        """
        effectiveness = {}
        strategy_effectiveness_data = report.get_strategy_effectiveness()

        # Create lookup dict for mutation stats
        stats_by_strategy = {stat.strategy_name: stat for stat in mutation_stats}

        for strategy, metrics in strategy_effectiveness_data.items():
            stat = stats_by_strategy.get(strategy)

            if stat:
                # Calculate comprehensive effectiveness
                effectiveness[strategy] = {
                    "effectiveness_score": stat.effectiveness_score(),
                    "crashes_per_mutation": (
                        stat.crashes_found / stat.times_used
                        if stat.times_used > 0
                        else 0.0
                    ),
                    "coverage_contribution": metrics["series_coverage"],
                    "time_efficiency": (
                        stat.times_used / stat.total_duration
                        if stat.total_duration > 0
                        else 0.0
                    ),
                    "usage_count": metrics["usage_count"],
                    "avg_mutations_per_series": metrics["avg_mutations_per_series"],
                }
            else:
                # Fallback to basic metrics from report
                effectiveness[strategy] = {
                    "effectiveness_score": 0.5,  # Unknown, assume moderate
                    "crashes_per_mutation": 0.0,
                    "coverage_contribution": metrics["series_coverage"],
                    "time_efficiency": 0.0,
                    "usage_count": metrics["usage_count"],
                    "avg_mutations_per_series": metrics["avg_mutations_per_series"],
                }

        return effectiveness

    def calculate_coverage_correlation(
        self,
        strategy: str,
        coverage_increase: float,
        unique_paths: int,
        crashes_found: int,
        mutations_applied: int,
    ) -> CoverageCorrelation:
        """Calculate coverage correlation for a mutation strategy.

        Args:
            strategy: Mutation strategy name
            coverage_increase: Percentage increase in coverage
            unique_paths: Number of unique code paths discovered
            crashes_found: Number of crashes found
            mutations_applied: Number of mutations applied

        Returns:
            CoverageCorrelation object with analysis results

        """
        # Calculate crash correlation (simple ratio for now)
        crash_correlation = (
            crashes_found / mutations_applied if mutations_applied > 0 else 0.0
        )

        correlation = CoverageCorrelation(
            strategy=strategy,
            coverage_increase=coverage_increase,
            unique_paths=unique_paths,
            crash_correlation=min(crash_correlation, 1.0),
            sample_size=mutations_applied,
        )

        # Cache for reporting
        self.coverage_data[strategy] = correlation

        return correlation

    def analyze_trends(
        self,
        start_time: datetime,
        end_time: datetime,
        crash_timeline: list[tuple[datetime, int]],
        coverage_timeline: list[tuple[datetime, float]],
        mutation_timeline: list[tuple[datetime, int]],
    ) -> TrendAnalysis:
        """Analyze time-series trends in fuzzing campaign.

        Args:
            start_time: Campaign start time
            end_time: Campaign end time
            crash_timeline: List of (timestamp, crash_count) tuples
            coverage_timeline: List of (timestamp, coverage_percentage) tuples
            mutation_timeline: List of (timestamp, mutation_count) tuples

        Returns:
            TrendAnalysis object with time-series analysis

        """
        trend = TrendAnalysis(
            campaign_name=self.campaign_name,
            start_time=start_time,
            end_time=end_time,
            total_duration=end_time - start_time,
            crashes_over_time=crash_timeline,
            coverage_over_time=coverage_timeline,
            mutations_over_time=mutation_timeline,
        )

        self.trend_data = trend
        return trend

    def profile_performance(
        self,
        mutations_per_second: float,
        peak_memory_mb: float,
        avg_memory_mb: float,
        cpu_utilization: float,
        disk_io_mb_per_sec: float = 0.0,
        cache_hit_rate: float = 0.0,
    ) -> PerformanceMetrics:
        """Profile campaign performance metrics.

        Args:
            mutations_per_second: Mutation throughput
            peak_memory_mb: Peak memory usage in MB
            avg_memory_mb: Average memory usage in MB
            cpu_utilization: CPU utilization percentage (0-100)
            disk_io_mb_per_sec: Disk I/O in MB/sec
            cache_hit_rate: Cache hit rate percentage (0-100)

        Returns:
            PerformanceMetrics object with profiling data

        """
        metrics = PerformanceMetrics(
            mutations_per_second=mutations_per_second,
            peak_memory_mb=peak_memory_mb,
            avg_memory_mb=avg_memory_mb,
            cpu_utilization=cpu_utilization,
            disk_io_mb_per_sec=disk_io_mb_per_sec,
            cache_hit_rate=cache_hit_rate,
        )

        self.performance_data = metrics
        return metrics

    def _recommend_coverage(self) -> list[str]:
        """Generate coverage-based recommendations."""
        if not self.coverage_data:
            return []
        recommendations: list[str] = []
        best_strategy = max(
            self.coverage_data.items(), key=lambda x: x[1].correlation_score()
        )
        recommendations.append(
            f"[+] Prioritize '{best_strategy[0]}' strategy "
            f"(correlation score: {best_strategy[1].correlation_score():.2f})"
        )
        weak_strategies = [
            strategy
            for strategy, corr in self.coverage_data.items()
            if corr.correlation_score() < 0.3
        ]
        if weak_strategies:
            recommendations.append(
                f"[!] Consider reducing usage of: {', '.join(weak_strategies)}"
            )
        return recommendations

    def _recommend_trends(self) -> list[str]:
        """Generate trend-based recommendations."""
        if not self.trend_data:
            return []
        recommendations: list[str] = []
        if self.trend_data.is_plateauing():
            recommendations.append(
                "[!] Campaign appears to be plateauing - consider stopping or changing strategies"
            )
        crash_rate = self.trend_data.crash_discovery_rate()
        if crash_rate > 1.0:
            recommendations.append(
                f"[+] High crash discovery rate ({crash_rate:.2f}/hour) - continue fuzzing"
            )
        elif crash_rate < 0.1:
            recommendations.append(
                f"[!] Low crash discovery rate ({crash_rate:.2f}/hour) - consider adjusting strategies"
            )
        return recommendations

    def _recommend_performance(self) -> list[str]:
        """Generate performance-based recommendations."""
        if not self.performance_data:
            return []
        recommendations: list[str] = []
        if self.performance_data.throughput_score() < 0.5:
            recommendations.append(
                "[!] Low throughput score - consider performance optimization"
            )
        if self.performance_data.cache_hit_rate < 50.0:
            recommendations.append(
                f"[!] Low cache hit rate ({self.performance_data.cache_hit_rate:.1f}%) - increase cache size"
            )
        if self.performance_data.cpu_utilization < 60.0:
            recommendations.append(
                f"[!] Low CPU utilization ({self.performance_data.cpu_utilization:.1f}%) - increase worker count"
            )
        if self.performance_data.peak_memory_mb > 2000:
            recommendations.append(
                f"[!] High memory usage ({self.performance_data.peak_memory_mb:.0f}MB) - consider reducing cache or batch size"
            )
        return recommendations

    def generate_recommendations(self) -> list[str]:
        """Generate actionable recommendations based on analysis.

        Returns:
            List of recommendation strings

        """
        recommendations: list[str] = []
        recommendations.extend(self._recommend_coverage())
        recommendations.extend(self._recommend_trends())
        recommendations.extend(self._recommend_performance())

        if not recommendations:
            recommendations.append(
                "[i] No specific recommendations - campaign performing normally"
            )

        return recommendations

    def export_to_json(self, output_path: Path) -> Path:
        """Export analysis results to JSON.

        Args:
            output_path: Path to output JSON file

        Returns:
            Path to exported file

        """
        data: dict[str, Any] = {
            "campaign_name": self.campaign_name,
            "generated_at": datetime.now().isoformat(),
            "coverage_correlation": {
                strategy: {
                    "coverage_increase": corr.coverage_increase,
                    "unique_paths": corr.unique_paths,
                    "crash_correlation": corr.crash_correlation,
                    "sample_size": corr.sample_size,
                    "correlation_score": corr.correlation_score(),
                }
                for strategy, corr in self.coverage_data.items()
            },
            "trend_analysis": None,
            "performance_metrics": None,
            "recommendations": self.generate_recommendations(),
        }

        if self.trend_data:
            data["trend_analysis"] = {
                "start_time": self.trend_data.start_time.isoformat(),
                "end_time": self.trend_data.end_time.isoformat(),
                "total_duration_hours": self.trend_data.total_duration.total_seconds()
                / 3600,
                "crash_discovery_rate": self.trend_data.crash_discovery_rate(),
                "coverage_growth_rate": self.trend_data.coverage_growth_rate(),
                "is_plateauing": self.trend_data.is_plateauing(),
            }

        if self.performance_data:
            data["performance_metrics"] = {
                "mutations_per_second": self.performance_data.mutations_per_second,
                "peak_memory_mb": self.performance_data.peak_memory_mb,
                "avg_memory_mb": self.performance_data.avg_memory_mb,
                "cpu_utilization": self.performance_data.cpu_utilization,
                "disk_io_mb_per_sec": self.performance_data.disk_io_mb_per_sec,
                "cache_hit_rate": self.performance_data.cache_hit_rate,
                "throughput_score": self.performance_data.throughput_score(),
            }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return output_path
