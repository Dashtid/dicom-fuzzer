"""
Tests for Coverage Correlation

Tests linking crashes to code coverage for guided fuzzing.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from dicom_fuzzer.core.coverage_correlation import CoverageCorrelator


class TestCoverageCorrelator:
    """Test coverage correlation functionality."""

    @pytest.fixture
    def temp_coverage_file(self):
        """Create temporary coverage file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            coverage_data = {
                "files": {
                    "core/parser.py": {
                        "executed_lines": [10, 11, 12, 50, 51],
                        "missing_lines": [100, 101, 102],
                    },
                    "core/validator.py": {
                        "executed_lines": [20, 21, 22],
                        "missing_lines": [80, 81],
                    },
                }
            }
            json.dump(coverage_data, f)
            path = Path(f.name)

        yield path
        path.unlink()

    @pytest.fixture
    def sample_crashes(self):
        """Create sample crash data."""
        return [
            {
                "crash_id": "crash_001",
                "timestamp": datetime.now().isoformat(),
                "crash_type": "crash",
                "severity": "high",
                "fuzzed_file_id": "file_001",
                "exception_type": "ValueError",
                "stack_trace": "File core/parser.py, line 50\nValueError",
            },
            {
                "crash_id": "crash_002",
                "timestamp": datetime.now().isoformat(),
                "crash_type": "crash",
                "severity": "medium",
                "fuzzed_file_id": "file_002",
                "exception_type": "RuntimeError",
                "stack_trace": "File core/validator.py, line 20\nRuntimeError",
            },
        ]

    @pytest.fixture
    def sample_session(self):
        """Create sample fuzzing session."""
        return {
            "session_id": "test_session",
            "mutations": [
                {
                    "mutation_id": "mut_001",
                    "file_id": "file_001",
                    "strategy": "metadata_fuzzer",
                },
                {
                    "mutation_id": "mut_002",
                    "file_id": "file_002",
                    "strategy": "pixel_fuzzer",
                },
            ],
        }

    def test_correlator_initialization_no_file(self):
        """Test correlator initialization without coverage file."""
        correlator = CoverageCorrelator(coverage_file=Path("nonexistent.json"))

        assert correlator.coverage_file == Path("nonexistent.json")
        assert correlator.coverage_data == {}

    def test_correlator_initialization_with_file(self, temp_coverage_file):
        """Test correlator initialization with coverage file."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        assert correlator.coverage_file == temp_coverage_file
        assert "files" in correlator.coverage_data

    def test_load_coverage_data(self, temp_coverage_file):
        """Test loading coverage data from file."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        assert correlator.coverage_data is not None
        assert "files" in correlator.coverage_data
        assert "core/parser.py" in correlator.coverage_data["files"]

    def test_correlate_crashes_basic(
        self, temp_coverage_file, sample_crashes, sample_session
    ):
        """Test basic crash correlation."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        result = correlator.correlate_crashes(sample_crashes, sample_session)

        assert "crashes_with_coverage" in result
        assert "coverage_hotspots" in result
        assert "uncovered_mutations" in result
        assert "coverage_guided_recommendations" in result

    def test_correlate_empty_crashes(self, temp_coverage_file, sample_session):
        """Test correlation with no crashes."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        result = correlator.correlate_crashes([], sample_session)

        assert result["crashes_with_coverage"] == []
        assert isinstance(result["coverage_hotspots"], dict)

    def test_correlate_returns_dict(
        self, temp_coverage_file, sample_crashes, sample_session
    ):
        """Test that correlation returns dictionary."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        result = correlator.correlate_crashes(sample_crashes, sample_session)

        assert isinstance(result, dict)
        assert isinstance(result["crashes_with_coverage"], list)
        assert isinstance(result["coverage_hotspots"], dict)
        assert isinstance(result["uncovered_mutations"], list)
        assert isinstance(result["coverage_guided_recommendations"], list)

    def test_hotspot_identification(
        self, temp_coverage_file, sample_crashes, sample_session
    ):
        """Test identification of coverage hotspots."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        result = correlator.correlate_crashes(sample_crashes, sample_session)

        # Hotspots should be a dictionary
        assert isinstance(result["coverage_hotspots"], dict)

    def test_generate_recommendations(
        self, temp_coverage_file, sample_crashes, sample_session
    ):
        """Test generation of coverage-guided recommendations."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        result = correlator.correlate_crashes(sample_crashes, sample_session)

        # Recommendations should be a list
        assert isinstance(result["coverage_guided_recommendations"], list)

    def test_no_coverage_file_graceful_handling(self, sample_crashes, sample_session):
        """Test graceful handling when no coverage file exists."""
        correlator = CoverageCorrelator(coverage_file=Path("nonexistent.json"))

        # Should not raise exception
        result = correlator.correlate_crashes(sample_crashes, sample_session)

        assert isinstance(result, dict)

    def test_multiple_correlations(
        self, temp_coverage_file, sample_crashes, sample_session
    ):
        """Test running multiple correlations."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        result1 = correlator.correlate_crashes(sample_crashes[:1], sample_session)
        result2 = correlator.correlate_crashes(sample_crashes, sample_session)

        assert isinstance(result1, dict)
        assert isinstance(result2, dict)

    def test_coverage_data_structure(self, temp_coverage_file):
        """Test that coverage data has expected structure."""
        correlator = CoverageCorrelator(coverage_file=temp_coverage_file)

        assert "files" in correlator.coverage_data
        files = correlator.coverage_data["files"]

        # Check structure of file data
        for filename, data in files.items():
            assert "executed_lines" in data
            assert "missing_lines" in data
            assert isinstance(data["executed_lines"], list)
            assert isinstance(data["missing_lines"], list)


class TestLoadCoverageExceptionHandling:
    """Test exception handling in _load_coverage (lines 36-42)."""

    def test_load_coverage_invalid_json(self):
        """Test loading invalid JSON coverage file (lines 36-42)."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("INVALID JSON{{{")
            invalid_file = Path(f.name)

        try:
            correlator = CoverageCorrelator(coverage_file=invalid_file)

            # Should handle exception gracefully (lines 36-42)
            assert correlator.coverage_data == {}
            assert correlator.coverage_file == invalid_file
        finally:
            invalid_file.unlink()

    def test_load_coverage_permission_error(self):
        """Test loading coverage file with permission errors (lines 36-42)."""
        import os
        import stat

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"test": "data"}, f)
            restricted_file = Path(f.name)

        try:
            # Make file unreadable (Unix-like systems only)
            if os.name != "nt":
                os.chmod(restricted_file, 0o000)

                correlator = CoverageCorrelator(coverage_file=restricted_file)

                # Should handle exception gracefully
                assert correlator.coverage_data == {}

                # Restore permissions for cleanup
                os.chmod(restricted_file, stat.S_IRUSR | stat.S_IWUSR)
            else:
                # On Windows, just verify the exception path works
                correlator = CoverageCorrelator(
                    coverage_file=Path("C:\\nonexistent\\path\\file.json")
                )
                assert correlator.coverage_data == {}
        finally:
            if restricted_file.exists():
                # Ensure we can delete
                if os.name != "nt":
                    os.chmod(restricted_file, stat.S_IRUSR | stat.S_IWUSR)
                restricted_file.unlink()


class TestAnalyzeCrashCoverageEdgeCases:
    """Test _analyze_crash_coverage None returns (lines 68, 96, 105-107)."""

    def test_crash_without_file_id(self):
        """Test crash analysis when fuzzed_file_id is missing (line 96)."""
        correlator = CoverageCorrelator()

        # Crash without fuzzed_file_id
        crash = {
            "crash_id": "crash_001",
            "crash_type": "crash",
            # No fuzzed_file_id
        }

        session = {
            "fuzzed_files": {"file_001": {"mutations": [{"mutation_type": "metadata"}]}}
        }

        # Should return None (line 96)
        result = correlator._analyze_crash_coverage(crash, session)
        assert result is None

    def test_crash_with_nonexistent_file_record(self):
        """Test crash analysis when file_record doesn't exist (lines 105-107)."""
        correlator = CoverageCorrelator()

        crash = {
            "crash_id": "crash_001",
            "fuzzed_file_id": "nonexistent_file",
            "crash_type": "crash",
        }

        session = {
            "fuzzed_files": {"file_001": {"mutations": [{"mutation_type": "metadata"}]}}
        }

        # Should return None (lines 105-107)
        result = correlator._analyze_crash_coverage(crash, session)
        assert result is None

    def test_correlate_crashes_filters_none_analyses(self):
        """Test that correlate_crashes filters out None analyses (line 68)."""
        correlator = CoverageCorrelator()

        crashes = [
            {"crash_id": "crash_001"},  # Missing fuzzed_file_id -> returns None
            {
                "crash_id": "crash_002",
                "fuzzed_file_id": "file_001",
                "crash_type": "crash",
                "severity": "high",
            },
        ]

        session = {
            "fuzzed_files": {
                "file_001": {
                    "mutations": [
                        {"mutation_type": "metadata"},
                        {"mutation_type": "pixel"},
                    ]
                }
            }
        }

        result = correlator.correlate_crashes(crashes, session)

        # Should only include crash_002 (line 68 filters None)
        assert len(result["crashes_with_coverage"]) == 1
        assert result["crashes_with_coverage"][0]["crash_id"] == "crash_002"


class TestHotspotIdentificationLogic:
    """Test hotspot identification edge cases (lines 132-144)."""

    def test_hotspot_with_multiple_mutation_types(self):
        """Test hotspot identification with multiple mutation types per crash (lines 132-144)."""
        correlator = CoverageCorrelator()

        crash_coverage = [
            {
                "crash_id": "crash_001",
                "file_id": "file_001",
                "mutation_types": ["metadata", "pixel"],  # Multiple types
                "severity": "critical",
                "crash_type": "crash",
                "mutations_count": 2,
            },
            {
                "crash_id": "crash_002",
                "file_id": "file_002",
                "mutation_types": ["metadata"],
                "severity": "high",
                "crash_type": "hang",
                "mutations_count": 1,
            },
        ]

        hotspots = correlator._identify_hotspots(crash_coverage)

        # Lines 132-144: Each mutation type should be tracked
        assert "metadata" in hotspots
        assert "pixel" in hotspots

        # Metadata appears in 2 crashes
        assert hotspots["metadata"]["crash_count"] == 2
        assert len(hotspots["metadata"]["crashes"]) == 2

        # Pixel appears in 1 crash
        assert hotspots["pixel"]["crash_count"] == 1

        # Severity distribution (lines 143-146)
        assert hotspots["metadata"]["severity_distribution"]["critical"] == 1
        assert hotspots["metadata"]["severity_distribution"]["high"] == 1

    def test_hotspot_sorting_by_crash_count(self):
        """Test hotspots are sorted by crash count descending (lines 149-151)."""
        correlator = CoverageCorrelator()

        crash_coverage = [
            {
                "crash_id": "crash_001",
                "mutation_types": ["rare_mutation"],
                "severity": "low",
            },
            {
                "crash_id": "crash_002",
                "mutation_types": ["common_mutation"],
                "severity": "high",
            },
            {
                "crash_id": "crash_003",
                "mutation_types": ["common_mutation"],
                "severity": "high",
            },
            {
                "crash_id": "crash_004",
                "mutation_types": ["common_mutation"],
                "severity": "critical",
            },
        ]

        hotspots = correlator._identify_hotspots(crash_coverage)

        # Should be sorted by crash count (lines 149-151)
        hotspot_items = list(hotspots.items())
        assert hotspot_items[0][0] == "common_mutation"  # 3 crashes (first)
        assert hotspot_items[1][0] == "rare_mutation"  # 1 crash (second)


class TestRecommendationGeneration:
    """Test recommendation generation logic (lines 168-177, 183)."""

    def test_generate_recommendations_with_critical_severity(self):
        """Test recommendations include critical severity warning (lines 175-177)."""
        correlator = CoverageCorrelator()

        results = {
            "coverage_hotspots": {
                "dangerous_mutation": {
                    "crash_count": 5,
                    "crashes": ["c1", "c2", "c3", "c4", "c5"],
                    "severity_distribution": {"critical": 3, "high": 2},
                }
            },
            "crashes_with_coverage": [],
            "uncovered_mutations": [],
        }

        recommendations = correlator._generate_recommendations(results)

        # Should have critical warning (lines 175-177)
        assert len(recommendations) >= 2
        assert "dangerous_mutation" in recommendations[0]
        assert "5 crashes" in recommendations[0]
        assert "CRITICAL" in recommendations[1]
        assert "3 critical vulnerabilities" in recommendations[1]

    def test_generate_recommendations_diversify_strategies(self):
        """Test diversify recommendation when many hotspots exist (line 183)."""
        correlator = CoverageCorrelator()

        # Create 5 different hotspots (>3 threshold)
        hotspots = {}
        for i in range(5):
            hotspots[f"mutation_type_{i}"] = {
                "crash_count": i + 1,
                "crashes": [f"crash_{i}"],
                "severity_distribution": {"high": 1},
            }

        results = {
            "coverage_hotspots": hotspots,
            "crashes_with_coverage": [],
            "uncovered_mutations": [],
        }

        recommendations = correlator._generate_recommendations(results)

        # Should recommend diversifying (line 183)
        diversify_rec = [r for r in recommendations if "Diversify" in r]
        assert len(diversify_rec) > 0
        assert "5 different areas" in diversify_rec[0]


class TestDataPointCollection:
    """Test add_data_point and analyze methods (lines 200, 215-255)."""

    def test_add_data_point(self):
        """Test adding data points (line 200)."""
        correlator = CoverageCorrelator()

        # Add data points (line 200)
        correlator.add_data_point("metadata_mutation", 0.75, True)
        correlator.add_data_point("pixel_mutation", 0.50, False)
        correlator.add_data_point("metadata_mutation", 0.80, True)

        assert len(correlator.data_points) == 3
        assert correlator.data_points[0]["mutation_type"] == "metadata_mutation"
        assert correlator.data_points[0]["coverage"] == 0.75
        assert correlator.data_points[0]["crash_found"] is True

    def test_analyze_empty_data_points(self):
        """Test analyze with no data points (lines 215-216)."""
        correlator = CoverageCorrelator()

        # Empty data points (lines 215-216)
        result = correlator.analyze()

        assert result["mutation_effectiveness"] == {}
        assert result["coverage_trends"] == {}

    def test_analyze_mutation_effectiveness(self):
        """Test analyze calculates mutation effectiveness (lines 218-241)."""
        correlator = CoverageCorrelator()

        # Add test data
        correlator.add_data_point("mutation_a", 0.60, True)
        correlator.add_data_point("mutation_a", 0.70, True)
        correlator.add_data_point("mutation_a", 0.65, False)

        correlator.add_data_point("mutation_b", 0.80, False)
        correlator.add_data_point("mutation_b", 0.85, False)

        result = correlator.analyze()

        # Mutation A: 3 runs, 2 crashes, avg coverage 0.65
        assert "mutation_a" in result["mutation_effectiveness"]
        stats_a = result["mutation_effectiveness"]["mutation_a"]
        assert stats_a["total_runs"] == 3
        assert stats_a["crashes"] == 2
        assert abs(stats_a["avg_coverage"] - 0.65) < 0.01
        assert abs(stats_a["crash_rate"] - 0.666) < 0.01

        # Mutation B: 2 runs, 0 crashes, avg coverage 0.825
        stats_b = result["mutation_effectiveness"]["mutation_b"]
        assert stats_b["total_runs"] == 2
        assert stats_b["crashes"] == 0
        assert abs(stats_b["avg_coverage"] - 0.825) < 0.01
        assert stats_b["crash_rate"] == 0.0

    def test_analyze_coverage_trends(self):
        """Test analyze calculates coverage trends (lines 244-253)."""
        correlator = CoverageCorrelator()

        correlator.add_data_point("mut_a", 0.50, False)
        correlator.add_data_point("mut_a", 0.70, True)
        correlator.add_data_point("mut_b", 0.80, True)

        result = correlator.analyze()

        trends = result["coverage_trends"]
        assert abs(trends["average_coverage"] - 0.666) < 0.01  # (0.5+0.7+0.8)/3
        assert trends["total_data_points"] == 3
        assert trends["total_crashes"] == 2
        assert abs(trends["overall_crash_rate"] - 0.666) < 0.01  # 2/3


class TestGetRecommendations:
    """Test get_recommendations method (lines 267-307)."""

    def test_get_recommendations_no_data(self):
        """Test recommendations with no data (lines 271-272)."""
        correlator = CoverageCorrelator()

        recommendations = correlator.get_recommendations()

        # Lines 271-272: Should suggest collecting more data
        assert len(recommendations) == 1
        assert "Collect more data" in recommendations[0]

    def test_get_recommendations_best_crash_rate(self):
        """Test recommendation for best crash rate mutation (lines 275-285)."""
        correlator = CoverageCorrelator()

        # Mutation with high crash rate
        correlator.add_data_point("dangerous_mut", 0.60, True)
        correlator.add_data_point("dangerous_mut", 0.65, True)
        correlator.add_data_point("dangerous_mut", 0.70, True)
        correlator.add_data_point("dangerous_mut", 0.55, False)

        # Mutation with low crash rate
        correlator.add_data_point("safe_mut", 0.80, False)
        correlator.add_data_point("safe_mut", 0.85, False)

        recommendations = correlator.get_recommendations()

        # Lines 279-285: Should recommend dangerous_mut (75% crash rate)
        crash_rec = [
            r for r in recommendations if "dangerous_mut" in r and "crash rate" in r
        ]
        assert len(crash_rec) > 0
        assert "75.0%" in crash_rec[0] or "75%" in crash_rec[0]
        assert "3/4 runs" in crash_rec[0]

    def test_get_recommendations_best_coverage(self):
        """Test recommendation for best coverage mutation (lines 288-297)."""
        correlator = CoverageCorrelator()

        # Mutation with high crash rate but low coverage
        correlator.add_data_point("high_crash_mut", 0.40, True)
        correlator.add_data_point("high_crash_mut", 0.45, True)

        # Mutation with no crashes but high coverage
        correlator.add_data_point("high_cov_mut", 0.90, False)
        correlator.add_data_point("high_cov_mut", 0.95, False)

        recommendations = correlator.get_recommendations()

        # Lines 292-297: Should mention high_cov_mut for coverage
        cov_rec = [
            r for r in recommendations if "high_cov_mut" in r and "coverage" in r
        ]
        assert len(cov_rec) > 0
        assert "92" in cov_rec[0] or "93" in cov_rec[0]  # 92.5% average

    def test_get_recommendations_high_crash_rate_warning(self):
        """Test warning for high overall crash rate (lines 300-305)."""
        correlator = CoverageCorrelator()

        # Add many crash data points (>50% crash rate)
        for i in range(6):
            correlator.add_data_point("mut", 0.5 + i * 0.05, True)
        for i in range(2):
            correlator.add_data_point("mut", 0.7 + i * 0.05, False)

        recommendations = correlator.get_recommendations()

        # Lines 302-305: Should warn about high crash rate (75%)
        warning = [r for r in recommendations if "High crash rate" in r]
        assert len(warning) > 0
        assert "75.0%" in warning[0] or "75%" in warning[0]
        assert "stability testing" in warning[0]


class TestCorrelateSessionCoverage:
    """Test correlate_session_coverage standalone function (lines 323-329)."""

    def test_correlate_session_coverage_function(self):
        """Test standalone correlate_session_coverage function (lines 323-329)."""
        from dicom_fuzzer.core.coverage_correlation import correlate_session_coverage

        # Create session file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            session_data = {
                "session_id": "test_session",
                "crashes": [
                    {
                        "crash_id": "crash_001",
                        "fuzzed_file_id": "file_001",
                        "severity": "high",
                        "crash_type": "crash",
                    }
                ],
                "fuzzed_files": {
                    "file_001": {"mutations": [{"mutation_type": "metadata"}]}
                },
            }
            json.dump(session_data, f)
            session_file = Path(f.name)

        try:
            # Test function (lines 323-329)
            result = correlate_session_coverage(session_file)

            assert "crashes_with_coverage" in result
            assert "coverage_hotspots" in result
            assert "uncovered_mutations" in result
            assert "coverage_guided_recommendations" in result

            # Should have analyzed the crash
            assert len(result["crashes_with_coverage"]) == 1
        finally:
            session_file.unlink()

    def test_correlate_session_coverage_with_coverage_file(self):
        """Test correlate_session_coverage with custom coverage file (lines 323-329)."""
        from dicom_fuzzer.core.coverage_correlation import correlate_session_coverage

        # Create session file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            session_data = {
                "crashes": [],
                "fuzzed_files": {},
            }
            json.dump(session_data, f)
            session_file = Path(f.name)

        # Create coverage file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            coverage_data = {"test": "data"}
            json.dump(coverage_data, f)
            coverage_file = Path(f.name)

        try:
            result = correlate_session_coverage(session_file, coverage_file)

            assert isinstance(result, dict)
            assert result["crashes_with_coverage"] == []
        finally:
            session_file.unlink()
            coverage_file.unlink()
