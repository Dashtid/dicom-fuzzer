"""Comprehensive tests for dicom_fuzzer.core.coverage_correlation module.

Tests coverage correlation functionality for linking crashes to code coverage.
"""

import json

import pytest

from dicom_fuzzer.core.coverage_correlation import (
    CoverageCorrelator,
    correlate_session_coverage,
)


class TestCoverageCorrelator:
    """Tests for CoverageCorrelator class."""

    @pytest.fixture
    def correlator(self, tmp_path):
        """Create a CoverageCorrelator instance."""
        return CoverageCorrelator(coverage_file=tmp_path / "coverage.json")

    @pytest.fixture
    def correlator_with_coverage(self, tmp_path):
        """Create a CoverageCorrelator with loaded coverage data."""
        coverage_file = tmp_path / "coverage.json"
        coverage_data = {
            "files": {
                "parser.py": {"covered_lines": [1, 2, 3, 4, 5]},
                "mutator.py": {"covered_lines": [10, 20, 30]},
            }
        }
        coverage_file.write_text(json.dumps(coverage_data))
        return CoverageCorrelator(coverage_file=coverage_file)

    def test_initialization(self, correlator, tmp_path):
        """Test CoverageCorrelator initialization."""
        assert correlator.coverage_file == tmp_path / "coverage.json"
        assert correlator.coverage_data == {}
        assert correlator.data_points == []

    def test_initialization_with_coverage_file(self, correlator_with_coverage):
        """Test initialization loads coverage data."""
        assert "files" in correlator_with_coverage.coverage_data

    def test_initialization_missing_file(self, tmp_path):
        """Test initialization handles missing coverage file."""
        correlator = CoverageCorrelator(coverage_file=tmp_path / "nonexistent.json")
        assert correlator.coverage_data == {}

    def test_correlate_crashes_empty(self, correlator):
        """Test correlate_crashes with empty crash list."""
        result = correlator.correlate_crashes(crashes=[], fuzzing_session={})

        assert result["crashes_with_coverage"] == []
        assert result["coverage_hotspots"] == {}
        assert result["coverage_guided_recommendations"] == []

    def test_correlate_crashes_with_data(self, correlator):
        """Test correlate_crashes with crash and session data."""
        crashes = [
            {
                "crash_id": "crash_1",
                "fuzzed_file_id": "file_1",
                "crash_type": "segfault",
                "severity": "critical",
            },
            {
                "crash_id": "crash_2",
                "fuzzed_file_id": "file_2",
                "crash_type": "overflow",
                "severity": "high",
            },
        ]

        fuzzing_session = {
            "fuzzed_files": {
                "file_1": {
                    "mutations": [
                        {"mutation_type": "header"},
                        {"mutation_type": "metadata"},
                    ]
                },
                "file_2": {
                    "mutations": [
                        {"mutation_type": "pixel"},
                    ]
                },
            }
        }

        result = correlator.correlate_crashes(crashes, fuzzing_session)

        assert len(result["crashes_with_coverage"]) == 2
        assert "header" in result["coverage_hotspots"]
        assert "pixel" in result["coverage_hotspots"]

    def test_correlate_crashes_missing_file_id(self, correlator):
        """Test correlate_crashes handles missing file_id."""
        crashes = [{"crash_id": "crash_no_file", "crash_type": "error"}]

        result = correlator.correlate_crashes(crashes, {})
        assert result["crashes_with_coverage"] == []

    def test_correlate_crashes_missing_file_record(self, correlator):
        """Test correlate_crashes handles missing file record."""
        crashes = [{"crash_id": "crash_1", "fuzzed_file_id": "nonexistent_file"}]

        result = correlator.correlate_crashes(crashes, {"fuzzed_files": {}})
        assert result["crashes_with_coverage"] == []

    def test_identify_hotspots(self, correlator):
        """Test hotspot identification."""
        crashes = [
            {"crash_id": "c1", "fuzzed_file_id": "f1", "severity": "critical"},
            {"crash_id": "c2", "fuzzed_file_id": "f2", "severity": "high"},
            {"crash_id": "c3", "fuzzed_file_id": "f3", "severity": "critical"},
        ]

        session = {
            "fuzzed_files": {
                "f1": {"mutations": [{"mutation_type": "header"}]},
                "f2": {"mutations": [{"mutation_type": "header"}]},
                "f3": {"mutations": [{"mutation_type": "metadata"}]},
            }
        }

        result = correlator.correlate_crashes(crashes, session)
        hotspots = result["coverage_hotspots"]

        # header should have 2 crashes
        assert hotspots["header"]["crash_count"] == 2
        # metadata should have 1 crash
        assert hotspots["metadata"]["crash_count"] == 1
        # hotspots should be sorted by crash count
        hotspot_counts = [data["crash_count"] for data in hotspots.values()]
        assert hotspot_counts == sorted(hotspot_counts, reverse=True)

    def test_generate_recommendations(self, correlator):
        """Test recommendation generation."""
        crashes = [
            {"crash_id": "c1", "fuzzed_file_id": "f1", "severity": "critical"},
            {"crash_id": "c2", "fuzzed_file_id": "f2", "severity": "critical"},
        ]

        session = {
            "fuzzed_files": {
                "f1": {"mutations": [{"mutation_type": "header"}]},
                "f2": {"mutations": [{"mutation_type": "header"}]},
            }
        }

        result = correlator.correlate_crashes(crashes, session)
        recommendations = result["coverage_guided_recommendations"]

        assert len(recommendations) > 0
        # Should recommend focusing on header mutations
        assert any("header" in rec for rec in recommendations)
        # Should mention critical vulnerabilities
        assert any("CRITICAL" in rec for rec in recommendations)

    def test_add_data_point(self, correlator):
        """Test add_data_point method."""
        correlator.add_data_point(
            mutation_type="header", coverage=0.75, crash_found=True
        )
        correlator.add_data_point(
            mutation_type="metadata", coverage=0.60, crash_found=False
        )

        assert len(correlator.data_points) == 2
        assert correlator.data_points[0]["mutation_type"] == "header"
        assert correlator.data_points[0]["coverage"] == 0.75
        assert correlator.data_points[0]["crash_found"] is True

    def test_analyze_empty(self, correlator):
        """Test analyze with no data points."""
        result = correlator.analyze()

        assert result["mutation_effectiveness"] == {}
        assert result["coverage_trends"] == {}

    def test_analyze_with_data(self, correlator):
        """Test analyze with data points."""
        # Add multiple data points
        correlator.add_data_point("header", 0.80, True)
        correlator.add_data_point("header", 0.70, True)
        correlator.add_data_point("header", 0.75, False)
        correlator.add_data_point("metadata", 0.60, False)
        correlator.add_data_point("metadata", 0.55, False)

        result = correlator.analyze()

        # Check mutation effectiveness
        effectiveness = result["mutation_effectiveness"]
        assert "header" in effectiveness
        assert "metadata" in effectiveness

        # Header: 3 runs, 2 crashes
        assert effectiveness["header"]["total_runs"] == 3
        assert effectiveness["header"]["crashes"] == 2
        assert effectiveness["header"]["crash_rate"] == pytest.approx(2 / 3)
        assert effectiveness["header"]["avg_coverage"] == pytest.approx(0.75)

        # Metadata: 2 runs, 0 crashes
        assert effectiveness["metadata"]["total_runs"] == 2
        assert effectiveness["metadata"]["crashes"] == 0
        assert effectiveness["metadata"]["crash_rate"] == 0.0

        # Check coverage trends
        trends = result["coverage_trends"]
        assert trends["total_data_points"] == 5
        assert trends["total_crashes"] == 2
        assert trends["overall_crash_rate"] == pytest.approx(2 / 5)

    def test_get_recommendations_no_data(self, correlator):
        """Test get_recommendations with no data."""
        recommendations = correlator.get_recommendations()
        assert recommendations == ["Collect more data to generate recommendations"]

    def test_get_recommendations_with_data(self, correlator):
        """Test get_recommendations with data."""
        correlator.add_data_point("header", 0.80, True)
        correlator.add_data_point("header", 0.70, True)
        correlator.add_data_point("metadata", 0.90, False)

        recommendations = correlator.get_recommendations()

        assert len(recommendations) > 0
        # Should recommend header (highest crash rate)
        assert any("header" in rec.lower() for rec in recommendations)

    def test_get_recommendations_high_crash_rate(self, correlator):
        """Test recommendations for high overall crash rate."""
        # Add many crashes (>50% rate)
        for i in range(10):
            correlator.add_data_point("header", 0.5, crash_found=(i < 6))

        recommendations = correlator.get_recommendations()

        # Should warn about high crash rate
        assert any("High crash rate" in rec for rec in recommendations)


class TestCorrelateSessionCoverage:
    """Tests for correlate_session_coverage function."""

    def test_correlate_session_coverage(self, tmp_path):
        """Test correlating entire session coverage."""
        # Create session file
        session_data = {
            "crashes": [{"crash_id": "c1", "fuzzed_file_id": "f1", "severity": "high"}],
            "fuzzed_files": {"f1": {"mutations": [{"mutation_type": "header"}]}},
        }
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        result = correlate_session_coverage(session_file)

        assert "crashes_with_coverage" in result
        assert "coverage_hotspots" in result
        assert "coverage_guided_recommendations" in result

    def test_correlate_session_coverage_no_crashes(self, tmp_path):
        """Test correlating session with no crashes."""
        session_data = {"crashes": [], "fuzzed_files": {}}
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        result = correlate_session_coverage(session_file)

        assert result["crashes_with_coverage"] == []

    def test_correlate_session_coverage_with_coverage_file(self, tmp_path):
        """Test with explicit coverage file."""
        session_data = {
            "crashes": [{"crash_id": "c1", "fuzzed_file_id": "f1"}],
            "fuzzed_files": {"f1": {"mutations": [{"mutation_type": "pixel"}]}},
        }
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        coverage_data = {"files": {"test.py": {"covered_lines": [1, 2, 3]}}}
        coverage_file = tmp_path / "coverage.json"
        coverage_file.write_text(json.dumps(coverage_data))

        result = correlate_session_coverage(session_file, coverage_file)

        assert "crashes_with_coverage" in result


class TestCrashAnalysis:
    """Tests for crash analysis functionality."""

    def test_analyze_crash_coverage_returns_correct_structure(self):
        """Test crash analysis returns expected structure."""
        correlator = CoverageCorrelator()
        crashes = [
            {
                "crash_id": "test_crash",
                "fuzzed_file_id": "test_file",
                "crash_type": "segfault",
                "severity": "critical",
            }
        ]
        session = {
            "fuzzed_files": {
                "test_file": {
                    "mutations": [
                        {"mutation_type": "header"},
                        {"mutation_type": "metadata"},
                    ]
                }
            }
        }

        result = correlator.correlate_crashes(crashes, session)
        analysis = result["crashes_with_coverage"][0]

        assert analysis["crash_id"] == "test_crash"
        assert analysis["file_id"] == "test_file"
        assert analysis["mutations_count"] == 2
        assert set(analysis["mutation_types"]) == {"header", "metadata"}
        assert analysis["severity"] == "critical"
        assert analysis["crash_type"] == "segfault"
