"""
Tests for Coverage Correlation

Tests linking crashes to code coverage for guided fuzzing.
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from core.coverage_correlation import CoverageCorrelator


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
