"""
Tests for automated crash triaging and prioritization.
"""

import pytest

from dicom_fuzzer.core.crash_triage import (
    CrashTriageEngine,
    ExploitabilityRating,
    Severity,
    triage_session_crashes,
)
from dicom_fuzzer.core.fuzzing_session import CrashRecord


@pytest.fixture
def engine():
    """Create a triage engine instance."""
    return CrashTriageEngine()


@pytest.fixture
def critical_crash():
    """Create a critical (write access violation) crash."""
    from datetime import datetime

    return CrashRecord(
        crash_id="crash_001",
        timestamp=datetime.now(),
        crash_type="SIGSEGV",
        severity="critical",
        fuzzed_file_id="file_001",
        fuzzed_file_path="test.dcm",
        exception_type="SegmentationFault",
        exception_message="Segmentation fault at 0x7fff: write access violation",
        stack_trace=(
            "frame 0: malloc() heap corruption detected\n"
            "frame 1: write_pixel_data() buffer overflow\n"
            "frame 2: process_dicom()"
        ),
    )


@pytest.fixture
def high_crash():
    """Create a high severity (use-after-free) crash."""
    from datetime import datetime

    return CrashRecord(
        crash_id="crash_002",
        timestamp=datetime.now(),
        crash_type="SIGSEGV",
        severity="high",
        fuzzed_file_id="file_002",
        fuzzed_file_path="test2.dcm",
        exception_type="SegmentationFault",
        exception_message="Use-after-free detected in heap allocator",
        stack_trace=(
            "frame 0: free() - invalid pointer\n"
            "frame 1: cleanup_resources()\n"
            "frame 2: main()"
        ),
    )


@pytest.fixture
def medium_crash():
    """Create a medium severity crash."""
    from datetime import datetime

    return CrashRecord(
        crash_id="crash_003",
        timestamp=datetime.now(),
        crash_type="SIGABRT",
        severity="medium",
        fuzzed_file_id="file_003",
        fuzzed_file_path="test3.dcm",
        exception_type="AssertionError",
        exception_message="Assertion failed: ptr != NULL",
        stack_trace="frame 0: assert()\nframe 1: validate_input()",
    )


@pytest.fixture
def low_crash():
    """Create a low severity (benign) crash."""
    from datetime import datetime

    return CrashRecord(
        crash_id="crash_004",
        timestamp=datetime.now(),
        crash_type="ERROR",
        severity="low",
        fuzzed_file_id="file_004",
        fuzzed_file_path="test4.dcm",
        exception_type="IOError",
        exception_message="Permission denied: cannot read file",
        stack_trace="frame 0: open_file()\nframe 1: main()",
    )


class TestCrashTriageEngine:
    """Test crash triaging functionality."""

    def test_triage_critical_crash(self, engine, critical_crash):
        """Test triaging a critical crash."""
        triage = engine.triage_crash(critical_crash)

        assert triage.severity == Severity.CRITICAL
        assert triage.exploitability == ExploitabilityRating.EXPLOITABLE
        assert triage.priority_score >= 90
        assert "write access violation" in triage.summary.lower()
        assert len(triage.indicators) > 0
        assert len(triage.recommendations) > 0
        assert "memory-corruption" in triage.tags or "heap-related" in triage.tags

    def test_triage_high_crash(self, engine, high_crash):
        """Test triaging a high severity crash."""
        triage = engine.triage_crash(high_crash)

        assert triage.severity == Severity.HIGH
        assert triage.exploitability == ExploitabilityRating.EXPLOITABLE
        assert triage.priority_score >= 70
        assert "use-after-free" in triage.summary.lower()
        assert any("heap" in ind.lower() for ind in triage.indicators)

    def test_triage_medium_crash(self, engine, medium_crash):
        """Test triaging a medium severity crash."""
        triage = engine.triage_crash(medium_crash)

        assert triage.severity in [Severity.MEDIUM, Severity.HIGH]
        assert triage.priority_score >= 40
        assert triage.priority_score < 80

    def test_triage_low_crash(self, engine, low_crash):
        """Test triaging a low severity crash."""
        triage = engine.triage_crash(low_crash)

        assert triage.severity == Severity.LOW
        assert triage.exploitability == ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE
        assert triage.priority_score < 50

    def test_triage_multiple_crashes(
        self, engine, critical_crash, high_crash, medium_crash
    ):
        """Test triaging multiple crashes with sorting."""
        crashes = [medium_crash, critical_crash, high_crash]
        triages = engine.triage_crashes(crashes)

        # Should be sorted by priority (highest first)
        assert triages[0].priority_score >= triages[1].priority_score
        assert triages[1].priority_score >= triages[2].priority_score

        # Critical should be first
        assert triages[0].severity == Severity.CRITICAL

    def test_triage_caching(self, engine, critical_crash):
        """Test that triaging results are cached."""
        triage1 = engine.triage_crash(critical_crash)
        triage2 = engine.triage_crash(critical_crash)

        # Should return same object from cache
        assert triage1.crash_id == triage2.crash_id
        assert triage1.priority_score == triage2.priority_score

    def test_get_triage_summary(
        self, engine, critical_crash, high_crash, medium_crash, low_crash
    ):
        """Test triage summary statistics."""
        crashes = [critical_crash, high_crash, medium_crash, low_crash]
        triages = engine.triage_crashes(crashes)
        summary = engine.get_triage_summary(triages)

        assert summary["total_crashes"] == 4
        assert summary["by_severity"]["critical"] >= 1
        assert summary["by_severity"]["high"] >= 1
        assert summary["by_exploitability"]["exploitable"] >= 1
        assert summary["high_priority_count"] >= 2
        assert summary["average_priority"] > 0

    def test_severity_assessment_write_vs_read(self, engine):
        """Test that write access violations are rated higher than read."""
        from datetime import datetime

        write_crash = CrashRecord(
            crash_id="write123",
            timestamp=datetime.now(),
            crash_type="SIGSEGV",
            severity="high",
            fuzzed_file_id="file_write",
            fuzzed_file_path="test.dcm",
            exception_type="SegmentationFault",
            exception_message="write access violation at 0x1234",
            stack_trace="",
        )

        read_crash = CrashRecord(
            crash_id="read123",
            timestamp=datetime.now(),
            crash_type="SIGSEGV",
            severity="high",
            fuzzed_file_id="file_read",
            fuzzed_file_path="test.dcm",
            exception_type="SegmentationFault",
            exception_message="read access violation at 0x1234",
            stack_trace="",
        )

        write_triage = engine.triage_crash(write_crash)
        read_triage = engine.triage_crash(read_crash)

        assert write_triage.priority_score > read_triage.priority_score

    def test_exploitability_keywords(self, engine):
        """Test detection of exploitability keywords."""
        from datetime import datetime

        keywords = [
            ("heap corruption", ExploitabilityRating.EXPLOITABLE),
            ("buffer overflow", ExploitabilityRating.EXPLOITABLE),
            ("double-free", ExploitabilityRating.EXPLOITABLE),
            ("stack smash", ExploitabilityRating.PROBABLY_EXPLOITABLE),
            ("timeout", ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE),
        ]

        for keyword, expected_rating in keywords:
            crash = CrashRecord(
                crash_id=f"{keyword}_hash",
                timestamp=datetime.now(),
                crash_type="SIGSEGV",
                severity="medium",
                fuzzed_file_id=f"file_{keyword}",
                fuzzed_file_path="test.dcm",
                exception_type="Error",
                exception_message=keyword,
                stack_trace="",
            )

            triage = engine.triage_crash(crash)
            assert triage.exploitability == expected_rating

    def test_indicator_extraction(self, engine):
        """Test extraction of crash indicators."""
        from datetime import datetime

        crash = CrashRecord(
            crash_id="indicator_test",
            timestamp=datetime.now(),
            crash_type="SIGSEGV",
            severity="high",
            fuzzed_file_id="file_indicator",
            fuzzed_file_path="test.dcm",
            exception_type="SegmentationFault",
            exception_message="heap buffer overflow in malloc",
            stack_trace="corrupted return address detected",
        )

        triage = engine.triage_crash(crash)

        # Should detect heap and control flow indicators
        indicators_text = " ".join(triage.indicators).lower()
        assert "heap" in indicators_text
        assert "control" in indicators_text or "return address" in indicators_text

    def test_tag_generation(self, engine):
        """Test automatic tag generation."""
        from datetime import datetime

        crash = CrashRecord(
            crash_id="tag_test",
            timestamp=datetime.now(),
            crash_type="SIGSEGV",
            severity="high",
            fuzzed_file_id="file_tag",
            fuzzed_file_path="test.dcm",
            exception_type="SegmentationFault",
            exception_message="heap corruption detected",
            stack_trace="stack buffer overflow",
        )

        triage = engine.triage_crash(crash)

        # Should have multiple relevant tags
        assert "heap-related" in triage.tags or "memory-corruption" in triage.tags
        assert "SIGSEGV" in triage.tags

    def test_recommendation_generation(self, engine, critical_crash):
        """Test that recommendations are generated."""
        triage = engine.triage_crash(critical_crash)

        assert len(triage.recommendations) > 0
        # High severity crashes should get immediate investigation recommendation
        assert any("immediately" in rec.lower() for rec in triage.recommendations)

    def test_priority_score_bounds(self, engine, critical_crash, low_crash):
        """Test that priority scores are within valid range."""
        critical_triage = engine.triage_crash(critical_crash)
        low_triage = engine.triage_crash(low_crash)

        # Scores should be 0-100
        assert 0 <= critical_triage.priority_score <= 100
        assert 0 <= low_triage.priority_score <= 100

        # Critical should be higher than low
        assert critical_triage.priority_score > low_triage.priority_score


class TestTriageSessionFunction:
    """Test the triage_session_crashes convenience function."""

    def test_triage_session_crashes(self, critical_crash, high_crash, medium_crash):
        """Test triaging session crashes."""
        crashes = [critical_crash, high_crash, medium_crash]
        result = triage_session_crashes(crashes)

        assert "triages" in result
        assert "summary" in result
        assert "high_priority" in result
        assert "critical_crashes" in result

        assert len(result["triages"]) == 3
        assert len(result["high_priority"]) >= 2  # At least critical and high
        assert len(result["critical_crashes"]) == 1  # One critical crash

    def test_triage_empty_list(self):
        """Test triaging empty crash list."""
        result = triage_session_crashes([])

        assert result["summary"]["total_crashes"] == 0
        assert len(result["triages"]) == 0
        assert len(result["high_priority"]) == 0


class TestCrashTriageStringRepresentation:
    """Test string representations for logging and reporting."""

    def test_triage_str(self, engine, critical_crash):
        """Test CrashTriage __str__ method."""
        triage = engine.triage_crash(critical_crash)
        triage_str = str(triage)

        assert "[CRITICAL]" in triage_str
        assert "Priority:" in triage_str
        assert triage.summary in triage_str

    def test_triage_contains_useful_info(self, engine, high_crash):
        """Test that string representation contains actionable information."""
        triage = engine.triage_crash(high_crash)
        triage_str = str(triage)

        # Should contain severity, priority, and description
        assert len(triage_str) > 20
        assert triage.severity.value.upper() in triage_str
