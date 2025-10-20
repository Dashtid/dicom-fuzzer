"""Comprehensive tests for dicom_fuzzer.core.crash_triage module.

This test suite provides thorough coverage of crash triaging, severity assessment,
exploitability rating, and priority calculation.
"""

from datetime import datetime

import pytest

from dicom_fuzzer.core.crash_triage import (
    CrashTriage,
    CrashTriageEngine,
    ExploitabilityRating,
    Severity,
    triage_session_crashes,
)
from dicom_fuzzer.core.fuzzing_session import CrashRecord


class TestSeverity:
    """Test suite for Severity enum."""

    def test_all_severities_defined(self):
        """Test all severity levels are defined."""
        assert Severity.CRITICAL
        assert Severity.HIGH
        assert Severity.MEDIUM
        assert Severity.LOW
        assert Severity.INFO

    def test_severity_values(self):
        """Test severity string values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestExploitabilityRating:
    """Test suite for ExploitabilityRating enum."""

    def test_all_ratings_defined(self):
        """Test all exploitability ratings are defined."""
        assert ExploitabilityRating.EXPLOITABLE
        assert ExploitabilityRating.PROBABLY_EXPLOITABLE
        assert ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE
        assert ExploitabilityRating.UNKNOWN

    def test_rating_values(self):
        """Test exploitability rating string values."""
        assert ExploitabilityRating.EXPLOITABLE.value == "exploitable"
        assert (
            ExploitabilityRating.PROBABLY_EXPLOITABLE.value == "probably_exploitable"
        )
        assert (
            ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE.value
            == "probably_not_exploitable"
        )
        assert ExploitabilityRating.UNKNOWN.value == "unknown"


class TestCrashTriage:
    """Test suite for CrashTriage dataclass."""

    def test_initialization_required_fields(self):
        """Test CrashTriage with required fields."""
        triage = CrashTriage(
            crash_id="crash_001",
            severity=Severity.HIGH,
            exploitability=ExploitabilityRating.EXPLOITABLE,
            priority_score=85.0,
        )

        assert triage.crash_id == "crash_001"
        assert triage.severity == Severity.HIGH
        assert triage.exploitability == ExploitabilityRating.EXPLOITABLE
        assert triage.priority_score == 85.0

    def test_initialization_defaults(self):
        """Test CrashTriage default values."""
        triage = CrashTriage(
            crash_id="crash_002",
            severity=Severity.MEDIUM,
            exploitability=ExploitabilityRating.UNKNOWN,
            priority_score=50.0,
        )

        assert triage.indicators == []
        assert triage.recommendations == []
        assert triage.tags == []
        assert triage.summary == ""

    def test_string_representation(self):
        """Test CrashTriage string representation."""
        triage = CrashTriage(
            crash_id="crash_003",
            severity=Severity.CRITICAL,
            exploitability=ExploitabilityRating.EXPLOITABLE,
            priority_score=95.0,
            summary="Buffer overflow in parser",
        )

        result = str(triage)

        assert "CRITICAL" in result
        assert "95.0" in result
        assert "Buffer overflow in parser" in result


class TestCrashTriageEngineInitialization:
    """Test suite for CrashTriageEngine initialization."""

    def test_initialization(self):
        """Test CrashTriageEngine initialization."""
        engine = CrashTriageEngine()

        assert isinstance(engine.triage_cache, dict)
        assert len(engine.triage_cache) == 0

    def test_critical_signals_defined(self):
        """Test critical signals dictionary exists."""
        engine = CrashTriageEngine()

        assert "SIGSEGV" in engine.CRITICAL_SIGNALS
        assert "SIGABRT" in engine.CRITICAL_SIGNALS
        assert "SIGILL" in engine.CRITICAL_SIGNALS

    def test_exploitability_keywords_defined(self):
        """Test exploitability keywords dictionary exists."""
        engine = CrashTriageEngine()

        assert "heap" in engine.EXPLOITABILITY_KEYWORDS
        assert "stack" in engine.EXPLOITABILITY_KEYWORDS
        assert "memory" in engine.EXPLOITABILITY_KEYWORDS


class TestSeverityAssessment:
    """Test suite for severity assessment."""

    def test_assess_severity_critical_sigsegv_write(self):
        """Test SIGSEGV with write access is critical."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="SIGSEGV",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_message="Write access violation at 0x1234",
        )

        severity = engine._assess_severity(crash)

        assert severity == Severity.CRITICAL

    def test_assess_severity_high_sigsegv(self):
        """Test SIGSEGV without write is high."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="SIGSEGV",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test.dcm",
            exception_message="Segmentation fault at 0x1234",
        )

        severity = engine._assess_severity(crash)

        assert severity == Severity.HIGH

    def test_assess_severity_high_heap_corruption(self):
        """Test heap corruption is high severity."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_003",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_003",
            fuzzed_file_path="/test.dcm",
            exception_message="Heap corruption detected",
            stack_trace="malloc error in libheap",
        )

        severity = engine._assess_severity(crash)

        assert severity == Severity.HIGH

    def test_assess_severity_low_benign(self):
        """Test benign patterns are low severity."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_004",
            timestamp=datetime.now(),
            crash_type="error",
            severity="low",
            fuzzed_file_id="file_004",
            fuzzed_file_path="/test.dcm",
            exception_message="Timeout occurred",
        )

        severity = engine._assess_severity(crash)

        assert severity == Severity.LOW


class TestExploitabilityAssessment:
    """Test suite for exploitability assessment."""

    def test_assess_exploitability_exploitable(self):
        """Test strong exploitability indicators."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="critical",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_message="Use-after-free detected",
            stack_trace="Free called twice on same pointer",
        )

        rating = engine._assess_exploitability(crash)

        assert rating == ExploitabilityRating.EXPLOITABLE

    def test_assess_exploitability_probably_exploitable(self):
        """Test probable exploitability indicators."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test.dcm",
            exception_message="Stack smashing detected",
            stack_trace="Stack canary check failed",
        )

        rating = engine._assess_exploitability(crash)

        assert rating == ExploitabilityRating.PROBABLY_EXPLOITABLE

    def test_assess_exploitability_probably_not(self):
        """Test benign patterns are probably not exploitable."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_003",
            timestamp=datetime.now(),
            crash_type="error",
            severity="low",
            fuzzed_file_id="file_003",
            fuzzed_file_path="/test.dcm",
            exception_message="File not found",
        )

        rating = engine._assess_exploitability(crash)

        assert rating == ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE

    def test_assess_exploitability_unknown(self):
        """Test SIGSEGV without clear indicators is unknown."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_004",
            timestamp=datetime.now(),
            crash_type="SIGSEGV",
            severity="high",
            fuzzed_file_id="file_004",
            fuzzed_file_path="/test.dcm",
            exception_message="Segmentation fault",
        )

        rating = engine._assess_exploitability(crash)

        assert rating == ExploitabilityRating.UNKNOWN


class TestIndicatorExtraction:
    """Test suite for indicator extraction."""

    def test_extract_indicators_basic(self):
        """Test basic indicator extraction."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_type="SegmentationFault",
            exception_message="Heap corruption",
        )

        indicators = engine._extract_indicators(crash)

        assert any("crash_type: crash" in ind for ind in indicators)
        assert any("exception: SegmentationFault" in ind for ind in indicators)
        assert any("heap" in ind.lower() for ind in indicators)

    def test_extract_indicators_multiple_categories(self):
        """Test extraction of multiple indicator categories."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="critical",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test.dcm",
            exception_message="Buffer overflow in heap allocation",
            stack_trace="Stack trace shows memory corruption",
        )

        indicators = engine._extract_indicators(crash)

        # Should find both heap and memory indicators
        assert len(indicators) >= 2


class TestTagGeneration:
    """Test suite for tag generation."""

    def test_generate_tags_heap_related(self):
        """Test generation of heap-related tags."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )
        indicators = ["heap: malloc", "crash_type: crash"]

        tags = engine._generate_tags(crash, indicators)

        assert "heap-related" in tags
        assert "crash" in tags

    def test_generate_tags_memory_corruption(self):
        """Test generation of memory corruption tags."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="critical",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test.dcm",
        )
        indicators = ["memory: buffer overflow", "crash_type: crash"]

        tags = engine._generate_tags(crash, indicators)

        assert "memory-corruption" in tags


class TestPriorityCalculation:
    """Test suite for priority calculation."""

    def test_calculate_priority_critical(self):
        """Test priority calculation for critical crashes."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="critical",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )

        score = engine._calculate_priority(
            Severity.CRITICAL, ExploitabilityRating.EXPLOITABLE, crash
        )

        assert score == 100.0  # 90 + 10 = 100

    def test_calculate_priority_high(self):
        """Test priority calculation for high severity."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test.dcm",
        )

        score = engine._calculate_priority(
            Severity.HIGH, ExploitabilityRating.PROBABLY_EXPLOITABLE, crash
        )

        assert score == 75.0  # 70 + 5 = 75

    def test_calculate_priority_with_write_boost(self):
        """Test priority boost for write access violations."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_003",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_003",
            fuzzed_file_path="/test.dcm",
            exception_message="Write access violation",
        )

        score = engine._calculate_priority(
            Severity.HIGH, ExploitabilityRating.UNKNOWN, crash
        )

        assert score == 75.0  # 70 + 0 + 5 = 75

    def test_calculate_priority_clamped(self):
        """Test priority score is clamped to 0-100."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_004",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="low",
            fuzzed_file_id="file_004",
            fuzzed_file_path="/test.dcm",
        )

        score = engine._calculate_priority(
            Severity.LOW, ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE, crash
        )

        # 30 + (-10) = 20, clamped to >= 0
        assert 0.0 <= score <= 100.0


class TestRecommendationGeneration:
    """Test suite for recommendation generation."""

    def test_generate_recommendations_critical(self):
        """Test recommendations for critical crashes."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="critical",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
        )
        indicators = []

        recommendations = engine._generate_recommendations(
            crash, Severity.CRITICAL, ExploitabilityRating.EXPLOITABLE, indicators
        )

        assert any("Investigate immediately" in rec for rec in recommendations)
        assert any("proof-of-concept" in rec for rec in recommendations)

    def test_generate_recommendations_heap(self):
        """Test recommendations for heap-related crashes."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="high",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test.dcm",
        )
        indicators = ["heap: malloc error"]

        recommendations = engine._generate_recommendations(
            crash, Severity.HIGH, ExploitabilityRating.UNKNOWN, indicators
        )

        assert any("AddressSanitizer" in rec for rec in recommendations)


class TestTriageCrash:
    """Test suite for triage_crash method."""

    def test_triage_crash_complete_workflow(self):
        """Test complete crash triaging workflow."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_001",
            timestamp=datetime.now(),
            crash_type="SIGSEGV",
            severity="high",
            fuzzed_file_id="file_001",
            fuzzed_file_path="/test.dcm",
            exception_message="Use-after-free detected",
            stack_trace="Heap corruption",
        )

        triage = engine.triage_crash(crash)

        assert isinstance(triage, CrashTriage)
        assert triage.severity in [Severity.CRITICAL, Severity.HIGH]
        assert triage.exploitability == ExploitabilityRating.EXPLOITABLE
        assert triage.priority_score > 70.0
        assert len(triage.indicators) > 0
        assert len(triage.recommendations) > 0

    def test_triage_crash_caching(self):
        """Test crash triage results are cached."""
        engine = CrashTriageEngine()
        crash = CrashRecord(
            crash_id="crash_002",
            timestamp=datetime.now(),
            crash_type="crash",
            severity="medium",
            fuzzed_file_id="file_002",
            fuzzed_file_path="/test.dcm",
            exception_message="Error occurred",
        )

        # First triage
        triage1 = engine.triage_crash(crash)
        # Second triage should use cache
        triage2 = engine.triage_crash(crash)

        assert triage1 is triage2  # Same object from cache


class TestTriageCrashes:
    """Test suite for triage_crashes method."""

    def test_triage_crashes_multiple(self):
        """Test triaging multiple crashes."""
        engine = CrashTriageEngine()
        crashes = [
            CrashRecord(
                crash_id=f"crash_{i}",
                timestamp=datetime.now(),
                crash_type="crash",
                severity="high",
                fuzzed_file_id=f"file_{i}",
                fuzzed_file_path=f"/test{i}.dcm",
            )
            for i in range(3)
        ]

        triages = engine.triage_crashes(crashes)

        assert len(triages) == 3
        assert all(isinstance(t, CrashTriage) for t in triages)

    def test_triage_crashes_sorted_by_priority(self):
        """Test triages are sorted by priority."""
        engine = CrashTriageEngine()
        crashes = [
            CrashRecord(
                crash_id="crash_low",
                timestamp=datetime.now(),
                crash_type="error",
                severity="low",
                fuzzed_file_id="file_low",
                fuzzed_file_path="/test_low.dcm",
                exception_message="Timeout",
            ),
            CrashRecord(
                crash_id="crash_high",
                timestamp=datetime.now(),
                crash_type="SIGSEGV",
                severity="critical",
                fuzzed_file_id="file_high",
                fuzzed_file_path="/test_high.dcm",
                exception_message="Write access violation",
            ),
        ]

        triages = engine.triage_crashes(crashes)

        # First should be higher priority
        assert triages[0].priority_score >= triages[1].priority_score


class TestTriageSummary:
    """Test suite for get_triage_summary method."""

    def test_get_triage_summary(self):
        """Test triage summary generation."""
        engine = CrashTriageEngine()
        triages = [
            CrashTriage(
                crash_id="crash_1",
                severity=Severity.CRITICAL,
                exploitability=ExploitabilityRating.EXPLOITABLE,
                priority_score=95.0,
            ),
            CrashTriage(
                crash_id="crash_2",
                severity=Severity.HIGH,
                exploitability=ExploitabilityRating.UNKNOWN,
                priority_score=70.0,
            ),
            CrashTriage(
                crash_id="crash_3",
                severity=Severity.LOW,
                exploitability=ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE,
                priority_score=20.0,
            ),
        ]

        summary = engine.get_triage_summary(triages)

        assert summary["total_crashes"] == 3
        assert "by_severity" in summary
        assert "by_exploitability" in summary
        assert summary["high_priority_count"] == 2
        assert summary["average_priority"] == pytest.approx(61.67, 0.1)


class TestTriageSessionCrashes:
    """Test suite for triage_session_crashes function."""

    def test_triage_session_crashes(self):
        """Test triaging session crashes."""
        crashes = [
            CrashRecord(
                crash_id=f"crash_{i}",
                timestamp=datetime.now(),
                crash_type="SIGSEGV" if i % 2 == 0 else "error",
                severity="high" if i % 2 == 0 else "low",
                fuzzed_file_id=f"file_{i}",
                fuzzed_file_path=f"/test{i}.dcm",
                exception_message="Write access" if i == 0 else "Error",
            )
            for i in range(3)
        ]

        result = triage_session_crashes(crashes)

        assert "triages" in result
        assert "summary" in result
        assert "high_priority" in result
        assert "critical_crashes" in result
        assert len(result["triages"]) == 3


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    def test_complete_triage_workflow(self):
        """Test complete crash triaging workflow."""
        # Create diverse set of crashes
        crashes = [
            # Critical exploitable crash
            CrashRecord(
                crash_id="crash_critical",
                timestamp=datetime.now(),
                crash_type="SIGSEGV",
                severity="critical",
                fuzzed_file_id="file_1",
                fuzzed_file_path="/test1.dcm",
                exception_message="Use-after-free in heap",
                stack_trace="Double-free detected",
            ),
            # High severity crash
            CrashRecord(
                crash_id="crash_high",
                timestamp=datetime.now(),
                crash_type="SIGABRT",
                severity="high",
                fuzzed_file_id="file_2",
                fuzzed_file_path="/test2.dcm",
                exception_message="Buffer overflow",
            ),
            # Low severity benign crash
            CrashRecord(
                crash_id="crash_low",
                timestamp=datetime.now(),
                crash_type="error",
                severity="low",
                fuzzed_file_id="file_3",
                fuzzed_file_path="/test3.dcm",
                exception_message="Timeout occurred",
            ),
        ]

        result = triage_session_crashes(crashes)

        # Verify comprehensive results
        assert len(result["triages"]) == 3
        assert len(result["high_priority"]) >= 1
        assert result["summary"]["total_crashes"] == 3

        # Verify highest priority is the critical crash
        assert result["triages"][0].severity in [Severity.CRITICAL, Severity.HIGH]
