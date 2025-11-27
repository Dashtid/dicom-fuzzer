"""Automated Crash Triaging and Prioritization

This module provides intelligent crash analysis and prioritization based on
severity, exploitability indicators, and crash characteristics. It helps
security researchers focus on the most critical bugs first.

CONCEPT: Not all crashes are equally important. Some indicate potentially
exploitable vulnerabilities (use-after-free, buffer overflows) while others
may be simple assertion failures or benign crashes.

Based on 2025 best practices for automated crash triaging systems.
"""

from dataclasses import dataclass, field
from enum import Enum

from dicom_fuzzer.core.fuzzing_session import CrashRecord
from dicom_fuzzer.utils.hashing import md5_hash
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class Severity(Enum):
    """Crash severity levels."""

    CRITICAL = "critical"  # Likely exploitable
    HIGH = "high"  # Potentially exploitable
    MEDIUM = "medium"  # Stability issue
    LOW = "low"  # Minor issue or expected behavior
    INFO = "info"  # Informational only


class ExploitabilityRating(Enum):
    """Exploitability assessment."""

    EXPLOITABLE = "exploitable"  # Strong indicators of exploitability
    PROBABLY_EXPLOITABLE = "probably_exploitable"  # Likely exploitable
    PROBABLY_NOT_EXPLOITABLE = "probably_not_exploitable"  # Unlikely exploitable
    UNKNOWN = "unknown"  # Insufficient information


@dataclass
class CrashTriage:
    """Triage analysis result for a crash.

    Contains severity assessment, exploitability rating, and detailed
    analysis of crash characteristics.
    """

    crash_id: str
    severity: Severity
    exploitability: ExploitabilityRating
    priority_score: float  # 0.0-100.0, higher = more important
    indicators: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    summary: str = ""

    def __str__(self) -> str:
        """String representation for reports."""
        return (
            f"[{self.severity.value.upper()}] "
            f"Priority: {self.priority_score:.1f}/100 - "
            f"{self.summary}"
        )


class CrashTriageEngine:
    """Automated crash triaging and prioritization engine.

    Analyzes crashes to determine severity, exploitability, and priority
    for investigation based on multiple indicators.
    """

    # Signal/exception patterns indicating high severity
    CRITICAL_SIGNALS = {
        "SIGSEGV": "Segmentation fault (memory access violation)",
        "SIGABRT": "Abort signal (assertion failure or corruption)",
        "SIGILL": "Illegal instruction",
        "SIGFPE": "Floating point exception",
        "SIGBUS": "Bus error (unaligned memory access)",
    }

    # Exploitability indicators (keywords in stack traces/messages)
    EXPLOITABILITY_KEYWORDS = {
        "heap": ["heap", "malloc", "free", "use-after-free", "double-free"],
        "stack": ["stack", "buffer overflow", "stack smash", "canary"],
        "memory": [
            "out-of-bounds",
            "buffer overflow",
            "write access violation",
            "heap corruption",
        ],
        "control_flow": ["return address", "function pointer", "vtable", "rip", "eip"],
        "type_confusion": ["type confusion", "vtable", "polymorphic"],
    }

    # Low-severity patterns (benign crashes)
    BENIGN_PATTERNS = [
        "timeout",
        "resource exhausted",
        "disk full",
        "permission denied",
        "file not found",
    ]

    def __init__(self):
        """Initialize triage engine."""
        self.triage_cache: dict[str, CrashTriage] = {}

    def triage_crash(self, crash: CrashRecord) -> CrashTriage:
        """Perform automated triage analysis on a crash.

        Args:
            crash: Crash record to analyze

        Returns:
            Triage analysis result

        """
        # Check cache
        crash_id = self._generate_crash_id(crash)
        if crash_id in self.triage_cache:
            return self.triage_cache[crash_id]

        # Analyze crash characteristics
        severity = self._assess_severity(crash)
        exploitability = self._assess_exploitability(crash)
        indicators = self._extract_indicators(crash)
        tags = self._generate_tags(crash, indicators)

        # Calculate priority score (weighted combination)
        priority_score = self._calculate_priority(severity, exploitability, crash)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            crash, severity, exploitability, indicators
        )

        # Create summary
        summary = self._generate_summary(crash, severity, exploitability)

        triage = CrashTriage(
            crash_id=crash_id,
            severity=severity,
            exploitability=exploitability,
            priority_score=priority_score,
            indicators=indicators,
            recommendations=recommendations,
            tags=tags,
            summary=summary,
        )

        # Cache result
        self.triage_cache[crash_id] = triage

        return triage

    def triage_crashes(self, crashes: list[CrashRecord]) -> list[CrashTriage]:
        """Triage multiple crashes and sort by priority.

        Args:
            crashes: List of crash records

        Returns:
            List of triage results, sorted by priority (highest first)

        """
        triages = [self.triage_crash(crash) for crash in crashes]
        return sorted(triages, key=lambda t: t.priority_score, reverse=True)

    def get_triage_summary(self, triages: list[CrashTriage]) -> dict:
        """Get summary statistics for triage results.

        Args:
            triages: List of triage results

        Returns:
            Dictionary with summary statistics

        """
        severity_counts = dict.fromkeys(Severity, 0)
        exploitability_counts = dict.fromkeys(ExploitabilityRating, 0)

        for triage in triages:
            severity_counts[triage.severity] += 1
            exploitability_counts[triage.exploitability] += 1

        return {
            "total_crashes": len(triages),
            "by_severity": {s.value: count for s, count in severity_counts.items()},
            "by_exploitability": {
                e.value: count for e, count in exploitability_counts.items()
            },
            "high_priority_count": sum(1 for t in triages if t.priority_score >= 70),
            "average_priority": (
                sum(t.priority_score for t in triages) / len(triages)
                if triages
                else 0.0
            ),
        }

    def _assess_severity(self, crash: CrashRecord) -> Severity:
        """Assess crash severity based on crash type and characteristics.

        Args:
            crash: Crash record

        Returns:
            Severity level

        """
        crash_type = crash.crash_type.upper()
        exception_msg = (crash.exception_message or "").lower()
        stack_trace = (crash.stack_trace or "").lower()

        # Check for critical signals
        for signal, _ in self.CRITICAL_SIGNALS.items():
            if signal in crash_type or signal in exception_msg:
                # SIGSEGV with write access = critical
                if signal == "SIGSEGV" and "write" in exception_msg:
                    return Severity.CRITICAL
                # Other critical signals = high
                return Severity.HIGH

        # Check for exploitability keywords
        combined_text = f"{exception_msg} {stack_trace}"
        for category, keywords in self.EXPLOITABILITY_KEYWORDS.items():
            if any(kw in combined_text for kw in keywords):
                if category in ["heap", "memory", "control_flow"]:
                    return Severity.HIGH
                return Severity.MEDIUM

        # Check for benign patterns
        if any(pattern in exception_msg for pattern in self.BENIGN_PATTERNS):
            return Severity.LOW

        # Default to medium for unknown crashes
        return Severity.MEDIUM

    def _assess_exploitability(self, crash: CrashRecord) -> ExploitabilityRating:
        """Assess potential exploitability of crash.

        Args:
            crash: Crash record

        Returns:
            Exploitability rating

        """
        crash_type = crash.crash_type.upper()
        exception_msg = (crash.exception_message or "").lower()
        stack_trace = (crash.stack_trace or "").lower()
        combined_text = f"{exception_msg} {stack_trace}"

        # Strong exploitability indicators
        strong_indicators = [
            "use-after-free",
            "double-free",
            "heap corruption",
            "write access violation",
            "buffer overflow",
            "control flow",
            "return address",
        ]
        if any(indicator in combined_text for indicator in strong_indicators):
            return ExploitabilityRating.EXPLOITABLE

        # Probable exploitability
        probable_indicators = [
            "heap",
            "stack smash",
            "out-of-bounds write",
            "function pointer",
            "vtable",
        ]
        if any(indicator in combined_text for indicator in probable_indicators):
            return ExploitabilityRating.PROBABLY_EXPLOITABLE

        # Benign crashes
        if any(pattern in exception_msg for pattern in self.BENIGN_PATTERNS):
            return ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE

        # SIGSEGV without clear exploitability = unknown
        if "SIGSEGV" in crash_type:
            return ExploitabilityRating.UNKNOWN

        return ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE

    def _extract_indicators(self, crash: CrashRecord) -> list[str]:
        """Extract key indicators from crash data.

        Args:
            crash: Crash record

        Returns:
            List of indicator strings

        """
        indicators = []
        combined_text = f"{crash.exception_message or ''} {crash.stack_trace or ''}"

        # Check for each category
        for category, keywords in self.EXPLOITABILITY_KEYWORDS.items():
            found = [kw for kw in keywords if kw in combined_text.lower()]
            if found:
                indicators.append(f"{category}: {', '.join(found)}")

        # Add crash type
        indicators.insert(0, f"crash_type: {crash.crash_type}")

        # Add exception type if present
        if crash.exception_type:
            indicators.append(f"exception: {crash.exception_type}")

        return indicators

    def _generate_tags(self, crash: CrashRecord, indicators: list[str]) -> list[str]:
        """Generate tags for categorizing crashes.

        Args:
            crash: Crash record
            indicators: Extracted indicators

        Returns:
            List of tags

        """
        tags = []

        # Add crash type
        tags.append(crash.crash_type)

        # Add exploitability category tags
        combined = " ".join(indicators).lower()
        if "heap" in combined:
            tags.append("heap-related")
        if "stack" in combined:
            tags.append("stack-related")
        if "memory" in combined or "buffer" in combined:
            tags.append("memory-corruption")
        if "control" in combined or "pointer" in combined:
            tags.append("control-flow")
        if "use-after-free" in combined or "double-free" in combined:
            tags.append("use-after-free")

        return list(set(tags))  # Remove duplicates

    def _calculate_priority(
        self,
        severity: Severity,
        exploitability: ExploitabilityRating,
        crash: CrashRecord,
    ) -> float:
        """Calculate priority score for crash.

        Args:
            severity: Assessed severity
            exploitability: Exploitability rating
            crash: Crash record

        Returns:
            Priority score (0.0-100.0)

        """
        # Base score from severity
        severity_scores = {
            Severity.CRITICAL: 90,
            Severity.HIGH: 70,
            Severity.MEDIUM: 50,
            Severity.LOW: 30,
            Severity.INFO: 10,
        }
        score = severity_scores[severity]

        # Adjust for exploitability
        exploit_adjustments = {
            ExploitabilityRating.EXPLOITABLE: 10,
            ExploitabilityRating.PROBABLY_EXPLOITABLE: 5,
            ExploitabilityRating.UNKNOWN: 0,
            ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE: -10,
        }
        score += exploit_adjustments[exploitability]

        # Boost for write access violations (more dangerous than read)
        if crash.exception_message and "write" in crash.exception_message.lower():
            score += 5

        # Clamp to 0-100
        return max(0.0, min(100.0, float(score)))

    def _generate_recommendations(
        self,
        crash: CrashRecord,
        severity: Severity,
        exploitability: ExploitabilityRating,
        indicators: list[str],
    ) -> list[str]:
        """Generate actionable recommendations for investigating crash.

        Args:
            crash: Crash record
            severity: Assessed severity
            exploitability: Exploitability rating
            indicators: Extracted indicators

        Returns:
            List of recommendation strings

        """
        recommendations = []

        # High priority crashes
        if severity in [Severity.CRITICAL, Severity.HIGH]:
            recommendations.append(
                "Investigate immediately - potential security vulnerability"
            )
            recommendations.append("Attempt to minimize test case for easier analysis")
            recommendations.append("Verify crash is reproducible")

        # Exploitability-specific recommendations
        if exploitability == ExploitabilityRating.EXPLOITABLE:
            recommendations.append("Attempt to develop proof-of-concept exploit")
            recommendations.append("Assess impact and scope of vulnerability")

        # Heap-related crashes
        if any("heap" in ind.lower() for ind in indicators):
            recommendations.append("Run with AddressSanitizer (ASAN) for detailed info")
            recommendations.append("Check for memory leaks or corruption patterns")

        # Stack-related crashes
        if any("stack" in ind.lower() for ind in indicators):
            recommendations.append(
                "Analyze stack layout and potential for buffer overflow"
            )
            recommendations.append("Check for stack canary bypass techniques")

        # General recommendations
        recommendations.append("Document findings in bug tracking system")
        recommendations.append("Compare with known CVEs for similar patterns")

        return recommendations

    def _generate_summary(
        self,
        crash: CrashRecord,
        severity: Severity,
        exploitability: ExploitabilityRating,
    ) -> str:
        """Generate concise summary of crash.

        Args:
            crash: Crash record
            severity: Assessed severity
            exploitability: Exploitability rating

        Returns:
            Summary string

        """
        parts = [
            crash.crash_type,
            f"({severity.value}",
            f"{exploitability.value})",
        ]

        # Add key detail from exception message
        if crash.exception_message:
            # Extract first meaningful phrase
            msg = crash.exception_message[:80].split("\n")[0]
            parts.append(f"- {msg}")

        return " ".join(parts)

    def _generate_crash_id(self, crash: CrashRecord) -> str:
        """Generate unique ID for crash (for caching).

        Args:
            crash: Crash record

        Returns:
            Crash ID string

        """
        # Use crash characteristics to generate ID
        id_parts = [
            crash.crash_type,
            crash.exception_type or "",
            crash.exception_message[:200] if crash.exception_message else "",
            crash.stack_trace[:500] if crash.stack_trace else "",
        ]
        id_str = "|".join(id_parts)
        return md5_hash(id_str)


def triage_session_crashes(crashes: list[CrashRecord]) -> dict:
    """Triage all crashes from a fuzzing session.

    Args:
        crashes: List of crash records from session

    Returns:
        Dictionary with triage results and statistics

    """
    engine = CrashTriageEngine()
    triages = engine.triage_crashes(crashes)
    summary = engine.get_triage_summary(triages)

    return {
        "triages": triages,
        "summary": summary,
        "high_priority": [t for t in triages if t.priority_score >= 70],
        "critical_crashes": [t for t in triages if t.severity == Severity.CRITICAL],
    }
