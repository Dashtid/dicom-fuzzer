"""Semantic crash bucketing for intelligent crash classification.

Provides:
- Crash context classification (data loss, privacy, availability, integrity)
- Impact assessment and severity inference
- Mutation strategy attribution
- Confidence scoring for deduplication decisions
- Root cause category detection

References:
- Semantic Crash Bucketing (ASE 2018)
- FuzzerAid: Fault Signature-Based Grouping
- CASR severity estimation

"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from dicom_fuzzer.core.constants import SEVERITY_SCORES, Severity
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class ImpactCategory(Enum):
    """Categories of crash impact."""

    DATA_LOSS = auto()  # Potential data corruption/loss
    PRIVACY = auto()  # Information disclosure risk
    AVAILABILITY = auto()  # Service denial/crash
    INTEGRITY = auto()  # Data integrity violation
    AUTHENTICATION = auto()  # Auth bypass potential
    AUTHORIZATION = auto()  # Access control issue
    UNKNOWN = auto()  # Unclassified impact


class RootCauseCategory(Enum):
    """Categories of root causes."""

    BUFFER_OVERFLOW = auto()
    INTEGER_OVERFLOW = auto()
    NULL_DEREFERENCE = auto()
    USE_AFTER_FREE = auto()
    DOUBLE_FREE = auto()
    TYPE_CONFUSION = auto()
    FORMAT_STRING = auto()
    COMMAND_INJECTION = auto()
    PATH_TRAVERSAL = auto()
    RESOURCE_EXHAUSTION = auto()
    ASSERTION_FAILURE = auto()
    UNHANDLED_EXCEPTION = auto()
    LOGIC_ERROR = auto()
    PARSING_ERROR = auto()
    PROTOCOL_VIOLATION = auto()
    UNKNOWN = auto()


@dataclass
class CrashContext:
    """Context information about a crash.

    Attributes:
        crash_type: Type of crash (signal, exception)
        error_message: Error/exception message
        stack_trace: Stack trace string
        mutation_strategy: Strategy that caused crash
        input_characteristics: Features of the input
        execution_phase: Where in execution crash occurred
        memory_state: Memory-related indicators

    """

    crash_type: str | None = None
    error_message: str | None = None
    stack_trace: str | None = None
    mutation_strategy: str | None = None
    input_characteristics: dict[str, Any] = field(default_factory=dict)
    execution_phase: str | None = None
    memory_state: dict[str, Any] = field(default_factory=dict)


@dataclass
class SemanticBucket:
    """A semantic bucket of similar crashes.

    Attributes:
        bucket_id: Unique bucket identifier
        impact_category: Primary impact category
        root_cause: Detected root cause category
        severity: Assessed severity level
        confidence: Confidence in classification (0-1)
        crash_ids: List of crash IDs in this bucket
        characteristics: Common characteristics
        mutation_strategies: Strategies that triggered these crashes

    """

    bucket_id: str
    impact_category: ImpactCategory = ImpactCategory.UNKNOWN
    root_cause: RootCauseCategory = RootCauseCategory.UNKNOWN
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    crash_ids: list[str] = field(default_factory=list)
    characteristics: dict[str, Any] = field(default_factory=dict)
    mutation_strategies: dict[str, int] = field(default_factory=dict)

    def add_crash(self, crash_id: str, strategy: str | None = None) -> None:
        """Add a crash to this bucket."""
        self.crash_ids.append(crash_id)
        if strategy:
            self.mutation_strategies[strategy] = (
                self.mutation_strategies.get(strategy, 0) + 1
            )


@dataclass
class BucketerConfig:
    """Configuration for semantic bucketer.

    Attributes:
        enable_impact_analysis: Enable impact categorization
        enable_root_cause_detection: Enable root cause detection
        enable_severity_inference: Enable severity inference
        min_confidence_threshold: Minimum confidence for classification
        max_buckets: Maximum number of buckets

    """

    enable_impact_analysis: bool = True
    enable_root_cause_detection: bool = True
    enable_severity_inference: bool = True
    min_confidence_threshold: float = 0.3
    max_buckets: int = 1000


class SemanticBucketer:
    """Semantic crash bucketing engine.

    Classifies crashes by:
    - Impact category (data loss, privacy, availability, etc.)
    - Root cause (buffer overflow, null deref, etc.)
    - Severity level
    - Mutation strategy attribution
    """

    # Patterns for root cause detection
    ROOT_CAUSE_PATTERNS: dict[RootCauseCategory, list[str]] = {
        RootCauseCategory.BUFFER_OVERFLOW: [
            r"buffer overflow",
            r"heap-buffer-overflow",
            r"stack-buffer-overflow",
            r"global-buffer-overflow",
            r"out.of.bounds",
            r"array index out of",
        ],
        RootCauseCategory.INTEGER_OVERFLOW: [
            r"integer overflow",
            r"signed integer overflow",
            r"negation overflow",
            r"shift exponent",
        ],
        RootCauseCategory.NULL_DEREFERENCE: [
            r"null pointer",
            r"null dereference",
            r"SEGV on unknown address.*0x0+",
            r"NoneType",
            r"AttributeError.*None",
        ],
        RootCauseCategory.USE_AFTER_FREE: [
            r"use.after.free",
            r"heap-use-after-free",
            r"freed memory",
        ],
        RootCauseCategory.DOUBLE_FREE: [
            r"double.free",
            r"attempting free on address",
        ],
        RootCauseCategory.TYPE_CONFUSION: [
            r"type confusion",
            r"bad cast",
            r"TypeError",
            r"type mismatch",
        ],
        RootCauseCategory.FORMAT_STRING: [
            r"format string",
            r"%n",
            r"%s.*crash",
        ],
        RootCauseCategory.RESOURCE_EXHAUSTION: [
            r"out of memory",
            r"MemoryError",
            r"stack overflow",
            r"recursion",
            r"too many open files",
            r"resource exhausted",
        ],
        RootCauseCategory.ASSERTION_FAILURE: [
            r"assert",
            r"AssertionError",
            r"SIGABRT",
            r"abort",
        ],
        RootCauseCategory.PARSING_ERROR: [
            r"parse error",
            r"syntax error",
            r"malformed",
            r"invalid format",
            r"unexpected token",
            r"decode error",
        ],
        RootCauseCategory.PROTOCOL_VIOLATION: [
            r"protocol error",
            r"invalid sequence",
            r"unexpected tag",
            r"invalid VR",
            r"transfer syntax",
        ],
    }

    # Patterns for impact detection
    IMPACT_PATTERNS: dict[ImpactCategory, list[str]] = {
        ImpactCategory.DATA_LOSS: [
            r"write.*fail",
            r"corrupt",
            r"truncat",
            r"data loss",
            r"inconsistent state",
        ],
        ImpactCategory.PRIVACY: [
            r"leak",
            r"disclosure",
            r"uninitialized",
            r"info.leak",
            r"memory disclosure",
        ],
        ImpactCategory.AVAILABILITY: [
            r"crash",
            r"denial",
            r"hang",
            r"timeout",
            r"unresponsive",
            r"SIGSEGV",
            r"SIGABRT",
        ],
        ImpactCategory.INTEGRITY: [
            r"integrity",
            r"checksum",
            r"signature",
            r"tamper",
            r"modify",
        ],
        ImpactCategory.AUTHENTICATION: [
            r"auth.*bypass",
            r"credential",
            r"login.*fail",
            r"password",
        ],
        ImpactCategory.AUTHORIZATION: [
            r"access.*denied",
            r"permission",
            r"unauthorized",
            r"privilege",
        ],
    }

    # Severity indicators
    SEVERITY_KEYWORDS: dict[Severity, list[str]] = {
        Severity.CRITICAL: [
            r"remote.code",
            r"arbitrary.code",
            r"shell",
            r"exec",
            r"command.injection",
            r"control.flow",
        ],
        Severity.HIGH: [
            r"heap",
            r"stack",
            r"overflow",
            r"use.after.free",
            r"write.*arbitrary",
            r"memory.corruption",
        ],
        Severity.MEDIUM: [
            r"crash",
            r"denial",
            r"SIGSEGV",
            r"SIGABRT",
            r"null.pointer",
            r"assertion",
        ],
        Severity.LOW: [
            r"timeout",
            r"resource",
            r"performance",
            r"warning",
        ],
    }

    def __init__(self, config: BucketerConfig | None = None):
        """Initialize semantic bucketer.

        Args:
            config: Configuration settings

        """
        self.config = config or BucketerConfig()
        self.buckets: dict[str, SemanticBucket] = {}
        self._crash_to_bucket: dict[str, str] = {}
        self._next_bucket_id = 0

        # Compile patterns
        self._root_cause_re = {
            cat: [re.compile(p, re.IGNORECASE) for p in patterns]
            for cat, patterns in self.ROOT_CAUSE_PATTERNS.items()
        }
        self._impact_re = {
            cat: [re.compile(p, re.IGNORECASE) for p in patterns]
            for cat, patterns in self.IMPACT_PATTERNS.items()
        }
        self._severity_re = {
            sev: [re.compile(p, re.IGNORECASE) for p in patterns]
            for sev, patterns in self.SEVERITY_KEYWORDS.items()
        }

    def classify_crash(
        self, crash_id: str, context: CrashContext
    ) -> tuple[SemanticBucket, float]:
        """Classify a crash and assign to bucket.

        Args:
            crash_id: Unique crash identifier
            context: Crash context information

        Returns:
            Tuple of (bucket, confidence)

        """
        # Detect root cause
        root_cause, rc_confidence = self._detect_root_cause(context)

        # Detect impact
        impact, impact_confidence = self._detect_impact(context)

        # Infer severity
        severity, sev_confidence = self._infer_severity(context, root_cause, impact)

        # Calculate overall confidence
        confidence = (rc_confidence + impact_confidence + sev_confidence) / 3

        # Find or create bucket
        bucket_key = f"{root_cause.name}_{impact.name}_{severity.name}"
        bucket = self._find_or_create_bucket(
            bucket_key, root_cause, impact, severity, confidence
        )

        # Add crash to bucket
        bucket.add_crash(crash_id, context.mutation_strategy)
        self._crash_to_bucket[crash_id] = bucket.bucket_id

        # Update bucket characteristics
        self._update_characteristics(bucket, context)

        return bucket, confidence

    def _detect_root_cause(
        self, context: CrashContext
    ) -> tuple[RootCauseCategory, float]:
        """Detect root cause category from context."""
        if not self.config.enable_root_cause_detection:
            return RootCauseCategory.UNKNOWN, 0.5

        # Combine all text sources
        text = " ".join(
            filter(
                None,
                [
                    context.crash_type,
                    context.error_message,
                    context.stack_trace,
                ],
            )
        )

        if not text:
            return RootCauseCategory.UNKNOWN, 0.0

        # Check each category
        matches: dict[RootCauseCategory, int] = defaultdict(int)

        for category, patterns in self._root_cause_re.items():
            for pattern in patterns:
                if pattern.search(text):
                    matches[category] += 1

        if not matches:
            return RootCauseCategory.UNKNOWN, 0.3

        # Return category with most matches
        best_category = max(matches.items(), key=lambda x: x[1])
        confidence = min(1.0, best_category[1] * 0.25 + 0.5)

        return best_category[0], confidence

    def _detect_impact(self, context: CrashContext) -> tuple[ImpactCategory, float]:
        """Detect impact category from context."""
        if not self.config.enable_impact_analysis:
            return ImpactCategory.UNKNOWN, 0.5

        text = " ".join(
            filter(
                None,
                [
                    context.crash_type,
                    context.error_message,
                    context.stack_trace,
                ],
            )
        )

        if not text:
            return ImpactCategory.AVAILABILITY, 0.5  # Default for crashes

        matches: dict[ImpactCategory, int] = defaultdict(int)

        for category, patterns in self._impact_re.items():
            for pattern in patterns:
                if pattern.search(text):
                    matches[category] += 1

        if not matches:
            # Default to availability for unclassified crashes
            return ImpactCategory.AVAILABILITY, 0.4

        best_category = max(matches.items(), key=lambda x: x[1])
        confidence = min(1.0, best_category[1] * 0.2 + 0.5)

        return best_category[0], confidence

    def _infer_severity(
        self,
        context: CrashContext,
        root_cause: RootCauseCategory,
        impact: ImpactCategory,
    ) -> tuple[Severity, float]:
        """Infer severity from context and classifications."""
        if not self.config.enable_severity_inference:
            return Severity.MEDIUM, 0.5

        text = " ".join(
            filter(
                None,
                [
                    context.crash_type,
                    context.error_message,
                    context.stack_trace,
                ],
            )
        )

        # Check keyword patterns
        matches: dict[Severity, int] = defaultdict(int)

        for severity, patterns in self._severity_re.items():
            for pattern in patterns:
                if pattern.search(text):
                    matches[severity] += 1

        # Adjust based on root cause
        if root_cause in (
            RootCauseCategory.BUFFER_OVERFLOW,
            RootCauseCategory.USE_AFTER_FREE,
            RootCauseCategory.DOUBLE_FREE,
        ):
            matches[Severity.HIGH] += 2

        if root_cause in (
            RootCauseCategory.COMMAND_INJECTION,
            RootCauseCategory.FORMAT_STRING,
        ):
            matches[Severity.CRITICAL] += 2

        if root_cause in (
            RootCauseCategory.ASSERTION_FAILURE,
            RootCauseCategory.RESOURCE_EXHAUSTION,
        ):
            matches[Severity.MEDIUM] += 1

        # Adjust based on impact
        if impact == ImpactCategory.PRIVACY:
            matches[Severity.HIGH] += 1
        elif impact == ImpactCategory.AUTHENTICATION:
            matches[Severity.CRITICAL] += 1

        if not matches:
            return Severity.MEDIUM, 0.4

        best_severity = max(matches.items(), key=lambda x: x[1])
        confidence = min(1.0, best_severity[1] * 0.15 + 0.5)

        return best_severity[0], confidence

    def _find_or_create_bucket(
        self,
        key: str,
        root_cause: RootCauseCategory,
        impact: ImpactCategory,
        severity: Severity,
        confidence: float,
    ) -> SemanticBucket:
        """Find existing bucket or create new one."""
        # Try to find matching bucket
        for bucket in self.buckets.values():
            if (
                bucket.root_cause == root_cause
                and bucket.impact_category == impact
                and bucket.severity == severity
            ):
                # Update confidence as average
                bucket.confidence = (bucket.confidence + confidence) / 2
                return bucket

        # Create new bucket
        if len(self.buckets) >= self.config.max_buckets:
            # Return generic bucket if at limit
            generic_key = "OVERFLOW_BUCKET"
            if generic_key not in self.buckets:
                self.buckets[generic_key] = SemanticBucket(
                    bucket_id=generic_key,
                    impact_category=ImpactCategory.UNKNOWN,
                    root_cause=RootCauseCategory.UNKNOWN,
                    severity=Severity.MEDIUM,
                    confidence=0.3,
                )
            return self.buckets[generic_key]

        bucket_id = f"bucket_{self._next_bucket_id}"
        self._next_bucket_id += 1

        bucket = SemanticBucket(
            bucket_id=bucket_id,
            impact_category=impact,
            root_cause=root_cause,
            severity=severity,
            confidence=confidence,
        )

        self.buckets[bucket_id] = bucket
        return bucket

    def _update_characteristics(
        self, bucket: SemanticBucket, context: CrashContext
    ) -> None:
        """Update bucket characteristics based on new crash."""
        # Track execution phase distribution
        if context.execution_phase:
            phases = bucket.characteristics.setdefault("execution_phases", {})
            phases[context.execution_phase] = phases.get(context.execution_phase, 0) + 1

        # Track crash type distribution
        if context.crash_type:
            types = bucket.characteristics.setdefault("crash_types", {})
            types[context.crash_type] = types.get(context.crash_type, 0) + 1

        # Track input characteristics
        for key, value in context.input_characteristics.items():
            char_key = f"input_{key}"
            if isinstance(value, (int, float)):
                # Track numeric ranges
                existing = bucket.characteristics.get(char_key, {})
                existing["min"] = min(existing.get("min", value), value)
                existing["max"] = max(existing.get("max", value), value)
                bucket.characteristics[char_key] = existing

    def get_bucket_for_crash(self, crash_id: str) -> SemanticBucket | None:
        """Get the bucket containing a crash.

        Args:
            crash_id: Crash identifier

        Returns:
            SemanticBucket or None

        """
        bucket_id = self._crash_to_bucket.get(crash_id)
        if bucket_id:
            return self.buckets.get(bucket_id)
        return None

    def get_buckets_by_severity(
        self, min_severity: Severity = Severity.LOW
    ) -> list[SemanticBucket]:
        """Get buckets at or above a severity level.

        Args:
            min_severity: Minimum severity level

        Returns:
            List of buckets sorted by severity

        """
        filtered = [
            b
            for b in self.buckets.values()
            if SEVERITY_SCORES[b.severity] >= SEVERITY_SCORES[min_severity]
        ]
        return sorted(filtered, key=lambda b: SEVERITY_SCORES[b.severity], reverse=True)

    def get_buckets_by_impact(self, impact: ImpactCategory) -> list[SemanticBucket]:
        """Get buckets with a specific impact category.

        Args:
            impact: Impact category to filter

        Returns:
            List of matching buckets

        """
        return [b for b in self.buckets.values() if b.impact_category == impact]

    def get_strategy_effectiveness(self) -> dict[str, dict[str, int]]:
        """Analyze which mutation strategies find which bug types.

        Returns:
            Dictionary mapping strategies to bug type counts

        """
        effectiveness: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for bucket in self.buckets.values():
            bug_type = f"{bucket.root_cause.name}_{bucket.severity.name}"
            for strategy, count in bucket.mutation_strategies.items():
                effectiveness[strategy][bug_type] += count

        return dict(effectiveness)

    def calculate_deduplication_confidence(
        self, crash_id1: str, crash_id2: str
    ) -> float:
        """Calculate confidence that two crashes are duplicates.

        Args:
            crash_id1: First crash ID
            crash_id2: Second crash ID

        Returns:
            Confidence score 0-1

        """
        bucket1 = self.get_bucket_for_crash(crash_id1)
        bucket2 = self.get_bucket_for_crash(crash_id2)

        if not bucket1 or not bucket2:
            return 0.0

        # Same bucket = high confidence they're duplicates
        if bucket1.bucket_id == bucket2.bucket_id:
            return bucket1.confidence

        # Different buckets
        confidence = 0.0

        # Same root cause adds some confidence
        if bucket1.root_cause == bucket2.root_cause:
            confidence += 0.3

        # Same severity adds some confidence
        if bucket1.severity == bucket2.severity:
            confidence += 0.1

        # Same impact adds some confidence
        if bucket1.impact_category == bucket2.impact_category:
            confidence += 0.2

        return confidence

    def export_report(self) -> dict[str, Any]:
        """Export a summary report of all buckets.

        Returns:
            Report dictionary

        """
        severity_dist: defaultdict[str, int] = defaultdict(int)
        impact_dist: defaultdict[str, int] = defaultdict(int)
        root_cause_dist: defaultdict[str, int] = defaultdict(int)

        for bucket in self.buckets.values():
            severity_dist[bucket.severity.name] += len(bucket.crash_ids)
            impact_dist[bucket.impact_category.name] += len(bucket.crash_ids)
            root_cause_dist[bucket.root_cause.name] += len(bucket.crash_ids)

        return {
            "total_buckets": len(self.buckets),
            "total_crashes": sum(len(b.crash_ids) for b in self.buckets.values()),
            "severity_distribution": dict(severity_dist),
            "impact_distribution": dict(impact_dist),
            "root_cause_distribution": dict(root_cause_dist),
            "strategy_effectiveness": self.get_strategy_effectiveness(),
            "high_severity_buckets": [
                {
                    "bucket_id": b.bucket_id,
                    "severity": b.severity.name,
                    "root_cause": b.root_cause.name,
                    "crash_count": len(b.crash_ids),
                    "confidence": b.confidence,
                }
                for b in self.get_buckets_by_severity(Severity.HIGH)
            ],
        }

    def get_stats(self) -> dict[str, Any]:
        """Get bucketing statistics.

        Returns:
            Statistics dictionary

        """
        if not self.buckets:
            return {
                "total_buckets": 0,
                "total_crashes": 0,
                "avg_bucket_size": 0,
                "avg_confidence": 0,
            }

        sizes = [len(b.crash_ids) for b in self.buckets.values()]
        confidences = [b.confidence for b in self.buckets.values()]

        return {
            "total_buckets": len(self.buckets),
            "total_crashes": sum(sizes),
            "avg_bucket_size": sum(sizes) / len(sizes),
            "max_bucket_size": max(sizes),
            "min_bucket_size": min(sizes),
            "avg_confidence": sum(confidences) / len(confidences),
            "min_confidence": min(confidences),
        }
