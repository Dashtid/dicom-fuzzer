"""Crash Analysis Framework - Automatic Crash Detection and Reporting

LEARNING OBJECTIVE: This module demonstrates how to automatically detect,
analyze, and report crashes during fuzzing campaigns.

CONCEPT: When fuzzing finds an input that crashes a program, we need to:
1. Detect the crash (exit codes, signals, exceptions)
2. Capture crash information (stack trace, registers, memory)
3. Minimize the input (find smallest crash-triggering input)
4. Classify the crash (unique vs duplicate)
5. Generate reproducible test cases

WHY: Crash analysis automates vulnerability discovery:
- Identifies exploitable vs non-exploitable crashes
- Deduplicates crashes to find unique bugs
- Creates minimal reproducible test cases for developers
- Prioritizes crashes by severity
"""

import hashlib
import traceback
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path


class CrashSeverity(Enum):
    """Crash severity classification.

    CONCEPT: Not all crashes are equal:
    - CRITICAL: Memory corruption, code execution possible
    - HIGH: Denial of service, data corruption
    - MEDIUM: Recoverable errors, degraded functionality
    - LOW: Minor issues, error messages
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class CrashType(Enum):
    """Types of crashes we can detect.

    CONCEPT: Different crash types indicate different vulnerabilities:
    - SEGFAULT: Memory access violation (exploitable)
    - ASSERTION: Developer assertion failed (logic error)
    - EXCEPTION: Uncaught exception (improper error handling)
    - TIMEOUT: Infinite loop or hang (DoS)
    - OUT_OF_MEMORY: Memory exhaustion (DoS)
    """

    SEGFAULT = "segmentation_fault"
    ASSERTION_FAILURE = "assertion_failure"
    UNCAUGHT_EXCEPTION = "uncaught_exception"
    TIMEOUT = "timeout"
    OUT_OF_MEMORY = "out_of_memory"
    STACK_OVERFLOW = "stack_overflow"
    UNKNOWN = "unknown"


@dataclass
class CrashReport:
    """Comprehensive crash report.

    CONCEPT: Captures all information needed to:
    - Reproduce the crash
    - Understand the root cause
    - Fix the vulnerability
    """

    crash_id: str  # Unique identifier
    timestamp: datetime
    crash_type: CrashType
    severity: CrashSeverity
    test_case_path: str  # Path to input that caused crash
    stack_trace: str | None
    exception_message: str | None
    crash_hash: str  # For deduplication
    additional_info: dict[str, str]


class CrashAnalyzer:
    """Analyzes crashes during fuzzing campaigns.

    CONCEPT: Runs test cases and monitors for crashes,
    collecting diagnostic information automatically.

    SECURITY: Helps identify exploitable vulnerabilities by:
    - Detecting memory corruption
    - Finding DoS conditions
    - Discovering logic errors
    """

    def __init__(self, crash_dir: str = "./crashes"):
        """Initialize crash analyzer.

        Args:
            crash_dir: Directory to store crash reports and test cases

        """
        self.crash_dir = Path(crash_dir)
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        self.crashes: list[CrashReport] = []
        self.crash_hashes: set = set()  # For deduplication

    def analyze_exception(
        self, exception: Exception, test_case_path: str
    ) -> CrashReport:
        """Analyze an exception that occurred during testing.

        CONCEPT: Exceptions contain valuable debugging information:
        - Exception type (TypeError, ValueError, etc.)
        - Stack trace (where it occurred)
        - Exception message (what went wrong)

        Args:
            exception: The exception that was raised
            test_case_path: Path to input file that caused the crash

        Returns:
            Crash report with analysis

        """
        # Get stack trace
        stack_trace = "".join(
            traceback.format_exception(
                type(exception), exception, exception.__traceback__
            )
        )

        # Classify crash type
        crash_type = self._classify_exception(exception)

        # Determine severity
        severity = self._determine_severity(crash_type, exception)

        # Create crash hash for deduplication
        crash_hash = self._generate_crash_hash(stack_trace, str(exception))

        # Generate unique crash ID
        crash_id = f"crash_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{crash_hash[:8]}"

        # Create crash report
        report = CrashReport(
            crash_id=crash_id,
            timestamp=datetime.now(),
            crash_type=crash_type,
            severity=severity,
            test_case_path=test_case_path,
            stack_trace=stack_trace,
            exception_message=str(exception),
            crash_hash=crash_hash,
            additional_info={
                "exception_type": type(exception).__name__,
                "exception_module": type(exception).__module__,
            },
        )

        return report

    def analyze_crash(self, crash_file: Path, exception: Exception) -> dict:
        """Analyze a crash and return results as dictionary.

        This method provides compatibility with test expectations and uses
        the mockable alias methods for testing.

        Args:
            crash_file: Path to file that caused crash
            exception: Exception that occurred

        Returns:
            Dictionary with crash analysis results

        """
        # Use mockable alias methods for test compatibility
        crash_type_str = self._get_crash_type(exception)
        severity_str = self._calculate_severity(crash_type_str, exception)

        # Get stack trace for hash generation
        stack_trace = "".join(
            traceback.format_exception(
                type(exception), exception, exception.__traceback__
            )
        )

        # Create crash hash
        crash_hash = self._generate_crash_hash(stack_trace, str(exception))

        # Generate unique crash ID
        crash_id = f"crash_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{crash_hash[:8]}"

        # Check exploitability
        exploitable = severity_str in ["critical", "high"]

        return {
            "type": crash_type_str,
            "severity": severity_str,
            "exploitable": exploitable,
            "crash_id": crash_id,
            "crash_hash": crash_hash,
        }

    def _classify_exception(self, exception: Exception) -> CrashType:
        """Classify exception type.

        CONCEPT: Maps Python exceptions to crash types:
        - MemoryError -> OUT_OF_MEMORY
        - RecursionError -> STACK_OVERFLOW
        - AssertionError -> ASSERTION_FAILURE
        - Others -> UNCAUGHT_EXCEPTION

        Args:
            exception: Exception to classify

        Returns:
            Crash type classification

        """
        if isinstance(exception, MemoryError):
            return CrashType.OUT_OF_MEMORY
        elif isinstance(exception, RecursionError):
            return CrashType.STACK_OVERFLOW
        elif isinstance(exception, AssertionError):
            return CrashType.ASSERTION_FAILURE
        elif isinstance(exception, TimeoutError):
            return CrashType.TIMEOUT
        else:
            return CrashType.UNCAUGHT_EXCEPTION

    def _determine_severity(
        self, crash_type: CrashType, exception: Exception
    ) -> CrashSeverity:
        """Determine crash severity.

        CONCEPT: Severity indicates exploitability and impact:
        - Memory corruption = CRITICAL (potential code execution)
        - DoS conditions = HIGH (service disruption)
        - Logic errors = MEDIUM (incorrect behavior)
        - Minor issues = LOW

        Args:
            crash_type: Type of crash
            exception: The exception

        Returns:
            Severity classification

        """
        # CRITICAL: Memory corruption indicators
        if crash_type == CrashType.SEGFAULT:
            return CrashSeverity.CRITICAL

        # HIGH: Denial of service
        if crash_type in [
            CrashType.OUT_OF_MEMORY,
            CrashType.STACK_OVERFLOW,
            CrashType.TIMEOUT,
        ]:
            return CrashSeverity.HIGH

        # MEDIUM: Logic errors
        if crash_type == CrashType.ASSERTION_FAILURE:
            return CrashSeverity.MEDIUM

        # Check exception type for additional hints
        exception_str = str(exception).lower()
        if any(
            keyword in exception_str
            for keyword in ["buffer", "overflow", "corruption", "memory"]
        ):
            return CrashSeverity.CRITICAL

        # Default
        return CrashSeverity.MEDIUM

    def _get_crash_type(self, exception: Exception) -> str:
        """Alias for _classify_exception for test compatibility.

        Args:
            exception: Exception to classify

        Returns:
            Crash type as string

        """
        return self._classify_exception(exception).value

    def _calculate_severity(self, crash_type_str: str, exception: Exception) -> str:
        """Alias for _determine_severity for test compatibility.

        Args:
            crash_type_str: Crash type string
            exception: Exception

        Returns:
            Severity as string

        """
        # Convert string back to CrashType enum
        crash_type = CrashType(crash_type_str)
        return self._determine_severity(crash_type, exception).value

    def _generate_crash_hash(self, stack_trace: str, exception_msg: str) -> str:
        """Generate hash for crash deduplication.

        CONCEPT: Multiple inputs might trigger the same bug,
        creating the same stack trace. We hash the stack trace
        to identify unique crashes vs duplicates.

        WHY: Prevents reporting the same bug multiple times.

        Args:
            stack_trace: Stack trace string
            exception_msg: Exception message

        Returns:
            Hash string for deduplication

        """
        # Combine stack trace and exception for hashing
        crash_signature = f"{stack_trace}\n{exception_msg}"

        # Create SHA256 hash
        return hashlib.sha256(crash_signature.encode()).hexdigest()

    def is_unique_crash(self, crash_hash: str) -> bool:
        """Check if this is a unique crash (not seen before).

        Args:
            crash_hash: Hash of the crash

        Returns:
            True if unique, False if duplicate

        """
        if crash_hash in self.crash_hashes:
            return False

        self.crash_hashes.add(crash_hash)
        return True

    def save_crash_report(self, report: CrashReport) -> Path:
        """Save crash report to disk.

        CONCEPT: Persistent crash reports allow:
        - Post-campaign analysis
        - Sharing with development teams
        - Long-term vulnerability tracking

        Args:
            report: Crash report to save

        Returns:
            Path to saved report

        """
        report_path = self.crash_dir / f"{report.crash_id}.txt"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write(f"CRASH REPORT: {report.crash_id}\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Timestamp:      {report.timestamp}\n")
            f.write(f"Crash Type:     {report.crash_type.value}\n")
            f.write(f"Severity:       {report.severity.value}\n")
            f.write(f"Test Case:      {report.test_case_path}\n")
            f.write(f"Crash Hash:     {report.crash_hash}\n")
            f.write("\n")

            if report.exception_message:
                f.write("Exception Message:\n")
                f.write(f"{report.exception_message}\n\n")

            if report.stack_trace:
                f.write("Stack Trace:\n")
                f.write("=" * 80 + "\n")
                f.write(f"{report.stack_trace}\n")

            if report.additional_info:
                f.write("\nAdditional Information:\n")
                for key, value in report.additional_info.items():
                    f.write(f"  {key}: {value}\n")

        return report_path

    def record_crash(
        self, exception: Exception, test_case_path: str
    ) -> CrashReport | None:
        """Record a crash for analysis.

        Args:
            exception: Exception that was raised
            test_case_path: Path to test case that triggered crash

        Returns:
            Crash report if unique, None if duplicate

        """
        # Analyze the crash
        report = self.analyze_exception(exception, test_case_path)

        # Check if unique
        if not self.is_unique_crash(report.crash_hash):
            return None  # Duplicate crash

        # Save report
        self.save_crash_report(report)

        # Store in memory
        self.crashes.append(report)

        return report

    def get_crash_summary(self) -> dict[str, int]:
        """Get summary of crashes found.

        Returns:
            Dictionary with crash statistics

        """
        summary = {
            "total_crashes": len(self.crashes),
            "unique_crashes": len(self.crash_hashes),
            "critical": sum(
                1 for c in self.crashes if c.severity == CrashSeverity.CRITICAL
            ),
            "high": sum(1 for c in self.crashes if c.severity == CrashSeverity.HIGH),
            "medium": sum(
                1 for c in self.crashes if c.severity == CrashSeverity.MEDIUM
            ),
            "low": sum(1 for c in self.crashes if c.severity == CrashSeverity.LOW),
        }
        return summary

    def generate_report(self) -> str:
        """Generate human-readable crash report summary.

        Returns:
            Formatted crash summary

        """
        summary = self.get_crash_summary()

        report = []
        report.append("=" * 80)
        report.append("CRASH ANALYSIS SUMMARY")
        report.append("=" * 80)
        report.append(f"Total Crashes:   {summary['total_crashes']}")
        report.append(f"Unique Crashes:  {summary['unique_crashes']}")
        report.append("")
        report.append("Severity Breakdown:")
        report.append(f"  CRITICAL:  {summary['critical']}")
        report.append(f"  HIGH:      {summary['high']}")
        report.append(f"  MEDIUM:    {summary['medium']}")
        report.append(f"  LOW:       {summary['low']}")
        report.append("")

        if self.crashes:
            report.append("Recent Crashes:")
            for crash in self.crashes[:10]:  # Show last 10
                report.append(f"  [{crash.severity.value.upper()}] {crash.crash_id}")
                report.append(f"    Type: {crash.crash_type.value}")
                report.append(f"    Test: {Path(crash.test_case_path).name}")
                report.append("")

        return "\n".join(report)
