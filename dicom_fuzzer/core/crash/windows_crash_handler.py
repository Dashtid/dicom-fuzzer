"""Windows Crash Handler - Native Windows crash dump capture and analysis.

This module provides Windows-specific crash detection and analysis:
- Detection of Windows exception codes (ACCESS_VIOLATION, HEAP_CORRUPTION, etc.)
- Minidump parsing for crash location and stack traces
- Crash signature generation for deduplication
- Integration with CrashAnalyzer for unified reporting

SECURITY CONTEXT: When fuzzing Windows applications like medical imaging viewers,
crashes manifest as specific Windows exception codes. Understanding these helps
identify exploitable vulnerabilities vs. benign errors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from pathlib import Path
from typing import Any

from dicom_fuzzer.core.constants import Severity
from dicom_fuzzer.utils.hashing import hash_string
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class WindowsExceptionCode(IntEnum):
    """Windows NTSTATUS exception codes indicating crash types.

    These codes are returned as negative exit codes by crashed Windows processes.
    The actual value is the signed 32-bit representation.

    Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
    """

    # Memory access violations - potential buffer overflow/RCE
    ACCESS_VIOLATION = 0xC0000005  # -1073741819
    IN_PAGE_ERROR = 0xC0000006  # -1073741818
    INVALID_HANDLE = 0xC0000008  # -1073741816

    # Heap corruption - potential heap overflow/RCE
    HEAP_CORRUPTION = 0xC0000374  # -1073740940

    # Stack issues - potential stack overflow/RCE
    STACK_OVERFLOW = 0xC00000FD  # -1073741571
    STACK_BUFFER_OVERRUN = (
        0xC0000409  # -1073740791 (/GS check failed, also CFG violations)
    )

    # Integer issues
    INTEGER_DIVIDE_BY_ZERO = 0xC0000094  # -1073741676
    INTEGER_OVERFLOW = 0xC0000095  # -1073741675

    # Array bounds - potential out-of-bounds access
    ARRAY_BOUNDS_EXCEEDED = 0xC000008C  # -1073741684

    # Illegal instructions
    ILLEGAL_INSTRUCTION = 0xC000001D  # -1073741795
    PRIVILEGED_INSTRUCTION = 0xC0000096  # -1073741674

    # Floating point
    FLOAT_DIVIDE_BY_ZERO = 0xC000008E  # -1073741682
    FLOAT_OVERFLOW = 0xC0000091  # -1073741679
    FLOAT_UNDERFLOW = 0xC0000093  # -1073741677

    # Assertion failures
    ASSERTION_FAILURE = 0xC0000420  # -1073740768


# Map exception codes to severity (CRITICAL = exploitable, HIGH = DoS)
EXCEPTION_SEVERITY: dict[WindowsExceptionCode, Severity] = {
    WindowsExceptionCode.ACCESS_VIOLATION: Severity.CRITICAL,
    WindowsExceptionCode.HEAP_CORRUPTION: Severity.CRITICAL,
    WindowsExceptionCode.STACK_BUFFER_OVERRUN: Severity.CRITICAL,
    WindowsExceptionCode.STACK_OVERFLOW: Severity.HIGH,
    WindowsExceptionCode.IN_PAGE_ERROR: Severity.HIGH,
    WindowsExceptionCode.INTEGER_OVERFLOW: Severity.MEDIUM,
    WindowsExceptionCode.INTEGER_DIVIDE_BY_ZERO: Severity.MEDIUM,
    WindowsExceptionCode.ARRAY_BOUNDS_EXCEEDED: Severity.CRITICAL,
    WindowsExceptionCode.ILLEGAL_INSTRUCTION: Severity.HIGH,
    WindowsExceptionCode.PRIVILEGED_INSTRUCTION: Severity.MEDIUM,
    WindowsExceptionCode.FLOAT_DIVIDE_BY_ZERO: Severity.LOW,
    WindowsExceptionCode.FLOAT_OVERFLOW: Severity.LOW,
    WindowsExceptionCode.FLOAT_UNDERFLOW: Severity.LOW,
    WindowsExceptionCode.ASSERTION_FAILURE: Severity.MEDIUM,
    WindowsExceptionCode.INVALID_HANDLE: Severity.MEDIUM,
}

# Human-readable descriptions
EXCEPTION_DESCRIPTIONS = {
    WindowsExceptionCode.ACCESS_VIOLATION: "Memory access violation (read/write to invalid address)",
    WindowsExceptionCode.HEAP_CORRUPTION: "Heap corruption detected (potential heap overflow)",
    WindowsExceptionCode.STACK_BUFFER_OVERRUN: "Stack buffer overrun (/GS security check or CFG violation)",
    WindowsExceptionCode.STACK_OVERFLOW: "Stack overflow (recursion or large stack allocation)",
    WindowsExceptionCode.IN_PAGE_ERROR: "Page fault accessing memory-mapped file",
    WindowsExceptionCode.INTEGER_OVERFLOW: "Integer overflow in arithmetic operation",
    WindowsExceptionCode.INTEGER_DIVIDE_BY_ZERO: "Integer division by zero",
    WindowsExceptionCode.ARRAY_BOUNDS_EXCEEDED: "Array index out of bounds",
    WindowsExceptionCode.ILLEGAL_INSTRUCTION: "Illegal CPU instruction executed",
    WindowsExceptionCode.PRIVILEGED_INSTRUCTION: "Privileged instruction in user mode",
    WindowsExceptionCode.FLOAT_DIVIDE_BY_ZERO: "Floating-point division by zero",
    WindowsExceptionCode.FLOAT_OVERFLOW: "Floating-point overflow",
    WindowsExceptionCode.FLOAT_UNDERFLOW: "Floating-point underflow",
    WindowsExceptionCode.ASSERTION_FAILURE: "Debug assertion failed",
    WindowsExceptionCode.INVALID_HANDLE: "Invalid handle used",
}


@dataclass
class WindowsCrashInfo:
    """Detailed Windows crash information."""

    exception_code: int
    exception_name: str
    description: str
    severity: Severity
    is_exploitable: bool
    crash_address: int | None = None
    faulting_module: str | None = None
    faulting_offset: int | None = None
    stack_trace: list[str] = field(default_factory=list)
    registers: dict[str, int] = field(default_factory=dict)
    crash_hash: str | None = None
    minidump_path: Path | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class WindowsCrashHandler:
    """Handles Windows-specific crash detection and analysis.

    This handler:
    1. Detects Windows exception codes from process exit codes
    2. Optionally parses minidump files for detailed crash info
    3. Generates crash signatures for deduplication
    4. Provides severity classification for triage
    """

    def __init__(
        self,
        crash_dir: Path | str = "./artifacts/crashes",
        enable_minidump: bool = True,
    ):
        """Initialize Windows crash handler.

        Args:
            crash_dir: Directory to store crash dumps and reports
            enable_minidump: Whether to attempt minidump parsing

        """
        self.crash_dir = Path(crash_dir)
        self.crash_dir.mkdir(parents=True, exist_ok=True)
        self.dumps_dir = self.crash_dir / "dumps"
        self.dumps_dir.mkdir(exist_ok=True)
        self.enable_minidump = enable_minidump
        self._minidump_available = self._check_minidump_library()

        if self.enable_minidump and not self._minidump_available:
            logger.warning(
                "minidump library not available - install with: pip install minidump"
            )

    def _check_minidump_library(self) -> bool:
        """Check if minidump parsing library is available."""
        try:
            import minidump  # noqa: F401

            return True
        except ImportError:
            return False

    def is_windows_crash(self, exit_code: int | None) -> bool:
        """Check if exit code indicates a Windows crash.

        Args:
            exit_code: Process exit code (can be negative signed or positive unsigned)

        Returns:
            True if exit code matches a known Windows exception

        """
        if exit_code is None:
            return False

        # Handle both signed and unsigned representations
        unsigned_code = self._to_unsigned(exit_code)

        # Check if it's a known exception code
        try:
            WindowsExceptionCode(unsigned_code)
            return True
        except ValueError:
            pass

        # Check for other crash indicators (negative codes often indicate crashes)
        # Windows uses negative codes for exceptions
        if exit_code < 0:
            # Check if it looks like an NTSTATUS code (0xC0000000 - 0xC0FFFFFF)
            if 0xC0000000 <= unsigned_code <= 0xC0FFFFFF:
                return True

        return False

    def _to_unsigned(self, code: int) -> int:
        """Convert signed 32-bit exit code to unsigned representation.

        Windows exception codes are NTSTATUS values which are unsigned,
        but Python receives them as signed 32-bit integers.

        Args:
            code: Signed exit code

        Returns:
            Unsigned 32-bit representation

        """
        if code >= 0:
            return code
        # Convert signed to unsigned 32-bit
        return code & 0xFFFFFFFF

    def analyze_crash(
        self,
        exit_code: int,
        test_file: Path,
        stdout: str = "",
        stderr: str = "",
    ) -> WindowsCrashInfo:
        """Analyze a Windows crash from exit code and process output.

        Args:
            exit_code: Process exit code
            test_file: Path to test file that caused crash
            stdout: Captured stdout
            stderr: Captured stderr

        Returns:
            WindowsCrashInfo with detailed crash analysis

        """
        unsigned_code = self._to_unsigned(exit_code)

        # Try to identify the exception type
        try:
            exception = WindowsExceptionCode(unsigned_code)
            exception_name = exception.name
            description = EXCEPTION_DESCRIPTIONS.get(
                exception, f"Unknown exception 0x{unsigned_code:08X}"
            )
            severity = EXCEPTION_SEVERITY.get(exception, Severity.UNKNOWN)
        except ValueError:
            exception_name = f"UNKNOWN_0x{unsigned_code:08X}"
            description = f"Unknown Windows exception code: 0x{unsigned_code:08X}"
            severity = Severity.HIGH if unsigned_code >= 0xC0000000 else Severity.MEDIUM

        is_exploitable = severity in (Severity.CRITICAL, Severity.HIGH)

        # Extract any crash details from stderr (common patterns)
        crash_address = self._extract_crash_address(stderr)
        faulting_module = self._extract_faulting_module(stderr)

        # Generate crash hash for deduplication
        crash_signature = (
            f"{exception_name}:{faulting_module or 'unknown'}:{crash_address or 0}"
        )
        crash_hash = hash_string(crash_signature)[:16]

        crash_info = WindowsCrashInfo(
            exception_code=unsigned_code,
            exception_name=exception_name,
            description=description,
            severity=severity,
            is_exploitable=is_exploitable,
            crash_address=crash_address,
            faulting_module=faulting_module,
            crash_hash=crash_hash,
        )

        logger.info(
            "Windows crash detected",
            exception=exception_name,
            code=f"0x{unsigned_code:08X}",
            severity=severity.value,
        )

        return crash_info

    def _extract_crash_address(self, stderr: str) -> int | None:
        """Extract crash address from stderr if available.

        Looks for common patterns like:
        - "at address 0x12345678"
        - "Exception at 0x12345678"
        - "Access violation at 0x12345678"

        Args:
            stderr: Process stderr

        Returns:
            Crash address if found, None otherwise

        """
        patterns = [
            r"at (?:address )?0x([0-9a-fA-F]+)",
            r"Exception at 0x([0-9a-fA-F]+)",
            r"violation (?:reading|writing) (?:address )?0x([0-9a-fA-F]+)",
            r"IP: 0x([0-9a-fA-F]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, stderr, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1), 16)
                except ValueError:
                    continue

        return None

    def _extract_faulting_module(self, stderr: str) -> str | None:
        """Extract faulting module name from stderr.

        Looks for patterns like:
        - "in module foo.dll"
        - "foo.exe!function"
        - "Faulting module: foo.dll"

        Args:
            stderr: Process stderr

        Returns:
            Module name if found, None otherwise

        """
        patterns = [
            r"in (?:module )?([a-zA-Z0-9_.-]+\.(?:dll|exe))",
            r"([a-zA-Z0-9_.-]+\.(?:dll|exe))!",
            r"[Ff]aulting module[:\s]+([a-zA-Z0-9_.-]+\.(?:dll|exe))",
        ]

        for pattern in patterns:
            match = re.search(pattern, stderr, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def parse_minidump(self, dump_path: Path) -> WindowsCrashInfo | None:
        """Parse a minidump file for detailed crash information.

        Args:
            dump_path: Path to .dmp file

        Returns:
            WindowsCrashInfo with details from minidump, or None if parsing fails

        """
        if not self._minidump_available:
            logger.debug("Minidump parsing not available")
            return None

        if not dump_path.exists():
            logger.warning("Minidump file not found", path=str(dump_path))
            return None

        try:
            from minidump.minidumpfile import MinidumpFile
            from minidump.streams import ExceptionStream

            with dump_path.open("rb") as f:
                mdmp = MinidumpFile.parse(f)

            # Get exception info
            exception_stream = mdmp.get_stream(ExceptionStream)
            if exception_stream:
                exception_record = exception_stream.exception_record
                exception_code = exception_record.ExceptionCode

                # Get exception name
                try:
                    exception = WindowsExceptionCode(exception_code)
                    exception_name = exception.name
                    severity = EXCEPTION_SEVERITY.get(exception, Severity.UNKNOWN)
                    description = EXCEPTION_DESCRIPTIONS.get(exception, "")
                except ValueError:
                    exception_name = f"UNKNOWN_0x{exception_code:08X}"
                    severity = Severity.HIGH
                    description = f"Unknown exception 0x{exception_code:08X}"

                # Get crash address
                crash_address = exception_record.ExceptionAddress

                # Get registers if available
                registers = {}
                if hasattr(exception_stream, "thread_context"):
                    ctx = exception_stream.thread_context
                    if hasattr(ctx, "Rip"):  # x64
                        registers = {
                            "RIP": ctx.Rip,
                            "RSP": ctx.Rsp,
                            "RBP": ctx.Rbp,
                            "RAX": ctx.Rax,
                        }
                    elif hasattr(ctx, "Eip"):  # x86
                        registers = {
                            "EIP": ctx.Eip,
                            "ESP": ctx.Esp,
                            "EBP": ctx.Ebp,
                            "EAX": ctx.Eax,
                        }

                # Generate crash hash
                crash_signature = f"{exception_name}:{crash_address:x}"
                crash_hash = hash_string(crash_signature)[:16]

                return WindowsCrashInfo(
                    exception_code=exception_code,
                    exception_name=exception_name,
                    description=description,
                    severity=severity,
                    is_exploitable=severity in (Severity.CRITICAL, Severity.HIGH),
                    crash_address=crash_address,
                    registers=registers,
                    crash_hash=crash_hash,
                    minidump_path=dump_path,
                )

        except Exception as e:
            logger.warning(
                "Failed to parse minidump", path=str(dump_path), error=str(e)
            )

        return None

    def save_crash_report(self, crash_info: WindowsCrashInfo, test_file: Path) -> Path:
        """Save detailed crash report to disk.

        Args:
            crash_info: Crash information to save
            test_file: Path to test file that caused crash

        Returns:
            Path to saved report

        """
        report_name = (
            f"crash_{crash_info.crash_hash}_{crash_info.timestamp:%Y%m%d_%H%M%S}.txt"
        )
        report_path = self.crash_dir / report_name

        with report_path.open("w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("WINDOWS CRASH REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Timestamp:        {crash_info.timestamp}\n")
            f.write(f"Exception Code:   0x{crash_info.exception_code:08X}\n")
            f.write(f"Exception Name:   {crash_info.exception_name}\n")
            f.write(f"Description:      {crash_info.description}\n")
            f.write(f"Severity:         {crash_info.severity.value.upper()}\n")
            f.write(
                f"Exploitable:      {'Yes' if crash_info.is_exploitable else 'No'}\n"
            )
            f.write(f"Crash Hash:       {crash_info.crash_hash}\n")
            f.write(f"Test File:        {test_file}\n")

            if crash_info.crash_address:
                f.write(f"Crash Address:    0x{crash_info.crash_address:016X}\n")

            if crash_info.faulting_module:
                f.write(f"Faulting Module:  {crash_info.faulting_module}\n")

            if crash_info.faulting_offset:
                f.write(f"Faulting Offset:  0x{crash_info.faulting_offset:08X}\n")

            if crash_info.registers:
                f.write("\nRegisters:\n")
                for reg, value in crash_info.registers.items():
                    f.write(f"  {reg}: 0x{value:016X}\n")

            if crash_info.stack_trace:
                f.write("\nStack Trace:\n")
                for frame in crash_info.stack_trace:
                    f.write(f"  {frame}\n")

            if crash_info.minidump_path:
                f.write(f"\nMinidump:         {crash_info.minidump_path}\n")

            f.write("\n" + "=" * 80 + "\n")

        logger.info("Crash report saved", path=str(report_path))
        return report_path

    def classify_for_triage(self, crash_info: WindowsCrashInfo) -> dict[str, Any]:
        """Classify crash for triage and prioritization.

        Returns a dictionary suitable for integration with CrashAnalyzer.

        Args:
            crash_info: Crash information

        Returns:
            Dictionary with triage classification

        """
        return {
            "crash_type": crash_info.exception_name.lower(),
            "severity": crash_info.severity,
            "exploitable": crash_info.is_exploitable,
            "crash_hash": crash_info.crash_hash,
            "description": crash_info.description,
            "windows_specific": True,
            "exception_code": crash_info.exception_code,
        }
