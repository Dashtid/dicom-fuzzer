"""Crash data models shared across the crash and session subsystems."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from dicom_fuzzer.core.serialization import SerializableMixin


@dataclass
class CrashRecord(SerializableMixin):
    """Detailed crash record with full forensic information.

    Links crash back to exact file and mutation history that caused it.
    """

    crash_id: str
    timestamp: datetime
    crash_type: str  # crash, hang, exception
    severity: str  # critical, high, medium, low

    # Link to fuzzed file
    fuzzed_file_id: str
    fuzzed_file_path: str

    # Crash details
    return_code: int | None = None
    exception_type: str | None = None
    exception_message: str | None = None
    stack_trace: str | None = None

    # Artifacts
    crash_log_path: str | None = None
    preserved_sample_path: str | None = None
    # Path to per-crash minidump (.dmp). Populated when the target was
    # launched with DOTNET_DbgEnableMiniDump env vars set, or when
    # createdump.exe captured a hung process. Consumed by the
    # pythonnet/ClrMD dump-analyzer for symbolic stack-trace extraction.
    dump_path: str | None = None

    # Reproducibility
    reproduction_command: str | None = None

    # Mutation tracking for deduplication
    mutation_sequence: list[tuple[Any, ...]] = field(default_factory=list)


__all__ = ["CrashRecord"]
