"""Crash Triage Enrichers.

Enriches crash records with automated triage analysis.
"""

from datetime import datetime
from typing import Any

from dicom_fuzzer.core.crash_triage import CrashTriageEngine
from dicom_fuzzer.core.fuzzing_session import CrashRecord


class CrashTriageEnricher:
    """Enriches crash records with automated triage analysis."""

    def __init__(self, triage_engine: CrashTriageEngine | None = None):
        """Initialize the crash triage enricher.

        Args:
            triage_engine: Crash triage engine instance.

        """
        self.triage_engine = triage_engine or CrashTriageEngine()

    def enrich_crashes(self, session_data: dict[str, Any]) -> dict[str, Any]:
        """Enrich crash records with automated triage analysis.

        Args:
            session_data: Session report dictionary.

        Returns:
            Enhanced session data with triage information.

        """
        crashes = session_data.get("crashes", [])
        if not crashes:
            return session_data

        # Convert crash dicts to CrashRecord objects for triage
        crash_records = []
        for crash in crashes:
            # Parse timestamp (could be string or datetime)
            timestamp_val = crash.get("timestamp", "")
            if isinstance(timestamp_val, str) and timestamp_val:
                try:
                    timestamp_obj = datetime.fromisoformat(timestamp_val)
                except (ValueError, AttributeError):
                    timestamp_obj = datetime.now()
            elif isinstance(timestamp_val, datetime):
                timestamp_obj = timestamp_val
            else:
                timestamp_obj = datetime.now()

            # Create CrashRecord from dict (simplified for triage)
            crash_record = CrashRecord(
                crash_id=crash.get("crash_id", "unknown"),
                timestamp=timestamp_obj,
                crash_type=crash.get("crash_type", "unknown"),
                severity=crash.get("severity", "medium"),
                fuzzed_file_id=crash.get("fuzzed_file_id", "unknown"),
                fuzzed_file_path=crash.get("fuzzed_file_path", ""),
                return_code=crash.get("return_code"),
                exception_type=crash.get("exception_type"),
                exception_message=crash.get("exception_message"),
                stack_trace=crash.get("stack_trace", ""),
            )
            crash_records.append((crash, crash_record))

        # Perform triage
        for crash_dict, crash_record in crash_records:
            triage = self.triage_engine.triage_crash(crash_record)

            # Add triage data to crash dict
            crash_dict["triage"] = {
                "severity": triage.severity.value,
                "exploitability": triage.exploitability.value,
                "priority_score": triage.priority_score,
                "indicators": triage.indicators,
                "recommendations": triage.recommendations,
                "tags": triage.tags,
                "summary": triage.summary,
            }

        # Sort crashes by priority score (highest first)
        session_data["crashes"] = sorted(
            crashes,
            key=lambda c: c.get("triage", {}).get("priority_score", 0),
            reverse=True,
        )

        return session_data


__all__ = ["CrashTriageEnricher"]
