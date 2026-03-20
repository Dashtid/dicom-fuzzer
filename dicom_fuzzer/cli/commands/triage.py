"""Triage subcommand for DICOM Fuzzer.

Runs CrashTriageEngine over a session JSON file and prints a prioritised
crash table to stdout.

Usage:
    dicom-fuzzer triage session.json
    dicom-fuzzer triage session.json --min-priority 50
    dicom-fuzzer triage session.json --json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from dicom_fuzzer.cli.base import SubcommandBase
from dicom_fuzzer.core.crash import CrashTriageEngine
from dicom_fuzzer.core.session.fuzzing_session import CrashRecord

__all__ = ["TriageCommand", "main"]


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for triage subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer triage",
        description="Triage and prioritise crashes from a fuzzing session",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dicom-fuzzer triage session.json
  dicom-fuzzer triage session.json --min-priority 50
  dicom-fuzzer triage session.json --json
        """,
    )

    parser.add_argument(
        "session_json",
        type=Path,
        help="Path to session JSON file",
    )

    parser.add_argument(
        "--min-priority",
        "-p",
        type=float,
        default=0.0,
        help="Only show crashes with priority >= value (default: 0.0)",
    )

    parser.add_argument(
        "--json",
        "-j",
        action="store_true",
        help="Output results as JSON",
    )

    return parser


class TriageCommand(SubcommandBase):
    """Crash triage subcommand."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        return create_parser()

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the subcommand."""
        if not args.session_json.exists():
            print(f"[-] Error: File not found: {args.session_json}", file=sys.stderr)
            return 1

        try:
            with open(args.session_json) as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[-] Error: Invalid JSON file: {e}", file=sys.stderr)
            return 1

        raw_crashes = data.get("crashes", [])
        if not raw_crashes:
            print("[i] No crashes found in session file.")
            return 0

        crashes: list[CrashRecord] = []
        for c in raw_crashes:
            try:
                record = CrashRecord(
                    crash_id=c.get("crash_id", ""),
                    timestamp=datetime.fromisoformat(c["timestamp"]),
                    crash_type=c.get("crash_type", "UNKNOWN"),
                    severity=c.get("severity", "medium"),
                    fuzzed_file_id=c.get("fuzzed_file_id", ""),
                    fuzzed_file_path=c.get("fuzzed_file_path", ""),
                    return_code=c.get("return_code"),
                    exception_type=c.get("exception_type"),
                    exception_message=c.get("exception_message"),
                    stack_trace=c.get("stack_trace"),
                    crash_log_path=c.get("crash_log_path"),
                    preserved_sample_path=c.get("preserved_sample_path"),
                    reproduction_command=c.get("reproduction_command"),
                    mutation_sequence=c.get("mutation_sequence", []),
                )
                crashes.append(record)
            except (KeyError, ValueError) as e:
                print(f"[!] Skipping malformed crash record: {e}", file=sys.stderr)

        if not crashes:
            print("[i] No valid crash records to triage.")
            return 0

        engine = CrashTriageEngine()
        triages = engine.triage_crashes(crashes)
        triages = [t for t in triages if t.priority_score >= args.min_priority]

        session_id = data.get("session_id", args.session_json.stem)

        if getattr(args, "json", False):
            output = {
                "session_id": session_id,
                "triages": [
                    {
                        "crash_id": t.crash_id,
                        "severity": t.severity.value,
                        "exploitability": t.exploitability.value,
                        "priority_score": t.priority_score,
                        "summary": t.summary,
                    }
                    for t in triages
                ],
                "summary": engine.get_triage_summary(triages),
            }
            print(json.dumps(output, indent=2))
            return 0

        print(f"[i] Triaging {len(crashes)} crashes from {session_id}...")
        if triages:
            print(
                f"  {'ID':<10}{'SEVERITY':<10}{'EXPLOITABILITY':<26}"
                f"{'PRIORITY':<10}SUMMARY"
            )
            for t in triages:
                print(
                    f"  {t.crash_id[:8]:<10}{t.severity.value:<10}"
                    f"{t.exploitability.value:<26}{t.priority_score:<10.1f}"
                    f"{t.summary[:60]}"
                )
        else:
            print("[i] No crashes meet the minimum priority threshold.")

        summary = engine.get_triage_summary(triages)
        sev = summary["by_severity"]
        print()
        print("Summary")
        print(
            f"  Total: {summary['total_crashes']}  "
            f"High priority: {summary['high_priority_count']}"
        )
        print(
            f"  By severity: critical={sev.get('critical', 0)} "
            f"high={sev.get('high', 0)} medium={sev.get('medium', 0)} "
            f"low={sev.get('low', 0)} info={sev.get('info', 0)}"
        )

        return 0


def main(argv: list[str] | None = None) -> int:
    """Main entry point for triage subcommand."""
    return TriageCommand.main(argv)


if __name__ == "__main__":
    sys.exit(main())
