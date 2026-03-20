"""Tests for the triage CLI subcommand."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from dicom_fuzzer.cli.commands.triage import main


def _make_session(crashes: list[dict]) -> dict:
    """Build a minimal session JSON dict."""
    return {"session_id": "sess_abc", "crashes": crashes}


def _make_crash(
    crash_type: str = "SIGSEGV",
    exception_message: str | None = None,
) -> dict:
    return {
        "crash_id": "crash_001",
        "timestamp": datetime.now(UTC).isoformat(),
        "crash_type": crash_type,
        "severity": "high",
        "fuzzed_file_id": "file_001",
        "fuzzed_file_path": "/tmp/fuzz.dcm",
        "return_code": -11,
        "exception_type": None,
        "exception_message": exception_message,
        "stack_trace": None,
        "crash_log_path": None,
        "preserved_sample_path": None,
        "reproduction_command": None,
        "mutation_sequence": [],
    }


class TestTriageFileNotFound:
    """Error handling for missing session file."""

    def test_missing_file_returns_1(self, tmp_path, capsys):
        """Non-existent session JSON must return exit code 1."""
        result = main([str(tmp_path / "does_not_exist.json")])
        assert result == 1
        captured = capsys.readouterr()
        assert (
            "not found" in captured.err.lower() or "not found" in captured.out.lower()
        )


class TestTriageInvalidJson:
    """Error handling for malformed JSON."""

    def test_invalid_json_returns_1(self, tmp_path, capsys):
        """Malformed JSON must return exit code 1."""
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        result = main([str(bad)])
        assert result == 1


class TestTriageEmptyCrashes:
    """Empty crash list is valid — just nothing to show."""

    def test_empty_crashes_returns_0(self, tmp_path, capsys):
        """Session with no crashes must return 0 and print info message."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(_make_session([])))

        result = main([str(session_file)])
        assert result == 0
        captured = capsys.readouterr()
        assert "[i]" in captured.out


class TestTriageTable:
    """Normal triage run renders crash table."""

    def test_triage_shows_table(self, tmp_path, capsys):
        """Valid crash list must produce a table with header and summary."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(_make_session([_make_crash("SIGSEGV")])))

        result = main([str(session_file)])
        assert result == 0
        captured = capsys.readouterr()
        assert "SEVERITY" in captured.out
        assert "Summary" in captured.out

    def test_triage_returns_0_on_success(self, tmp_path):
        """Successful triage must return exit code 0."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(_make_session([_make_crash("crash")])))
        result = main([str(session_file)])
        assert result == 0


class TestTriageMinPriority:
    """--min-priority filters low-priority crashes out of the table."""

    def test_min_priority_filters(self, tmp_path, capsys):
        """Crashes below --min-priority must not appear in output."""
        session_file = tmp_path / "session.json"
        # A plain "crash" type with no exploitability keywords gets a low score
        session_file.write_text(json.dumps(_make_session([_make_crash("crash")])))

        result = main([str(session_file), "--min-priority", "100"])
        assert result == 0
        captured = capsys.readouterr()
        # Nothing meets priority 100 — table rows should be absent
        assert "SEVERITY" not in captured.out


class TestTriageJsonFlag:
    """--json flag outputs machine-readable JSON."""

    def test_json_flag_outputs_json(self, tmp_path, capsys):
        """--json flag must produce parseable JSON output."""
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(_make_session([_make_crash("SIGSEGV")])))

        result = main([str(session_file), "--json"])
        assert result == 0
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "triages" in parsed
        assert "summary" in parsed
        assert parsed["session_id"] == "sess_abc"
