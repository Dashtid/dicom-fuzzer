"""Tests for the auto-triage hook in cli.main._run_auto_triage."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from dicom_fuzzer.cli.main import _run_auto_triage


def _write_session(run_dir: Path, crashes: list[dict]) -> Path:
    json_dir = run_dir / "reports" / "json"
    json_dir.mkdir(parents=True, exist_ok=True)
    session_path = json_dir / "session.json"
    session_path.write_text(
        json.dumps({"session_id": "auto_triage_test", "crashes": crashes})
    )
    return session_path


def _crash(
    crash_id: str = "c1", exception_message: str = "write access violation"
) -> dict:
    return {
        "crash_id": crash_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "crash_type": "SIGSEGV",
        "severity": "critical",
        "fuzzed_file_id": crash_id,
        "fuzzed_file_path": f"/tmp/{crash_id}.dcm",
        "return_code": -11,
        "exception_type": "SegmentationFault",
        "exception_message": exception_message,
        "stack_trace": "frame 0: heap corruption\nframe 1: process",
        "mutation_sequence": [],
    }


class TestNoSessionFile:
    def test_missing_session_file_is_silent(self, tmp_path):
        # No session.json exists -- helper must return without raising
        _run_auto_triage(tmp_path)
        assert not (tmp_path / "reports" / "triage").exists()


class TestEmptyCrashes:
    def test_zero_crashes_writes_no_reports(self, tmp_path):
        _write_session(tmp_path, [])
        _run_auto_triage(tmp_path)
        assert not (tmp_path / "reports" / "triage").exists()


class TestCrashesPresent:
    def test_one_crash_writes_index_and_cluster(self, tmp_path, capsys):
        _write_session(tmp_path, [_crash()])
        _run_auto_triage(tmp_path)

        triage_dir = tmp_path / "reports" / "triage"
        assert (triage_dir / "index.md").is_file()
        assert any(triage_dir.glob("cluster_*.md"))

        captured = capsys.readouterr()
        assert "Auto-triage" in captured.out
        assert "1 crashes" in captured.out
        assert "1 unique" in captured.out

    def test_duplicate_crashes_collapse_into_one_cluster(self, tmp_path, capsys):
        _write_session(tmp_path, [_crash("c1"), _crash("c2"), _crash("c3")])
        _run_auto_triage(tmp_path)

        captured = capsys.readouterr()
        assert "3 crashes" in captured.out
        assert "1 unique" in captured.out

        cluster_files = list((tmp_path / "reports" / "triage").glob("cluster_*.md"))
        assert len(cluster_files) == 1


class TestErrorTolerance:
    def test_malformed_session_does_not_raise(self, tmp_path):
        json_dir = tmp_path / "reports" / "json"
        json_dir.mkdir(parents=True)
        (json_dir / "session.json").write_text("{not valid json")
        # Must not raise -- triage failures should never break the campaign
        _run_auto_triage(tmp_path)

    def test_malformed_crash_record_skipped(self, tmp_path, capsys):
        # One good crash + one missing required timestamp field
        bad = {"crash_id": "bad", "crash_type": "X"}
        good = _crash()
        _write_session(tmp_path, [bad, good])
        _run_auto_triage(tmp_path)

        captured = capsys.readouterr()
        # Should still report the good crash
        assert "1 crashes" in captured.out
