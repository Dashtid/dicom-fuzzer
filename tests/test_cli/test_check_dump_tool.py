"""Unit tests for the ``check-dump-tool`` Phase 4 pre-flight subcommand.

These tests don't invoke real procdump.exe or dump-analyzer.exe; they
stand up fake binaries on disk and mock the subprocess boundary to
cover every branch of the diagnostic output.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from dicom_fuzzer.cli.commands.check_dump_tool import main


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


_OK_HELPER_OUTPUT = json.dumps(
    {
        "schema_version": 1,
        "dump_path": "C:/bogus.dmp",
        "exception": None,
        "faulting_thread_id": None,
        "frames": [],
        "error": "dump file not found: C:/bogus.dmp",
    }
)


class TestProcDumpDetection:
    def test_explicit_path_found(self, tmp_path, monkeypatch, capsys):
        procdump = tmp_path / "procdump.exe"
        procdump.write_bytes(b"mock")
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        with patch(
            "dicom_fuzzer.cli.commands.check_dump_tool.subprocess.run",
            return_value=_completed(stdout=_OK_HELPER_OUTPUT),
        ):
            rc = main(
                [
                    "--dump-tool",
                    str(procdump),
                    "--analyzer",
                    str(helper),
                ]
            )
        assert rc == 0
        out = capsys.readouterr().out
        assert "ProcDump:" in out
        assert "All checks passed" in out

    def test_env_fallback(self, tmp_path, monkeypatch, capsys):
        procdump = tmp_path / "procdump.exe"
        procdump.write_bytes(b"mock")
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        monkeypatch.setenv("DICOM_FUZZER_PROCDUMP", str(procdump))
        with patch(
            "dicom_fuzzer.cli.commands.check_dump_tool.subprocess.run",
            return_value=_completed(stdout=_OK_HELPER_OUTPUT),
        ):
            rc = main(["--analyzer", str(helper)])
        assert rc == 0

    def test_missing_procdump_path(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("DICOM_FUZZER_PROCDUMP", raising=False)
        rc = main(["--analyzer", str(tmp_path / "fake_helper.exe")])
        out = capsys.readouterr().out
        assert rc == 1
        assert "NOT CONFIGURED" in out

    def test_procdump_path_does_not_exist(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("DICOM_FUZZER_PROCDUMP", raising=False)
        rc = main(
            [
                "--dump-tool",
                str(tmp_path / "missing.exe"),
                "--analyzer",
                str(tmp_path / "fake_helper.exe"),
            ]
        )
        out = capsys.readouterr().out
        assert rc == 1
        assert "NOT FOUND" in out


class TestStackBackendDetection:
    def test_helper_passes_smoke_test(self, tmp_path, capsys):
        procdump = tmp_path / "procdump.exe"
        procdump.write_bytes(b"mock")
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        with patch(
            "dicom_fuzzer.cli.commands.check_dump_tool.subprocess.run",
            return_value=_completed(stdout=_OK_HELPER_OUTPUT),
        ):
            rc = main(
                [
                    "--dump-tool",
                    str(procdump),
                    "--analyzer",
                    str(helper),
                ]
            )
        assert rc == 0
        out = capsys.readouterr().out
        assert "ClrMD helper: smoke test passed" in out

    def test_helper_emits_no_stdout(self, tmp_path, capsys):
        procdump = tmp_path / "procdump.exe"
        procdump.write_bytes(b"mock")
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        with patch(
            "dicom_fuzzer.cli.commands.check_dump_tool.subprocess.run",
            return_value=_completed(returncode=1, stdout="", stderr="boom"),
        ):
            rc = main(
                [
                    "--dump-tool",
                    str(procdump),
                    "--analyzer",
                    str(helper),
                ]
            )
        out = capsys.readouterr().out
        assert rc == 1
        assert "emitted no stdout" in out

    def test_helper_emits_non_json(self, tmp_path, capsys):
        procdump = tmp_path / "procdump.exe"
        procdump.write_bytes(b"mock")
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        with patch(
            "dicom_fuzzer.cli.commands.check_dump_tool.subprocess.run",
            return_value=_completed(stdout="not json"),
        ):
            rc = main(
                [
                    "--dump-tool",
                    str(procdump),
                    "--analyzer",
                    str(helper),
                ]
            )
        out = capsys.readouterr().out
        assert rc == 1
        assert "not JSON" in out

    def test_helper_timeout(self, tmp_path, capsys):
        procdump = tmp_path / "procdump.exe"
        procdump.write_bytes(b"mock")
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        with patch(
            "dicom_fuzzer.cli.commands.check_dump_tool.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="x", timeout=15),
        ):
            rc = main(
                [
                    "--dump-tool",
                    str(procdump),
                    "--analyzer",
                    str(helper),
                ]
            )
        out = capsys.readouterr().out
        assert rc == 1
        assert "TIMED OUT" in out

    def test_falls_back_to_dotnet_dump(self, tmp_path, capsys, monkeypatch):
        procdump = tmp_path / "procdump.exe"
        procdump.write_bytes(b"mock")
        # No analyzer at the explicit path
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_dump_tool.shutil.which",
            lambda name: "C:/tools/dotnet-dump.exe" if name == "dotnet-dump" else None,
        )
        rc = main(
            [
                "--dump-tool",
                str(procdump),
                "--analyzer",
                str(tmp_path / "missing-helper.exe"),
            ]
        )
        out = capsys.readouterr().out
        assert rc == 0
        assert "dotnet-dump fallback" in out

    def test_no_backend_available(self, tmp_path, capsys, monkeypatch):
        procdump = tmp_path / "procdump.exe"
        procdump.write_bytes(b"mock")
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_dump_tool.shutil.which",
            lambda name: None,
        )
        rc = main(
            [
                "--dump-tool",
                str(procdump),
                "--analyzer",
                str(tmp_path / "missing-helper.exe"),
            ]
        )
        out = capsys.readouterr().out
        assert rc == 1
        assert "No stack-trace backend" in out


class TestDispatcher:
    """Confirm the subcommand is wired into SUBCOMMANDS."""

    def test_subcommand_is_registered(self):
        from dicom_fuzzer.cli.main import SUBCOMMANDS

        assert "check-dump-tool" in SUBCOMMANDS
        assert SUBCOMMANDS["check-dump-tool"] == (
            "dicom_fuzzer.cli.commands.check_dump_tool"
        )
