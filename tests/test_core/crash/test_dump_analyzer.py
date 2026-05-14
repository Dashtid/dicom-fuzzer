"""Unit tests for the Python wrapper around the ClrMD dump-analyzer.

These tests don't invoke a real .NET runtime or dump-analyzer.exe;
they mock the subprocess boundary so the parsing and fallback logic
is covered on every platform.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from dicom_fuzzer.core.crash.dump_analyzer import (
    ExceptionInfo,
    StackFrame,
    StackResult,
    _parse_clrstack_output,
    _result_from_helper_doc,
    _split_call_site,
    analyze_dump,
)

HELPER_OK_DOC = {
    "schema_version": 1,
    "dump_path": "C:/dump.dmp",
    "exception": {
        "code_hex": "0x80131509",
        "name": "InvalidOperationException",
        "address_hex": "0x7ffd00000000",
    },
    "faulting_thread_id": 12345,
    "frames": [
        {
            "is_managed": True,
            "module": "Hermes.exe",
            "type": "Hermes.Parser.DicomReader",
            "method": "ReadSequence",
            "signature": "ReadSequence(System.IO.Stream, Int32)",
            "md_token": "0x06000123",
            "il_offset_hex": "0x4a",
            "ip_hex": "0x7ffd91234567",
        },
        {
            "is_managed": False,
            "module": None,
            "type": None,
            "method": None,
            "signature": None,
            "md_token": None,
            "il_offset_hex": None,
            "ip_hex": "0x7ffd91234abc",
        },
    ],
    "error": None,
}


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    """Build a CompletedProcess-shaped mock for subprocess.run."""
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


class TestStackResultSerialization:
    """StackResult round-trips through asdict/JSON without loss."""

    def test_to_json_roundtrip(self):
        r = StackResult(
            backend="clrmd",
            dump_path="C:/d.dmp",
            exception=ExceptionInfo("0x1", "X", "0x2"),
            faulting_thread_id=42,
            frames=[
                StackFrame(
                    is_managed=True,
                    module="m.exe",
                    type="T",
                    method="M",
                    signature="M()",
                    md_token="0x06000001",  # noqa: S106 -- .NET MethodDef metadata token, not a credential
                    il_offset_hex="0x0",
                    ip_hex="0x100",
                )
            ],
        )
        decoded = json.loads(r.to_json())
        assert decoded["backend"] == "clrmd"
        assert decoded["faulting_thread_id"] == 42
        assert decoded["frames"][0]["method"] == "M"
        assert decoded["exception"]["name"] == "X"


class TestAnalyzeDumpHelperPath:
    """Happy path + helper-side failures."""

    def test_missing_dump_returns_error_no_backend(self, tmp_path):
        result = analyze_dump(tmp_path / "nope.dmp")
        assert result.backend == "none"
        assert "not found" in (result.error or "")
        assert result.frames == []

    def test_helper_success_parsed(self, tmp_path):
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"dump")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            return_value=_completed(stdout=json.dumps(HELPER_OK_DOC)),
        ) as run_mock:
            r = analyze_dump(dump, helper_path=helper)
        run_mock.assert_called_once()
        cmd = run_mock.call_args.args[0]
        assert cmd[0] == str(helper)
        assert cmd[1] == str(dump)
        assert r.backend == "clrmd"
        assert r.error is None
        assert r.faulting_thread_id == 12345
        assert r.exception is not None
        assert r.exception.name == "InvalidOperationException"
        assert len(r.frames) == 2
        assert r.frames[0].is_managed is True
        assert r.frames[0].module == "Hermes.exe"
        assert r.frames[0].method == "ReadSequence"
        assert r.frames[1].is_managed is False

    def test_helper_returns_error_field(self, tmp_path):
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        err_doc = dict(HELPER_OK_DOC, error="dump has no managed runtime")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            return_value=_completed(stdout=json.dumps(err_doc)),
        ):
            r = analyze_dump(dump, helper_path=helper)
        assert r.backend == "clrmd"
        # error is parsed and surfaced even when the helper returns 0
        assert r.error == "dump has no managed runtime"

    def test_helper_nonzero_no_stdout(self, tmp_path):
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            return_value=_completed(returncode=2, stdout="", stderr="usage err"),
        ):
            r = analyze_dump(dump, helper_path=helper)
        assert r.backend == "clrmd"
        assert "exited 2" in (r.error or "")
        assert "usage err" in (r.error or "")

    def test_helper_stdout_not_json(self, tmp_path):
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            return_value=_completed(stdout="not-json"),
        ):
            r = analyze_dump(dump, helper_path=helper)
        assert r.backend == "clrmd"
        assert "not JSON" in (r.error or "")

    def test_helper_timeout(self, tmp_path):
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1.0),
        ):
            r = analyze_dump(dump, helper_path=helper, timeout_sec=1.0)
        assert r.backend == "clrmd"
        assert "timed out" in (r.error or "")

    def test_helper_oserror(self, tmp_path):
        helper = tmp_path / "dump-analyzer.exe"
        helper.write_bytes(b"mock")
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            side_effect=OSError("denied"),
        ):
            r = analyze_dump(dump, helper_path=helper)
        assert r.backend == "clrmd"
        assert "denied" in (r.error or "")


class TestAnalyzeDumpFallback:
    """When the helper isn't built, fall back to dotnet-dump."""

    def test_falls_back_to_dotnet_dump_when_helper_missing(self, tmp_path):
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        # Synthetic clrstack output
        clrstack = (
            "OS Thread Id: 0x3210 (1)\n"
            "        Child SP               IP Call Site\n"
            "000000a3b25fea90 00007ffd91234567 Hermes.Parser.DicomReader.ReadSequence(System.IO.Stream, Int32)\n"
            "000000a3b25feb20 00007ffd91234abc Hermes.Parser.DicomReader.ReadSequence(System.IO.Stream, Int32)\n"
        )
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            return_value=_completed(stdout=clrstack),
        ) as run_mock:
            r = analyze_dump(
                dump,
                helper_path=tmp_path / "missing.exe",
                dotnet_dump="C:/tools/dotnet-dump.exe",
            )
        # Ensure we actually called dotnet-dump, not the helper
        cmd = run_mock.call_args.args[0]
        assert cmd[0] == "C:/tools/dotnet-dump.exe"
        assert "analyze" in cmd
        assert r.backend == "dotnet-dump"
        assert r.error is None
        assert len(r.frames) == 2
        assert r.frames[0].method == "ReadSequence"
        # No module name from clrstack output (load-bearing for Phase 3 cluster)
        assert r.frames[0].module is None
        assert r.frames[0].md_token is None
        # IP is preserved
        assert r.frames[0].ip_hex == "0x00007ffd91234567"

    def test_no_backend_available(self, tmp_path):
        """Helper missing AND no dotnet-dump on PATH -> clear error."""
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.shutil.which", return_value=None
        ):
            r = analyze_dump(dump, helper_path=tmp_path / "missing.exe")
        assert r.backend == "none"
        assert "no stack-trace backend" in (r.error or "")
        assert "build.ps1" in (r.error or "")
        assert "dotnet-dump" in (r.error or "")

    def test_dotnet_dump_nonzero_exit(self, tmp_path):
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            return_value=_completed(returncode=1, stderr="bad dump"),
        ):
            r = analyze_dump(
                dump,
                helper_path=tmp_path / "missing.exe",
                dotnet_dump="C:/tools/dotnet-dump.exe",
            )
        assert r.backend == "dotnet-dump"
        assert "exited 1" in (r.error or "")
        assert "bad dump" in (r.error or "")

    def test_dotnet_dump_no_parsable_frames(self, tmp_path):
        dump = tmp_path / "in.dmp"
        dump.write_bytes(b"d")
        with patch(
            "dicom_fuzzer.core.crash.dump_analyzer.subprocess.run",
            return_value=_completed(stdout="unrelated diagnostic blurb\n"),
        ):
            r = analyze_dump(
                dump,
                helper_path=tmp_path / "missing.exe",
                dotnet_dump="C:/tools/dotnet-dump.exe",
            )
        assert r.backend == "dotnet-dump"
        assert "no parsable frames" in (r.error or "")
        assert r.frames == []


class TestParsers:
    """Unit tests for the small parsing helpers, since they carry the
    fragile bits of the dotnet-dump fallback."""

    def test_split_call_site_namespaced(self):
        mod, typ, meth = _split_call_site("Hermes.Parser.DicomReader.ReadSequence(x)")
        assert mod is None
        assert typ == "Hermes.Parser.DicomReader"
        assert meth == "ReadSequence"

    def test_split_call_site_bare_method(self):
        mod, typ, meth = _split_call_site("Main()")
        assert mod is None
        assert typ is None
        assert meth == "Main"

    def test_parse_clrstack_skips_until_header(self):
        output = (
            "junk before header\n"
            "OS Thread Id: 0x1 (1)\n"
            "    Child SP               IP Call Site\n"
            "00000001 00007ff111111111 Some.Type.Method()\n"
        )
        frames = _parse_clrstack_output(output)
        assert len(frames) == 1
        assert frames[0].method == "Method"
        assert frames[0].type == "Some.Type"

    def test_parse_clrstack_resets_on_new_thread(self):
        """clrstack -all emits one block per thread; we keep frames
        from each (no per-thread filtering at parse time -- Phase 3
        deals with thread selection)."""
        output = (
            "OS Thread Id: 0x1 (1)\n"
            "    Child SP               IP Call Site\n"
            "00000001 00007ff111111111 A.X()\n"
            "\n"
            "OS Thread Id: 0x2 (2)\n"
            "    Child SP               IP Call Site\n"
            "00000002 00007ff222222222 B.Y()\n"
        )
        frames = _parse_clrstack_output(output)
        assert [f.method for f in frames] == ["X", "Y"]


class TestResultFromHelperDoc:
    """Defensive: the C# helper might add fields in future schema bumps."""

    def test_handles_unknown_fields_gracefully(self):
        doc = dict(HELPER_OK_DOC, future_field="ignored")
        r = _result_from_helper_doc(doc, backend="clrmd")
        assert r.schema_version == 1
        assert len(r.frames) == 2

    def test_handles_missing_exception(self):
        doc = dict(HELPER_OK_DOC, exception=None)
        r = _result_from_helper_doc(doc, backend="clrmd")
        assert r.exception is None

    def test_handles_missing_frames(self):
        doc = dict(HELPER_OK_DOC, frames=None)
        r = _result_from_helper_doc(doc, backend="clrmd")
        assert r.frames == []


def test_default_helper_path_is_relative_to_repo():
    """The default helper path matches build.ps1's publish output, so
    a vanilla 'analyze_dump(...)' call works after running build.ps1
    from any cwd inside the repo."""
    from dicom_fuzzer.core.crash.dump_analyzer import _DEFAULT_HELPER

    parts = _DEFAULT_HELPER.parts
    assert "tools" in parts
    assert "dump-analyzer" in parts
    assert parts[-1] == "dump-analyzer.exe"
