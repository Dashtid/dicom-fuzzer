"""Unit tests for the pythonnet-backed dump analyzer.

These tests don't load pythonnet or .NET at all — they monkeypatch the
init function and the ClrMD-walk function so the dataclass plumbing,
error handling, and public API can be verified on any platform.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from dicom_fuzzer.core.crash import dump_analyzer
from dicom_fuzzer.core.crash.dump_analyzer import (
    ExceptionInfo,
    StackFrame,
    StackResult,
    _to_frame,
    analyze_dump,
)


@pytest.fixture(autouse=True)
def _reset_init():
    """Clear the module-level init cache between tests."""
    dump_analyzer._reset_for_tests()
    yield
    dump_analyzer._reset_for_tests()


class TestDataclassShape:
    def test_stack_result_defaults(self):
        r = StackResult(backend="clrmd")
        assert r.frames == []
        assert r.exception is None
        assert r.error is None
        assert r.schema_version == dump_analyzer.SCHEMA_VERSION

    def test_to_json_roundtrips(self):
        r = StackResult(
            backend="clrmd",
            dump_path="C:/x.dmp",
            exception=ExceptionInfo(
                code_hex="0xC00000FD",
                name="STACK_OVERFLOW",
                address_hex="0x0",
            ),
            frames=[
                StackFrame(
                    is_managed=True,
                    module="Hermes.exe",
                    type="Parser",
                    method="ReadSeq",
                    signature="ReadSeq()",
                    md_token="0x06000123",  # noqa: S106 -- .NET MethodDef token, not a secret
                    il_offset_hex="0x4a",
                    ip_hex="0x7ffd91234567",
                )
            ],
        )
        doc = json.loads(r.to_json())
        assert doc["backend"] == "clrmd"
        assert doc["frames"][0]["method"] == "ReadSeq"
        assert doc["exception"]["name"] == "STACK_OVERFLOW"


class TestAnalyzeDumpDispatch:
    def test_missing_dump_returns_error_no_init(self, tmp_path, monkeypatch):
        called = []
        monkeypatch.setattr(
            dump_analyzer,
            "_ensure_clrmd_ready",
            lambda: called.append("init") or True,
        )
        result = analyze_dump(tmp_path / "does_not_exist.dmp")
        assert result.backend == "none"
        assert "not found" in (result.error or "")
        # Init should NOT have been called — short-circuit on missing dump
        assert called == []

    def test_init_failure_surfaces_error(self, tmp_path, monkeypatch):
        dump = tmp_path / "fake.dmp"
        dump.write_bytes(b"fake")
        monkeypatch.setattr(dump_analyzer, "_ensure_clrmd_ready", lambda: False)
        monkeypatch.setattr(dump_analyzer, "_init_error", "pythonnet missing")
        result = analyze_dump(dump)
        assert result.backend == "none"
        assert result.error == "pythonnet missing"
        assert result.dump_path == str(dump)

    def test_init_success_calls_walker(self, tmp_path, monkeypatch):
        dump = tmp_path / "fake.dmp"
        dump.write_bytes(b"fake")
        fake_result = StackResult(
            backend="clrmd",
            dump_path=str(dump),
            frames=[
                StackFrame(
                    is_managed=True,
                    module="Hermes.exe",
                    type="X",
                    method="Y",
                    signature=None,
                    md_token=None,
                    il_offset_hex=None,
                    ip_hex="0x1",
                )
            ],
        )
        monkeypatch.setattr(dump_analyzer, "_ensure_clrmd_ready", lambda: True)
        monkeypatch.setattr(dump_analyzer, "_walk_with_clrmd", lambda d: fake_result)
        assert analyze_dump(dump) is fake_result


class TestEnsureClrmdReady:
    def test_pythonnet_import_failure_caches(self, monkeypatch):
        # Force ImportError by injecting a None entry for `pythonnet`
        import sys

        monkeypatch.setitem(sys.modules, "pythonnet", None)
        assert dump_analyzer._ensure_clrmd_ready() is False
        # Second call hits the cache, returns the same answer
        assert dump_analyzer._ensure_clrmd_ready() is False
        assert "pythonnet" in (dump_analyzer._init_error or "")

    def test_missing_dll_returns_false(self, monkeypatch, tmp_path):
        fake_pythonnet = MagicMock()
        fake_pythonnet.load = MagicMock()
        import sys

        monkeypatch.setitem(sys.modules, "pythonnet", fake_pythonnet)
        # Point the DLL constant at a non-existent file
        monkeypatch.setattr(dump_analyzer, "_CLRMD_DLL", tmp_path / "nope.dll")
        assert dump_analyzer._ensure_clrmd_ready() is False
        assert "DLL not vendored" in (dump_analyzer._init_error or "")


class TestFrameConversion:
    def test_native_frame(self):
        clr_frame = MagicMock()
        clr_frame.Method = None
        clr_frame.ModuleName = "kernel32.dll"
        clr_frame.InstructionPointer = 0x7FFD12345678
        f = _to_frame(clr_frame)
        assert f.is_managed is False
        assert f.module == "kernel32.dll"
        assert f.method is None
        assert f.ip_hex.startswith("0x")

    def test_managed_frame_with_metadata(self):
        clr_frame = MagicMock()
        clr_frame.ModuleName = None
        clr_frame.InstructionPointer = 0x1234
        method = MagicMock()
        method.Name = "ReadSequence"
        method.MetadataToken = 0x06000123
        method.Signature = "ReadSequence(System.IO.Stream)"
        # GetILOffset is a real method on ClrMethod; mock it to return 0x4a
        method.GetILOffset = MagicMock(return_value=0x4A)
        type_obj = MagicMock()
        type_obj.Name = "Hermes.Parser.DicomReader"
        module_obj = MagicMock()
        module_obj.Name = "C:/Hermes/Affinity/Hermes.exe"
        type_obj.Module = module_obj
        method.Type = type_obj
        clr_frame.Method = method

        f = _to_frame(clr_frame)
        assert f.is_managed is True
        assert f.module == "Hermes.exe"
        assert f.type == "Hermes.Parser.DicomReader"
        assert f.method == "ReadSequence"
        assert f.md_token == "0x06000123"
        assert f.il_offset_hex == "0x4A"

    def test_managed_frame_il_offset_handles_failure(self):
        clr_frame = MagicMock()
        clr_frame.ModuleName = "Hermes.exe"
        clr_frame.InstructionPointer = 0x1234
        method = MagicMock()
        method.Name = "Foo"
        method.MetadataToken = 0
        method.GetILOffset = MagicMock(side_effect=RuntimeError("symbol miss"))
        method.Type = None
        clr_frame.Method = method

        f = _to_frame(clr_frame)
        assert f.is_managed is True
        assert f.il_offset_hex is None
