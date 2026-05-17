"""Tests for the check-stack-trace pre-flight subcommand."""

from __future__ import annotations

import sys
from pathlib import Path

from dicom_fuzzer.cli.commands.check_stack_trace import main


def _write_pe_blob(path: Path, size: int = 200_000) -> None:
    """Write a fake but PE-magic-passing DLL file at the given size."""
    path.write_bytes(b"MZ" + b"\x00" * (size - 2))


class TestPythonnetCheck:
    def test_missing_pythonnet_returns_failure(self, capsys, monkeypatch):
        monkeypatch.setitem(sys.modules, "pythonnet", None)
        rc = main([])
        out = capsys.readouterr().out
        assert rc == 1
        assert "pythonnet: NOT INSTALLED" in out

    def test_pythonnet_present_does_not_fail_alone(self, capsys, monkeypatch, tmp_path):
        # Stub pythonnet as importable
        import types

        fake_pythonnet = types.ModuleType("pythonnet")
        monkeypatch.setitem(sys.modules, "pythonnet", fake_pythonnet)
        # And give it valid DLL + createdump
        dll = tmp_path / "Microsoft.Diagnostics.Runtime.dll"
        _write_pe_blob(dll)
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_stack_trace._CLRMD_DLL", dll
        )
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_stack_trace.find_createdump",
            lambda: Path("C:/dotnet/createdump.exe"),
        )
        rc = main([])
        out = capsys.readouterr().out
        assert rc == 0
        assert "All checks passed" in out


class TestClrmdDllCheck:
    def test_missing_dll(self, capsys, monkeypatch, tmp_path):
        import types

        monkeypatch.setitem(sys.modules, "pythonnet", types.ModuleType("pythonnet"))
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_stack_trace._CLRMD_DLL",
            tmp_path / "doesnt_exist.dll",
        )
        rc = main([])
        out = capsys.readouterr().out
        assert rc == 1
        assert "ClrMD DLL: NOT FOUND" in out

    def test_dll_too_small(self, capsys, monkeypatch, tmp_path):
        import types

        monkeypatch.setitem(sys.modules, "pythonnet", types.ModuleType("pythonnet"))
        dll = tmp_path / "tiny.dll"
        _write_pe_blob(dll, size=500)  # under threshold
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_stack_trace._CLRMD_DLL", dll
        )
        rc = main([])
        out = capsys.readouterr().out
        assert rc == 1
        assert "suspiciously small" in out

    def test_dll_missing_pe_magic(self, capsys, monkeypatch, tmp_path):
        import types

        monkeypatch.setitem(sys.modules, "pythonnet", types.ModuleType("pythonnet"))
        dll = tmp_path / "junk.dll"
        dll.write_bytes(b"XX" + b"\x00" * 200_000)  # no MZ
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_stack_trace._CLRMD_DLL", dll
        )
        rc = main([])
        out = capsys.readouterr().out
        assert rc == 1
        assert "not a PE file" in out


class TestCreatedumpCheck:
    def test_no_createdump_returns_failure(self, capsys, monkeypatch, tmp_path):
        import types

        monkeypatch.setitem(sys.modules, "pythonnet", types.ModuleType("pythonnet"))
        dll = tmp_path / "ok.dll"
        _write_pe_blob(dll)
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_stack_trace._CLRMD_DLL", dll
        )
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.check_stack_trace.find_createdump",
            lambda: None,
        )
        rc = main([])
        out = capsys.readouterr().out
        assert rc == 1
        assert "createdump.exe: NOT FOUND" in out


class TestDispatcher:
    def test_subcommand_is_registered(self):
        from dicom_fuzzer.cli.main import SUBCOMMANDS

        assert SUBCOMMANDS["check-stack-trace"] == (
            "dicom_fuzzer.cli.commands.check_stack_trace"
        )
        assert SUBCOMMANDS["install-stack-trace"] == (
            "dicom_fuzzer.cli.commands.install_stack_trace"
        )
