"""Tests for the install-stack-trace ClrMD DLL fetcher."""

from __future__ import annotations

import hashlib
import io
import zipfile
from unittest.mock import patch

from dicom_fuzzer.cli.commands import install_stack_trace as ist


def _make_nupkg(dll_bytes: bytes) -> bytes:
    """Build a tiny in-memory .nupkg zip containing the expected layout."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(ist._DLL_PATH_IN_NUPKG, dll_bytes)
    return buf.getvalue()


class TestInstallStackTrace:
    def test_downloads_extracts_and_writes(self, tmp_path, monkeypatch, capsys):
        dll_bytes = b"MZ" + b"\x00" * 10_000
        nupkg = _make_nupkg(dll_bytes)
        target = tmp_path / "Microsoft.Diagnostics.Runtime.dll"
        monkeypatch.setattr(ist, "_TARGET_DLL", target)
        monkeypatch.setattr(ist, "CLRMD_SHA256", None)  # no pin, accept any

        fake_resp = patch(
            "dicom_fuzzer.cli.commands.install_stack_trace.urllib.request.urlopen",
        )
        with fake_resp as m:
            m.return_value.__enter__.return_value.read.return_value = nupkg
            rc = ist.main([])
        assert rc == 0
        assert target.exists()
        assert target.read_bytes() == dll_bytes
        out = capsys.readouterr().out
        assert "Installed" in out

    def test_no_op_when_dll_already_present_and_matching(
        self, tmp_path, monkeypatch, capsys
    ):
        dll_bytes = b"MZ" + b"\x00" * 10_000
        digest = hashlib.sha256(dll_bytes).hexdigest()
        target = tmp_path / "exists.dll"
        target.write_bytes(dll_bytes)
        monkeypatch.setattr(ist, "_TARGET_DLL", target)
        monkeypatch.setattr(ist, "CLRMD_SHA256", digest)

        # urlopen must NOT be called
        with patch(
            "dicom_fuzzer.cli.commands.install_stack_trace.urllib.request.urlopen",
        ) as m:
            rc = ist.main([])
        assert rc == 0
        assert m.call_count == 0
        out = capsys.readouterr().out
        assert "checksum OK" in out

    def test_refetches_on_force_even_when_match(self, tmp_path, monkeypatch):
        dll_bytes = b"MZ" + b"\x00" * 10_000
        target = tmp_path / "exists.dll"
        target.write_bytes(dll_bytes)
        monkeypatch.setattr(ist, "_TARGET_DLL", target)
        monkeypatch.setattr(ist, "CLRMD_SHA256", None)

        nupkg = _make_nupkg(dll_bytes)
        with patch(
            "dicom_fuzzer.cli.commands.install_stack_trace.urllib.request.urlopen",
        ) as m:
            m.return_value.__enter__.return_value.read.return_value = nupkg
            rc = ist.main(["--force"])
        assert rc == 0
        assert m.call_count == 1

    def test_rejects_checksum_mismatch_from_nuget(self, tmp_path, monkeypatch, capsys):
        dll_bytes = b"MZ" + b"\x00" * 10_000
        target = tmp_path / "out.dll"
        monkeypatch.setattr(ist, "_TARGET_DLL", target)
        # Pin a hash that won't match
        monkeypatch.setattr(ist, "CLRMD_SHA256", "0" * 64)

        with patch(
            "dicom_fuzzer.cli.commands.install_stack_trace.urllib.request.urlopen",
        ) as m:
            m.return_value.__enter__.return_value.read.return_value = _make_nupkg(
                dll_bytes
            )
            rc = ist.main([])
        assert rc == 1
        assert not target.exists()
        out = capsys.readouterr().out
        assert "checksum mismatch" in out

    def test_download_failure_returns_error(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(ist, "_TARGET_DLL", tmp_path / "out.dll")
        with patch(
            "dicom_fuzzer.cli.commands.install_stack_trace.urllib.request.urlopen",
            side_effect=Exception("network down"),
        ):
            rc = ist.main([])
        assert rc == 1
        out = capsys.readouterr().out
        assert "download failed" in out
