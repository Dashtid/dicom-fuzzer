"""Unit tests for createdump.exe discovery + invocation."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from dicom_fuzzer.core.crash import createdump as cd


class TestFindCreatedump:
    def test_returns_none_on_non_windows(self, monkeypatch):
        monkeypatch.setattr(cd.os, "name", "posix")
        assert cd.find_createdump() is None

    def test_returns_none_when_no_runtime_present(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cd.os, "name", "nt")
        # Point both candidates at empty/nonexistent dirs
        monkeypatch.setattr(
            cd,
            "_PROGRAM_FILES_CANDIDATES",
            (str(tmp_path / "nope1"), str(tmp_path / "nope2")),
        )
        assert cd.find_createdump() is None

    def test_picks_newest_version_when_multiple_present(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cd.os, "name", "nt")
        base = tmp_path / "dotnet"
        (base / "8.0.0").mkdir(parents=True)
        (base / "8.0.5").mkdir(parents=True)
        (base / "6.0.27").mkdir(parents=True)
        for ver in ("8.0.0", "8.0.5", "6.0.27"):
            (base / ver / "createdump.exe").write_bytes(b"MZ")
        monkeypatch.setattr(cd, "_PROGRAM_FILES_CANDIDATES", (str(base),))
        result = cd.find_createdump()
        assert result is not None
        assert result.parent.name == "8.0.5"

    def test_skips_files_in_version_dir_root(self, monkeypatch, tmp_path):
        """Loose files (non-dirs) under Microsoft.NETCore.App should be ignored."""
        monkeypatch.setattr(cd.os, "name", "nt")
        base = tmp_path / "dotnet"
        base.mkdir()
        (base / "noise.txt").write_text("not a version dir")
        (base / "8.0.5").mkdir()
        (base / "8.0.5" / "createdump.exe").write_bytes(b"MZ")
        monkeypatch.setattr(cd, "_PROGRAM_FILES_CANDIDATES", (str(base),))
        result = cd.find_createdump()
        assert result is not None
        assert result.parent.name == "8.0.5"

    def test_handles_non_numeric_version_dirs(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cd.os, "name", "nt")
        base = tmp_path / "dotnet"
        (base / "8.0.5").mkdir(parents=True)
        (base / "preview-something").mkdir(parents=True)
        (base / "8.0.5" / "createdump.exe").write_bytes(b"MZ")
        (base / "preview-something" / "createdump.exe").write_bytes(b"MZ")
        monkeypatch.setattr(cd, "_PROGRAM_FILES_CANDIDATES", (str(base),))
        # Should not crash, should prefer the numeric version
        result = cd.find_createdump()
        assert result is not None
        assert result.parent.name == "8.0.5"


class TestCaptureDump:
    def test_returns_failure_when_no_createdump_available(self, monkeypatch, tmp_path):
        monkeypatch.setattr(cd, "find_createdump", lambda: None)
        ok, err = cd.capture_dump(1234, tmp_path / "out.dmp")
        assert ok is False
        assert "not found" in (err or "")

    def test_invokes_createdump_with_correct_args(self, monkeypatch, tmp_path):
        fake_exe = tmp_path / "createdump.exe"
        fake_exe.write_bytes(b"MZ")
        out = tmp_path / "out.dmp"

        # Simulate createdump writing the file
        def fake_run(cmd, **kwargs):
            Path(cmd[cmd.index("-f") + 1]).write_bytes(b"dump")
            proc = MagicMock()
            proc.returncode = 0
            proc.stdout = ""
            proc.stderr = ""
            return proc

        monkeypatch.setattr(cd, "find_createdump", lambda: fake_exe)
        with patch.object(cd.subprocess, "run", side_effect=fake_run) as mock_run:
            ok, err = cd.capture_dump(4242, out)
        assert ok is True
        assert err is None
        assert out.is_file()
        # Inspect the constructed command
        called_cmd = mock_run.call_args[0][0]
        assert str(fake_exe) in called_cmd
        assert "-f" in called_cmd
        assert "--withheap" in called_cmd
        assert "4242" in called_cmd

    def test_full_heap_false_uses_normal_flag(self, monkeypatch, tmp_path):
        fake_exe = tmp_path / "createdump.exe"
        fake_exe.write_bytes(b"MZ")
        out = tmp_path / "out.dmp"

        def fake_run(cmd, **kwargs):
            Path(cmd[cmd.index("-f") + 1]).write_bytes(b"d")
            proc = MagicMock()
            proc.returncode = 0
            proc.stdout = ""
            proc.stderr = ""
            return proc

        monkeypatch.setattr(cd, "find_createdump", lambda: fake_exe)
        with patch.object(cd.subprocess, "run", side_effect=fake_run) as mock_run:
            cd.capture_dump(4242, out, full_heap=False)
        called_cmd = mock_run.call_args[0][0]
        assert "--normal" in called_cmd
        assert "--withheap" not in called_cmd

    def test_returns_failure_on_nonzero_exit(self, monkeypatch, tmp_path):
        fake_exe = tmp_path / "createdump.exe"
        fake_exe.write_bytes(b"MZ")
        monkeypatch.setattr(cd, "find_createdump", lambda: fake_exe)
        proc = MagicMock(returncode=3, stdout="", stderr="some error")
        with patch.object(cd.subprocess, "run", return_value=proc):
            ok, err = cd.capture_dump(4242, tmp_path / "out.dmp")
        assert ok is False
        assert "exited 3" in (err or "")

    def test_returns_failure_on_timeout(self, monkeypatch, tmp_path):
        fake_exe = tmp_path / "createdump.exe"
        fake_exe.write_bytes(b"MZ")
        monkeypatch.setattr(cd, "find_createdump", lambda: fake_exe)
        with patch.object(
            cd.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="x", timeout=5),
        ):
            ok, err = cd.capture_dump(4242, tmp_path / "out.dmp", timeout_sec=5)
        assert ok is False
        assert "timed out" in (err or "")

    def test_returns_failure_when_dump_file_missing(self, monkeypatch, tmp_path):
        """createdump can exit 0 yet not actually write the file (weird)."""
        fake_exe = tmp_path / "createdump.exe"
        fake_exe.write_bytes(b"MZ")
        monkeypatch.setattr(cd, "find_createdump", lambda: fake_exe)
        proc = MagicMock(returncode=0, stdout="ok", stderr="")
        with patch.object(cd.subprocess, "run", return_value=proc):
            ok, err = cd.capture_dump(4242, tmp_path / "out.dmp")
        assert ok is False
        assert "not present" in (err or "")
