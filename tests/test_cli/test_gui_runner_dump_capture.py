"""Tests for the DOTNET_DbgEnableMiniDump capture path in GUITargetRunner.

These tests cover the new ``dump_dir`` plumbing: env-var construction,
dump-dir snapshotting, and attribution of new .dmp files to the test
that produced them. The Popen call is mocked so no real process is
launched.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

psutil = pytest.importorskip("psutil")

from dicom_fuzzer.cli.utils.gui_runner import GUITargetRunner  # noqa: E402


@pytest.fixture
def fake_target(tmp_path: Path) -> Path:
    """A stand-in for the target binary (just any existing file)."""
    p = tmp_path / "fake_target.exe"
    p.write_bytes(b"exe")
    return p


class TestEnvBuilding:
    def test_no_dump_dir_returns_none(self, fake_target):
        runner = GUITargetRunner(str(fake_target))
        assert runner._build_target_env() is None

    def test_with_dump_dir_sets_dotnet_dbg_vars(self, fake_target, tmp_path):
        dump_dir = tmp_path / "dumps"
        runner = GUITargetRunner(str(fake_target), dump_dir=str(dump_dir))
        env = runner._build_target_env()
        assert env is not None
        assert env["DOTNET_DbgEnableMiniDump"] == "1"
        assert env["DOTNET_DbgMiniDumpType"] == "2"
        # Template should include %p / %t for createdump to substitute
        assert "%p" in env["DOTNET_DbgMiniDumpName"]
        assert "%t" in env["DOTNET_DbgMiniDumpName"]
        # Path should be under our dump_dir
        assert str(dump_dir.resolve()) in env["DOTNET_DbgMiniDumpName"]

    def test_inherits_existing_environment(self, fake_target, tmp_path, monkeypatch):
        dump_dir = tmp_path / "dumps"
        monkeypatch.setenv("MY_CUSTOM_VAR", "value123")
        runner = GUITargetRunner(str(fake_target), dump_dir=str(dump_dir))
        env = runner._build_target_env()
        assert env["MY_CUSTOM_VAR"] == "value123"


class TestSnapshotting:
    def test_snapshot_returns_empty_set_when_no_dump_dir(self, fake_target):
        runner = GUITargetRunner(str(fake_target))
        assert runner._snapshot_dump_dir() == set()

    def test_snapshot_returns_existing_dmps(self, fake_target, tmp_path):
        dump_dir = tmp_path / "dumps"
        dump_dir.mkdir()
        (dump_dir / "old.dmp").write_bytes(b"x")
        (dump_dir / "stale.dmp").write_bytes(b"y")
        (dump_dir / "noise.txt").write_text("not a dump")
        runner = GUITargetRunner(str(fake_target), dump_dir=str(dump_dir))
        snap = runner._snapshot_dump_dir()
        names = {p.name for p in snap}
        assert names == {"old.dmp", "stale.dmp"}


class TestAttribution:
    def test_no_new_dumps_returns_none(self, fake_target, tmp_path):
        dump_dir = tmp_path / "dumps"
        dump_dir.mkdir()
        (dump_dir / "old.dmp").write_bytes(b"x")
        runner = GUITargetRunner(str(fake_target), dump_dir=str(dump_dir))
        pre = runner._snapshot_dump_dir()
        # Nothing happens in between
        assert runner._attribute_new_dump(pre) is None

    def test_single_new_dump_attributed(self, fake_target, tmp_path):
        dump_dir = tmp_path / "dumps"
        dump_dir.mkdir()
        runner = GUITargetRunner(str(fake_target), dump_dir=str(dump_dir))
        pre = runner._snapshot_dump_dir()
        new = dump_dir / "hermes.1234.5678.dmp"
        new.write_bytes(b"d")
        attributed = runner._attribute_new_dump(pre)
        assert attributed == str(new)

    def test_picks_newest_when_multiple_new_dumps(self, fake_target, tmp_path):
        dump_dir = tmp_path / "dumps"
        dump_dir.mkdir()
        runner = GUITargetRunner(str(fake_target), dump_dir=str(dump_dir))
        pre = runner._snapshot_dump_dir()
        first = dump_dir / "first.dmp"
        first.write_bytes(b"f")
        # Make sure the second has a later mtime than the first
        old = first.stat().st_mtime
        os.utime(first, (old - 10, old - 10))
        second = dump_dir / "second.dmp"
        second.write_bytes(b"s")
        attributed = runner._attribute_new_dump(pre)
        assert attributed == str(second)


class TestExecuteTestPlumbsDumpPath:
    def test_dump_path_populated_on_crash(self, fake_target, tmp_path, monkeypatch):
        """End-to-end: when target 'crashes' and a new .dmp appears,
        the result's dump_path points at it."""
        dump_dir = tmp_path / "dumps"
        dump_dir.mkdir()
        runner = GUITargetRunner(
            str(fake_target),
            dump_dir=str(dump_dir),
            startup_delay=0.0,
            timeout=5.0,
        )

        # Fake Popen that simulates a crash and writes a dump
        fake_proc = MagicMock(spec=subprocess.Popen)
        fake_proc.pid = 9999
        fake_proc.poll = MagicMock(return_value=-1073741819)  # 0xC0000005 AV
        fake_proc.communicate = MagicMock(return_value=(b"", b""))

        def fake_popen(*args, **kwargs):
            # Simulate createdump producing a file as Popen launches
            (dump_dir / "hermes.9999.123.dmp").write_bytes(b"dmp")
            return fake_proc

        monkeypatch.setattr("subprocess.Popen", fake_popen)
        # Mock memory check to keep the loop short
        monkeypatch.setattr(runner, "_check_memory", lambda _proc: (10.0, False))
        # Avoid trying to kill the fake proc
        monkeypatch.setattr(runner, "_kill_process_tree", lambda _proc: None)

        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"dicom")
        result = runner.execute_test(test_file)

        assert result.crashed is True
        assert result.dump_path is not None
        assert result.dump_path.endswith("hermes.9999.123.dmp")

    def test_dump_path_none_when_no_crash(self, fake_target, tmp_path, monkeypatch):
        dump_dir = tmp_path / "dumps"
        dump_dir.mkdir()
        runner = GUITargetRunner(
            str(fake_target),
            dump_dir=str(dump_dir),
            startup_delay=0.0,
            timeout=0.5,  # Will time out without crashing
        )

        fake_proc = MagicMock(spec=subprocess.Popen)
        fake_proc.pid = 9998
        fake_proc.poll = MagicMock(return_value=None)  # Still running
        fake_proc.communicate = MagicMock(return_value=(b"", b""))
        monkeypatch.setattr("subprocess.Popen", lambda *a, **k: fake_proc)
        monkeypatch.setattr(runner, "_check_memory", lambda _proc: (10.0, False))
        monkeypatch.setattr(runner, "_kill_process_tree", lambda _proc: None)

        test_file = tmp_path / "test.dcm"
        test_file.write_bytes(b"dicom")
        result = runner.execute_test(test_file)

        # Timeout != crash for GUI runners; no dump expected
        assert result.crashed is False
        assert result.timed_out is True
        assert result.dump_path is None
