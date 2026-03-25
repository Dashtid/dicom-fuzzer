"""Tests for the replay CLI subcommand."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pydicom
from pydicom.dataset import Dataset, FileDataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid

from dicom_fuzzer.cli.commands.replay import _find_session, main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_minimal_dcm(path: Path) -> Path:
    """Write a minimal valid DICOM file to *path*."""
    file_meta = pydicom.dataset.FileMetaDataset()
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = generate_uid()
    file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    file_meta.ImplementationClassUID = generate_uid()

    ds = FileDataset(str(path), {}, file_meta=file_meta, preamble=b"\x00" * 128)
    ds.PatientName = "Test^Patient"
    ds.PatientID = "123"
    ds.StudyInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.Modality = "CT"
    ds.save_as(str(path), write_like_original=False)
    return path


def _make_session(
    source_path: Path,
    output_path: Path,
    mutations: list[dict],
    crashes: list[dict] | None = None,
    file_id: str = "file_001",
) -> dict:
    return {
        "session_id": "sess_test",
        "fuzzed_files": [
            {
                "file_id": file_id,
                "source_file": str(source_path),
                "output_file": str(output_path),
                "timestamp": datetime.now(UTC).isoformat(),
                "mutations": mutations,
            }
        ],
        "crashes": crashes or [],
    }


def _fake_registry(methods: dict[str, list[str]]) -> dict:
    """Build a fake strategy registry where each strategy exposes listed methods.

    Each method records its name in a shared call_log and returns ds unchanged.
    """
    call_log: list[str] = []

    registry: dict = {}
    for strategy_name, method_names in methods.items():

        class FakeStrategy:
            pass

        FakeStrategy.strategy_name = strategy_name  # type: ignore[attr-defined]
        for mname in method_names:
            # Capture loop variable
            def _make_method(name: str):
                def _method(self, ds: Dataset) -> Dataset:
                    call_log.append(name)
                    return ds

                _method.__name__ = name
                return _method

            setattr(FakeStrategy, mname, _make_method(mname))

        def _make_mutate(names: list[str]):
            def mutate(self, ds: Dataset) -> Dataset:
                call_log.append("mutate")
                return ds

            return mutate

        FakeStrategy.mutate = _make_mutate(method_names)  # type: ignore[attr-defined]
        registry[strategy_name] = FakeStrategy()

    registry["_call_log"] = call_log  # expose for assertions
    return registry


# ---------------------------------------------------------------------------
# TestDecomposeCreatesOutputDir
# ---------------------------------------------------------------------------


class TestDecomposeCreatesOutputDir:
    def test_creates_nested_output_dir(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")
        output_dir = tmp_path / "decomposed" / "nested"

        session_data = _make_session(
            source,
            fuzzed,
            [{"strategy_name": "encoding", "variant": "_null_byte_injection"}],
        )
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: _fake_registry({"encoding": ["_null_byte_injection"]}),
        )

        result = main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        assert result == 0
        assert output_dir.exists()


# ---------------------------------------------------------------------------
# TestDecomposeFilePerMethod
# ---------------------------------------------------------------------------


class TestDecomposeFilePerMethod:
    def test_two_methods_produce_two_files(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")
        output_dir = tmp_path / "out"

        session_data = _make_session(
            source,
            fuzzed,
            [
                {
                    "strategy_name": "encoding",
                    "variant": "_null_byte_injection,_overlong_utf8",
                }
            ],
        )
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        registry = _fake_registry(
            {"encoding": ["_null_byte_injection", "_overlong_utf8"]}
        )
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: registry,
        )

        result = main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        assert result == 0
        dcm_files = list(output_dir.glob("*.dcm"))
        assert len(dcm_files) == 2

    def test_methods_in_call_log(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")
        output_dir = tmp_path / "out"

        session_data = _make_session(
            source,
            fuzzed,
            [
                {
                    "strategy_name": "encoding",
                    "variant": "_null_byte_injection,_overlong_utf8",
                }
            ],
        )
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        registry = _fake_registry(
            {"encoding": ["_null_byte_injection", "_overlong_utf8"]}
        )
        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: registry,
        )

        main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        assert "_null_byte_injection" in registry["_call_log"]
        assert "_overlong_utf8" in registry["_call_log"]


# ---------------------------------------------------------------------------
# TestDecomposeOutputFilenameFormat
# ---------------------------------------------------------------------------


class TestDecomposeOutputFilenameFormat:
    def test_filename_contains_stem_strategy_method(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_xyz.dcm")
        output_dir = tmp_path / "out"

        session_data = _make_session(
            source,
            fuzzed,
            [{"strategy_name": "encoding", "variant": "_null_byte_injection"}],
        )
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: _fake_registry({"encoding": ["_null_byte_injection"]}),
        )

        main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        files = list(output_dir.glob("*.dcm"))
        assert len(files) == 1
        name = files[0].name
        assert name.startswith("fuzzed_xyz_mut00_encoding_")
        assert "null_byte_injection" in name
        assert name.endswith(".dcm")

    def test_null_variant_uses_full_suffix(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_xyz.dcm")
        output_dir = tmp_path / "out"

        session_data = _make_session(
            source, fuzzed, [{"strategy_name": "encoding", "variant": None}]
        )
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: _fake_registry({"encoding": []}),
        )

        main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        files = list(output_dir.glob("*.dcm"))
        assert len(files) == 1
        assert files[0].name == "fuzzed_xyz_mut00_encoding_full.dcm"


# ---------------------------------------------------------------------------
# TestDecomposeSourceFileUsedAsSeed
# ---------------------------------------------------------------------------


class TestDecomposeSourceFileUsedAsSeed:
    def test_reads_from_source_not_fuzzed(self, tmp_path, monkeypatch):
        """Source file should be the seed, even if fuzzed file differs."""
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")
        output_dir = tmp_path / "out"

        read_paths: list[str] = []
        real_dcmread = pydicom.dcmread

        def mock_dcmread(path, **kwargs):
            read_paths.append(str(path))
            return real_dcmread(path, **kwargs)

        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay.pydicom.dcmread", mock_dcmread
        )

        session_data = _make_session(
            source,
            fuzzed,
            [{"strategy_name": "encoding", "variant": "_null_byte_injection"}],
        )
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: _fake_registry({"encoding": ["_null_byte_injection"]}),
        )

        main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        assert str(source) in read_paths
        assert str(fuzzed) not in read_paths


# ---------------------------------------------------------------------------
# TestDecomposeUnknownStrategy
# ---------------------------------------------------------------------------


class TestDecomposeUnknownStrategy:
    def test_skips_unknown_strategy_with_warning(self, tmp_path, monkeypatch, capsys):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")
        output_dir = tmp_path / "out"

        session_data = _make_session(
            source,
            fuzzed,
            [{"strategy_name": "nonexistent_strategy", "variant": "_some_method"}],
        )
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: {},  # empty registry
        )

        result = main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        assert result == 0
        captured = capsys.readouterr()
        assert "nonexistent_strategy" in captured.err
        # No files written since strategy was skipped
        assert list(output_dir.glob("*.dcm")) == []


# ---------------------------------------------------------------------------
# TestDecomposeSessionNotFound
# ---------------------------------------------------------------------------


class TestDecomposeSessionNotFound:
    def test_missing_explicit_session_returns_1(self, tmp_path, capsys):
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")

        result = main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(tmp_path / "does_not_exist.json"),
            ]
        )
        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()

    def test_missing_fuzzed_file_returns_1(self, tmp_path, capsys):
        result = main(["--decompose", str(tmp_path / "ghost.dcm")])
        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err.lower()

    def test_record_not_in_session_returns_1(self, tmp_path, capsys, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")
        other_fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_other.dcm")

        # Session records *other_fuzzed*, not *fuzzed*
        session_data = _make_session(source, other_fuzzed, [])
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        result = main(["--decompose", str(fuzzed), "--session", str(session_file)])
        assert result == 1
        captured = capsys.readouterr()
        assert "no record" in captured.err.lower()


# ---------------------------------------------------------------------------
# TestDecomposeReproductionCommand
# ---------------------------------------------------------------------------


class TestDecomposeReproductionCommand:
    def test_populates_reproduction_command(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")
        output_dir = tmp_path / "out"

        crash = {
            "crash_id": "c001",
            "fuzzed_file_id": "file_001",
            "fuzzed_file_path": str(fuzzed),
            "crash_type": "SIGSEGV",
            "severity": "high",
            "timestamp": datetime.now(UTC).isoformat(),
            "reproduction_command": None,
        }
        session_data = _make_session(
            source,
            fuzzed,
            [{"strategy_name": "encoding", "variant": "_null_byte_injection"}],
            crashes=[crash],
        )
        session_file = tmp_path / "session.json"
        session_file.write_text(json.dumps(session_data))

        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: _fake_registry({"encoding": ["_null_byte_injection"]}),
        )

        result = main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        assert result == 0

        updated = json.loads(session_file.read_text())
        cmd = updated["crashes"][0]["reproduction_command"]
        assert cmd is not None
        assert "--decompose" in cmd
        assert fuzzed.name in cmd

    def test_no_matching_crash_does_not_modify_session(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = _make_minimal_dcm(tmp_path / "fuzzed_abc.dcm")
        output_dir = tmp_path / "out"

        crash = {
            "crash_id": "c001",
            "fuzzed_file_id": "different_file_id",  # does not match
            "crash_type": "SIGSEGV",
            "severity": "high",
            "timestamp": datetime.now(UTC).isoformat(),
            "reproduction_command": None,
        }
        session_data = _make_session(
            source,
            fuzzed,
            [{"strategy_name": "encoding", "variant": "_null_byte_injection"}],
            crashes=[crash],
        )
        original_text = json.dumps(session_data)
        session_file = tmp_path / "session.json"
        session_file.write_text(original_text)

        monkeypatch.setattr(
            "dicom_fuzzer.cli.commands.replay._get_strategy_registry",
            lambda: _fake_registry({"encoding": ["_null_byte_injection"]}),
        )

        main(
            [
                "--decompose",
                str(fuzzed),
                "--session",
                str(session_file),
                "--output-dir",
                str(output_dir),
            ]
        )
        # File must not have been rewritten (reproduction_command still None)
        updated = json.loads(session_file.read_text())
        assert updated["crashes"][0]["reproduction_command"] is None


# ---------------------------------------------------------------------------
# TestFindSession
# ---------------------------------------------------------------------------


class TestFindSession:
    def test_explicit_session_path_takes_priority(self, tmp_path):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = tmp_path / "fuzzed_abc.dcm"

        session_data = _make_session(source, fuzzed, [])
        session_file = tmp_path / "explicit.json"
        session_file.write_text(json.dumps(session_data))

        result = _find_session(fuzzed, session_file)
        assert result is not None
        assert result[0] == session_file

    def test_explicit_missing_returns_none(self, tmp_path):
        fuzzed = tmp_path / "fuzzed_abc.dcm"
        result = _find_session(fuzzed, tmp_path / "does_not_exist.json")
        assert result is None

    def test_auto_discover_finds_matching_session(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        fuzzed = tmp_path / "fuzzed_abc.dcm"

        reports_dir = tmp_path / "artifacts" / "reports" / "json"
        reports_dir.mkdir(parents=True)

        session_data = _make_session(source, fuzzed, [])
        session_file = reports_dir / "session_001.json"
        session_file.write_text(json.dumps(session_data))

        # Change cwd so the relative glob resolves correctly
        monkeypatch.chdir(tmp_path)

        result = _find_session(fuzzed, None)
        assert result is not None
        assert result[0].resolve() == session_file.resolve()

    def test_auto_discover_returns_none_when_no_match(self, tmp_path, monkeypatch):
        source = _make_minimal_dcm(tmp_path / "seed.dcm")
        other_fuzzed = tmp_path / "fuzzed_other.dcm"
        target_fuzzed = tmp_path / "fuzzed_target.dcm"

        reports_dir = tmp_path / "artifacts" / "reports" / "json"
        reports_dir.mkdir(parents=True)

        session_data = _make_session(source, other_fuzzed, [])
        (reports_dir / "session_001.json").write_text(json.dumps(session_data))

        monkeypatch.chdir(tmp_path)

        result = _find_session(target_fuzzed, None)
        assert result is None
