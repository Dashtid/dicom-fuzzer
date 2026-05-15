"""Tests for write_cluster_reports markdown output."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime

import pytest

from dicom_fuzzer.core.crash.crash_triage import CrashTriageEngine
from dicom_fuzzer.core.crash.models import CrashRecord
from dicom_fuzzer.core.crash.triage_report import write_cluster_reports


@pytest.fixture
def engine() -> CrashTriageEngine:
    return CrashTriageEngine()


def _make_crash(
    crash_id: str = "crash_a",
    exception_message: str = "write access violation at 0x7fff",
    fuzzed_file_path: str = "input.dcm",
    stack_trace: str = "frame 0: heap corruption\nframe 1: process_dicom",
) -> CrashRecord:
    return CrashRecord(
        crash_id=crash_id,
        timestamp=datetime(2026, 4, 13, 12, 0, 0),
        crash_type="SIGSEGV",
        severity="critical",
        fuzzed_file_id=crash_id,
        fuzzed_file_path=fuzzed_file_path,
        return_code=-11,
        exception_type="SegmentationFault",
        exception_message=exception_message,
        stack_trace=stack_trace,
        mutation_sequence=[("metadata", "patient_name_overflow")],
        reproduction_command="dicom-fuzzer replay --decompose input.dcm",
    )


class TestWriteClusterReportsBasics:
    def test_empty_crashes_writes_nothing(self, tmp_path):
        result = write_cluster_reports([], tmp_path / "triage")
        assert result == []
        assert not (tmp_path / "triage").exists()

    def test_creates_output_directory(self, tmp_path):
        out = tmp_path / "triage" / "nested"
        write_cluster_reports([_make_crash()], out)
        assert out.is_dir()

    def test_returns_index_first(self, tmp_path):
        written = write_cluster_reports([_make_crash()], tmp_path)
        assert written[0].name == "index.md"

    def test_one_crash_produces_index_plus_one_cluster(self, tmp_path):
        written = write_cluster_reports([_make_crash()], tmp_path)
        assert len(written) == 2  # index + one cluster
        assert written[1].name.startswith("cluster_001_")
        assert written[1].suffix == ".md"


class TestWriteClusterReportsClustering:
    def test_duplicate_crashes_collapse_into_single_cluster_file(self, tmp_path):
        c1 = _make_crash(crash_id="a", fuzzed_file_path="a.dcm")
        c2 = _make_crash(crash_id="b", fuzzed_file_path="b.dcm")
        c3 = _make_crash(crash_id="c", fuzzed_file_path="c.dcm")
        written = write_cluster_reports([c1, c2, c3], tmp_path)
        # Just one cluster file (plus index)
        assert len(written) == 2

    def test_distinct_crashes_each_get_own_file(self, tmp_path):
        c1 = _make_crash(crash_id="a", exception_message="msg 1")
        c2 = _make_crash(crash_id="b", exception_message="msg 2")
        written = write_cluster_reports([c1, c2], tmp_path)
        assert len(written) == 3  # index + 2 clusters


class TestIndexContent:
    def test_index_lists_total_and_unique_counts(self, tmp_path):
        c1 = _make_crash(crash_id="a")
        c2 = _make_crash(crash_id="b")  # same signature as c1
        c3 = _make_crash(crash_id="c", exception_message="different bug")
        write_cluster_reports([c1, c2, c3], tmp_path)
        index = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "Total crashes: **3**" in index
        assert "Unique clusters: **2**" in index

    def test_index_has_table_header(self, tmp_path):
        write_cluster_reports([_make_crash()], tmp_path)
        index = (tmp_path / "index.md").read_text(encoding="utf-8")
        assert "Signature" in index
        assert "Priority" in index
        assert "Severity" in index


class TestClusterFileContent:
    def test_cluster_file_includes_stack_trace(self, tmp_path):
        write_cluster_reports([_make_crash()], tmp_path)
        cluster_files = list(tmp_path.glob("cluster_*.md"))
        assert len(cluster_files) == 1
        content = cluster_files[0].read_text(encoding="utf-8")
        assert "Stack trace" in content
        assert "heap corruption" in content

    def test_cluster_file_includes_reproduction_command(self, tmp_path):
        write_cluster_reports([_make_crash()], tmp_path)
        cluster_files = list(tmp_path.glob("cluster_*.md"))
        content = cluster_files[0].read_text(encoding="utf-8")
        assert "dicom-fuzzer replay" in content

    def test_cluster_file_includes_mutation_sequence(self, tmp_path):
        write_cluster_reports([_make_crash()], tmp_path)
        cluster_files = list(tmp_path.glob("cluster_*.md"))
        content = cluster_files[0].read_text(encoding="utf-8")
        assert "Mutation sequence" in content
        assert "patient_name_overflow" in content

    def test_multi_crash_cluster_lists_other_crashes(self, tmp_path):
        c1 = _make_crash(crash_id="primary")
        c2 = _make_crash(crash_id="dup_one", fuzzed_file_path="dup1.dcm")
        c3 = _make_crash(crash_id="dup_two", fuzzed_file_path="dup2.dcm")
        write_cluster_reports([c1, c2, c3], tmp_path)
        cluster_files = list(tmp_path.glob("cluster_*.md"))
        content = cluster_files[0].read_text(encoding="utf-8")
        assert "Other crashes in cluster" in content
        assert "dup_one" in content
        assert "dup_two" in content
        assert "dup1.dcm" in content


class TestEngineReuse:
    def test_passing_engine_uses_its_cache(self, tmp_path, engine):
        # Pre-triage so the engine cache has entries
        crash = _make_crash()
        engine.triage_crash(crash)
        assert len(engine.triage_cache) == 1

        write_cluster_reports([crash], tmp_path, engine=engine)
        # No new triage entries were created -- the cached one was reused
        assert len(engine.triage_cache) == 1


class TestPriorityOrdering:
    def test_clusters_ordered_by_priority_descending(self, tmp_path):
        # Critical (high priority) cluster
        crit = _make_crash(
            crash_id="crit",
            exception_message="write access violation -- heap corruption",
        )
        # Low (timeout, benign pattern, low priority)
        low = deepcopy(crit)
        low.crash_id = "low"
        low.crash_type = "TIMEOUT"
        low.exception_message = "timeout exceeded"
        low.stack_trace = "no stack"

        write_cluster_reports([low, crit], tmp_path)
        index = (tmp_path / "index.md").read_text(encoding="utf-8")
        # The critical cluster should appear before the low one in the table
        crit_pos = index.find("write access")
        low_pos = index.find("timeout")
        assert 0 < crit_pos < low_pos


class TestSymbolicStackSection:
    """Phase 4: cluster reports render the Phase 3 stack-hash output
    inline so triage reads the bug site without opening the dump.
    """

    def test_section_omitted_when_no_dump_path(self, tmp_path):
        crash = _make_crash()
        assert crash.dump_path is None
        write_cluster_reports([crash], tmp_path)
        cluster_files = list(tmp_path.glob("cluster_*.md"))
        content = cluster_files[0].read_text(encoding="utf-8")
        assert "Symbolic stack" not in content

    def test_section_omitted_when_analyzer_returns_no_frames(
        self, tmp_path, monkeypatch
    ):
        from dicom_fuzzer.core.crash.dump_analyzer import StackResult

        crash = _make_crash()
        crash.dump_path = str(tmp_path / "x.dmp")
        (tmp_path / "x.dmp").write_bytes(b"fake")
        monkeypatch.setattr(
            "dicom_fuzzer.core.crash.dump_analyzer.analyze_dump",
            lambda *a, **kw: StackResult(
                backend="none", dump_path=crash.dump_path, error="no backend"
            ),
        )
        write_cluster_reports([crash], tmp_path)
        cluster_files = list(tmp_path.glob("cluster_*.md"))
        content = cluster_files[0].read_text(encoding="utf-8")
        assert "Symbolic stack" not in content

    def test_section_rendered_when_analyzer_succeeds(self, tmp_path, monkeypatch):
        """Happy path: analyzer + hasher succeed -> markdown has the
        backend, primary/minor hashes, exception name, and top frames."""
        from dicom_fuzzer.core.crash.dump_analyzer import (
            ExceptionInfo,
            StackFrame,
            StackResult,
        )
        from dicom_fuzzer.core.crash.stack_hash import StackSignature

        crash = _make_crash()
        crash.dump_path = str(tmp_path / "x.dmp")
        (tmp_path / "x.dmp").write_bytes(b"fake")

        fake_frame = StackFrame(
            is_managed=True,
            module="Hermes.exe",
            type="Hermes.Parser.DicomReader",
            method="ReadSequence",
            signature="ReadSequence()",
            md_token="0x06000123",  # noqa: S106 -- .NET MethodDef token
            il_offset_hex="0x4a",
            ip_hex="0x1",
        )
        monkeypatch.setattr(
            "dicom_fuzzer.core.crash.dump_analyzer.analyze_dump",
            lambda *a, **kw: StackResult(
                backend="clrmd",
                dump_path=crash.dump_path,
                exception=ExceptionInfo(
                    code_hex="0xC00000FD",
                    name="STACK_OVERFLOW",
                    address_hex="0x0",
                ),
                frames=[fake_frame],
            ),
        )
        monkeypatch.setattr(
            "dicom_fuzzer.core.crash.stack_hash.compute_signature",
            lambda *a, **kw: StackSignature(
                primary="abc123primary",
                minor="def456minor",
                top_frames=[
                    "hermes.exe!hermes.parser.dicomreader.readsequence+il_0x4a",
                ],
            ),
        )

        write_cluster_reports([crash], tmp_path)
        cluster_files = list(tmp_path.glob("cluster_*.md"))
        content = cluster_files[0].read_text(encoding="utf-8")

        assert "Symbolic stack" in content
        assert "clrmd" in content  # backend tag
        assert "abc123primary" in content
        assert "def456minor" in content
        assert "STACK_OVERFLOW" in content
        assert "hermes.exe!hermes.parser.dicomreader.readsequence+il_0x4a" in content

    def test_section_skipped_on_analyzer_exception(self, tmp_path, monkeypatch):
        """Even if analyze_dump itself raises, the report renders the
        rest of the cluster info; the stack section is just omitted."""
        crash = _make_crash()
        crash.dump_path = str(tmp_path / "x.dmp")
        (tmp_path / "x.dmp").write_bytes(b"fake")

        def boom(*a, **kw):
            raise RuntimeError("analyzer self-destructed")

        monkeypatch.setattr("dicom_fuzzer.core.crash.dump_analyzer.analyze_dump", boom)
        write_cluster_reports([crash], tmp_path)
        cluster_files = list(tmp_path.glob("cluster_*.md"))
        content = cluster_files[0].read_text(encoding="utf-8")
        assert "# Cluster" in content
        assert "Symbolic stack" not in content
