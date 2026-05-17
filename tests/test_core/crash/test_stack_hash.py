"""Unit tests for Socorro-style stack-trace hashing.

These tests pin the algorithm's behavior on synthetic stack inputs.
The crash-set we actually care about (the 70-stack-overflow cluster
from the 2026-05-14 8h Hermes campaign) is exercised end-to-end in
a separate integration test once a re-fuzz captures dumps via Phase
1 + Phase 2.
"""

from __future__ import annotations

import pytest

from dicom_fuzzer.core.crash.dump_analyzer import StackFrame
from dicom_fuzzer.core.crash.stack_hash import (
    MINOR_N,
    PRIMARY_N,
    StackSignature,
    _fold_consecutive_duplicates,
    _is_irrelevant,
    _is_stack_overflow,
    _short_hash,
    compute_signature,
    normalize_frame,
)


def _managed(
    module: str = "Hermes.exe",
    type_: str = "Hermes.Parser.DicomReader",
    method: str = "ReadSequence",
    il: str | None = "0x4a",
    ip: str = "0x7ffd91234567",
    signature: str | None = None,
) -> StackFrame:
    return StackFrame(
        is_managed=True,
        module=module,
        type=type_,
        method=method,
        signature=signature or f"{method}()",
        md_token="0x06000123",  # noqa: S106 -- .NET MethodDef token, not a credential
        il_offset_hex=il,
        ip_hex=ip,
    )


def _native(module: str | None = "ntdll.dll", ip: str = "0x7ffd00000000") -> StackFrame:
    return StackFrame(
        is_managed=False,
        module=module,
        type=None,
        method=None,
        signature=None,
        md_token=None,
        il_offset_hex=None,
        ip_hex=ip,
    )


class TestNormalizeFrame:
    """One frame -> one canonical string."""

    def test_managed_with_module(self):
        f = _managed()
        out = normalize_frame(f)
        assert out == "hermes.exe!hermes.parser.dicomreader.readsequence+il_0x4a"

    def test_managed_without_il_offset(self):
        f = _managed(il=None)
        out = normalize_frame(f)
        assert out == "hermes.exe!hermes.parser.dicomreader.readsequence"

    def test_lambda_display_class_canonicalized(self):
        """Two different display classes for the same code site
        should normalize to the same string."""
        a = _managed(type_="<>c__DisplayClass4_0", method="<Run>b__1_0", il=None)
        b = _managed(type_="<>c__DisplayClass7_2", method="<Run>b__1_0", il=None)
        assert normalize_frame(a) == normalize_frame(b)

    def test_template_params_stripped(self):
        f = _managed(method="List<int>.Add", il=None)
        out = normalize_frame(f)
        assert "<int>" not in out
        assert "list.add" in out

    def test_native_with_module(self):
        f = _native()
        out = normalize_frame(f)
        # IP is intentionally NOT in the hash (ASLR-randomized)
        assert out == "ntdll.dll!<native>"
        assert "0x7ffd00000000" not in out

    def test_native_unknown_module(self):
        f = _native(module=None)
        assert normalize_frame(f) == "<unknown-native>"

    def test_module_lowercased(self):
        f = _managed(module="HERMES.EXE", il=None)
        assert normalize_frame(f).startswith("hermes.exe!")


class TestIrrelevantFilter:
    """Frames in _IRRELEVANT_FRAME_PATTERNS get dropped before hashing."""

    @pytest.mark.parametrize(
        "frame",
        [
            "ntdll.dll!kiuserexceptiondispatcher",
            "kernel32.dll!raiseexception",
            "ntdll.dll!rtldispatchexception",
            "ntdll.dll!rtluserthreadstart",
            "kernel32.dll!basethreadinitthunk",
            "coreclr.dll!jit_throw",
            "coreclr.dll!dispatchclrexception",
            "system.windows.threading.dispatcher.pushframe",
            "system.windows.threading.dispatcheroperation.invoke",
            "presentationcore.dll!something.dispatcherrelated",
        ],
    )
    def test_dropped(self, frame: str):
        assert _is_irrelevant(frame)

    @pytest.mark.parametrize(
        "frame",
        [
            "hermes.exe!hermes.parser.dicomreader.readsequence",
            "system.private.corelib.dll!system.io.stream.read",
            "fo-dicom.core.dll!dicom.io.reader.dicomreader.readsequence",
        ],
    )
    def test_kept(self, frame: str):
        assert not _is_irrelevant(frame)


class TestRecursionFolding:
    def test_consecutive_duplicates_collapsed(self):
        out = _fold_consecutive_duplicates(["A", "A", "A", "B"])
        assert out == ["A", "B"]

    def test_non_consecutive_duplicates_preserved(self):
        # PDM-ordered: A-B-A and A-A-B are different bugs
        out = _fold_consecutive_duplicates(["A", "B", "A"])
        assert out == ["A", "B", "A"]

    def test_empty(self):
        assert _fold_consecutive_duplicates([]) == []

    def test_single(self):
        assert _fold_consecutive_duplicates(["A"]) == ["A"]


class TestStackOverflowDetection:
    @pytest.mark.parametrize(
        "name",
        [
            "STACK_OVERFLOW",
            "stack_overflow",
            "Stack_Overflow",
            "StackOverflowException",
            "System.StackOverflowException",
        ],
    )
    def test_detects(self, name: str):
        assert _is_stack_overflow(name)

    @pytest.mark.parametrize(
        "name",
        [
            None,
            "",
            "InvalidOperationException",
            "AccessViolationException",
            "ACCESS_VIOLATION",
        ],
    )
    def test_does_not_detect(self, name: str | None):
        assert not _is_stack_overflow(name)


class TestComputeSignatureRegular:
    """Non-stack-overflow path: normalize -> filter -> fold -> hash top-N."""

    def test_empty_frames_returns_none(self):
        assert compute_signature([], exception_name="X") is None

    def test_all_filtered_returns_none(self):
        # Every frame is a dispatcher / runtime stub
        frames = [
            _managed(type_="System.Windows.Threading.Dispatcher", method="PushFrame"),
            _managed(
                type_="System.Windows.Threading.DispatcherOperation", method="Invoke"
            ),
        ]
        assert compute_signature(frames, exception_name="X") is None

    def test_basic_hash_stability(self):
        """Identical inputs -> identical signature, run after run."""
        frames = [_managed(method=m, il=None) for m in ("A", "B", "C")]
        s1 = compute_signature(frames, exception_name="X")
        s2 = compute_signature(frames, exception_name="X")
        assert s1 == s2
        assert s1 is not None
        assert len(s1.primary) == 16
        assert len(s1.minor) == 16

    def test_different_top_frame_different_signature(self):
        a = [_managed(method=m, il=None) for m in ("X", "Y")]
        b = [_managed(method=m, il=None) for m in ("Z", "Y")]
        sa = compute_signature(a, "Ex")
        sb = compute_signature(b, "Ex")
        assert sa is not None and sb is not None
        assert sa.primary != sb.primary

    def test_top_frames_returned_for_human_inspection(self):
        frames = [_managed(method=m, il=None) for m in ("A", "B", "C")]
        s = compute_signature(frames, exception_name="X")
        assert s is not None
        assert s.top_frames == [normalize_frame(f) for f in frames][:PRIMARY_N]

    def test_minor_uses_only_top_3(self):
        # 4 distinct frames; flipping anything outside top-3 must NOT
        # change the minor hash.
        a = [_managed(method=m, il=None) for m in ("A", "B", "C", "D")]
        b = [_managed(method=m, il=None) for m in ("A", "B", "C", "Z")]
        sa = compute_signature(a, "X")
        sb = compute_signature(b, "X")
        assert sa is not None and sb is not None
        assert sa.minor == sb.minor
        assert sa.primary != sb.primary  # primary did change

    def test_primary_caps_at_top_n(self):
        # 20 distinct frames; flipping frame 11 must NOT change primary
        # (only top-10 contribute).
        a = [_managed(method=f"M{i}", il=None) for i in range(20)]
        b = [_managed(method=f"M{i}", il=None) for i in range(20)]
        b[15] = _managed(method="DIFFERENT", il=None)
        sa = compute_signature(a, "X")
        sb = compute_signature(b, "X")
        assert sa is not None and sb is not None
        assert sa.primary == sb.primary

    def test_recursion_folding_collapses_depth_variance(self):
        """The same recursive function repeated 3 vs 5 times must
        produce the same signature -- this is what fixes the dicomdir
        CWE-674 case where naive top-N would split crashes by depth."""
        shallow = [_managed(method="ReadSeq", il=None)] * 3 + [
            _managed(method="Main", il=None)
        ]
        deep = [_managed(method="ReadSeq", il=None)] * 7 + [
            _managed(method="Main", il=None)
        ]
        s_shallow = compute_signature(shallow, exception_name="InvalidOp")
        s_deep = compute_signature(deep, exception_name="InvalidOp")
        assert s_shallow is not None and s_deep is not None
        assert s_shallow.primary == s_deep.primary


class TestComputeSignatureStackOverflow:
    """Stack-overflow path: 'stackoverflow:' tag + recursion fold."""

    def test_tag_makes_overflow_distinct_from_non_overflow(self):
        """Same stack, two exception classes -> two clusters. Same
        frames hitting STACK_OVERFLOW vs. InvalidOperationException
        are different bugs; the tag enforces that."""
        frames = [_managed(method="ReadSeq", il=None)] * 5 + [
            _managed(method="Main", il=None)
        ]
        s_overflow = compute_signature(frames, exception_name="STACK_OVERFLOW")
        s_normal = compute_signature(frames, exception_name="InvalidOp")
        assert s_overflow is not None and s_normal is not None
        assert s_overflow.primary != s_normal.primary

    def test_overflow_folds_recursion(self):
        """3-deep recursion and 50-deep recursion produce the same
        primary signature -- the key dicomdir CWE-674 property."""
        shallow = [_managed(method="ReadSeq", il=None)] * 3 + [
            _managed(method="ParseFile", il=None)
        ]
        deep = [_managed(method="ReadSeq", il=None)] * 50 + [
            _managed(method="ParseFile", il=None)
        ]
        s_shallow = compute_signature(shallow, exception_name="STACK_OVERFLOW")
        s_deep = compute_signature(deep, exception_name="STACK_OVERFLOW")
        assert s_shallow is not None and s_deep is not None
        assert s_shallow.primary == s_deep.primary
        assert s_shallow.minor == s_deep.minor

    def test_overflow_signature_includes_caller_frame(self):
        """The caller into the recursion (ParseFile) participates in
        the signature even after fold."""
        frames = [_managed(method="ReadSeq", il=None)] * 5 + [
            _managed(method="ParseFile", il=None)
        ]
        s = compute_signature(frames, exception_name="STACK_OVERFLOW")
        assert s is not None
        # ReadSeq + ParseFile both appear in the folded top_frames
        joined = "|".join(s.top_frames)
        assert "readseq" in joined
        assert "parsefile" in joined

    def test_overflow_pure_recursion(self):
        """A stack that's ONLY the recursive function (no caller)
        still produces a valid signature -- pathological but stable."""
        frames = [_managed(method="ReadSeq", il=None)] * 200
        s = compute_signature(frames, exception_name="STACK_OVERFLOW")
        assert s is not None
        assert len(s.top_frames) == 1
        assert s.primary  # non-empty


class TestPDMOrdering:
    """Position-dependent: A->B and B->A are different bugs."""

    def test_order_matters(self):
        ab = [_managed(method="A", il=None), _managed(method="B", il=None)]
        ba = [_managed(method="B", il=None), _managed(method="A", il=None)]
        s_ab = compute_signature(ab, "Ex")
        s_ba = compute_signature(ba, "Ex")
        assert s_ab is not None and s_ba is not None
        assert s_ab.primary != s_ba.primary


class TestShortHash:
    def test_deterministic(self):
        assert _short_hash("abc") == _short_hash("abc")

    def test_length(self):
        assert len(_short_hash("anything")) == 16

    def test_different_inputs_different_output(self):
        assert _short_hash("a") != _short_hash("b")


class TestSignatureDataclass:
    def test_defaults(self):
        s = StackSignature(primary="p", minor="m")
        assert s.top_frames == []
        assert s.algorithm_version == 1


def test_module_constants_match_research_recommendation():
    """Pin the tuning constants. Bumping these is a deliberate
    algorithm change and should require updating the BACKLOG entry
    + bumping StackSignature.algorithm_version."""
    assert PRIMARY_N == 10  # dedupT 2025 optimum
    assert MINOR_N == 3  # Socorro / Watson convention
