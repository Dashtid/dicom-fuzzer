"""Socorro-style stack-trace hashing for crash deduplication.

Capture (``DOTNET_DbgEnableMiniDump`` env vars on the target /
``createdump.exe`` for hung processes) drops a minidump on disk;
``dump_analyzer.analyze_dump`` turns it into structured frames via
pythonnet + ClrMD; this module turns those frames into a stable
cluster signature.

Algorithm: normalize -> filter irrelevant -> fold consecutive duplicates
-> hash top-N. Same shape as Mozilla Socorro's signature pipeline (the
load-bearing battle-tested implementation we copy from). Two hashes
per crash:

- **primary** (top N=10 normalized frames after folding): the cluster
  bucket. Same primary = same bug.
- **minor** (top N=3): a coarser bucket. When primary clusters get
  noisy across builds, the minor hash gives a fuzzy fall-back so
  related crashes still group together. Same idea as OneFuzz's
  ``call_stack_sha256`` + ``minimized_stack_sha256`` pair and
  syzkaller's ``AltTitles``.

**Stack-overflow special case.** The dicomdir CWE-674 in Hermes
recurses to varying depths depending on the input, so naive hashing
of the top-10 frames would put each recursion depth in its own
bucket. Mozilla Socorro handles this with a dedicated
``StackOverflowSignature`` rule: prepend a literal ``stackoverflow:``
tag, collapse runs of identical frames to one entry, and use the
frame *above* the collapsed run -- the caller into the recursive
function, i.e. the actual bug site. That's what the
``is_overflow`` branch in ``compute_signature`` does here.

The recursion-folding step is also useful for non-stack-overflow
crashes (e.g. a runaway loop that crashes in a non-recursive function
deep inside many wrapper calls), so we apply it unconditionally.

Sources:
- Mozilla Socorro signature generation:
  https://github.com/mozilla-services/socorro/blob/main/socorro/signature/rules.py
- ReBucket (Dao et al., ICSE 2012):
  https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/rebucket-icse2012.pdf
- Klees et al. "Evaluating Fuzz Testing" USENIX SEC '18:
  https://arxiv.org/pdf/1808.09700  (16% false-merge baseline for
  naive top-N; recursion folding + filtering gets us well below)
- dedupT ablation (arXiv 2508.19449, 2025): N=10-15 optimal.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from dicom_fuzzer.core.crash.dump_analyzer import StackFrame

# Tuning constants. Defaults reflect the research:
#  - 40 frame cap (POST-FOLD) matches Socorro's MAXIMUM_FRAMES_TO_CONSIDER.
#  - 4000 raw cap is a defensive upper bound before folding; real
#    .NET stack overflows produce ~1000-30000 frames before the OS
#    fires the exception. Folding collapses those to <10 typically.
#  - N=10 primary matches dedupT (2025) optimum.
#  - N=3 minor matches Socorro's "minor hash" tradition and Watson's
#    coarse FAILURE_BUCKET_ID flavor.
MAX_RAW_FRAMES = 4000
MAX_FRAMES = 40
PRIMARY_N = 10
MINOR_N = 3
HASH_HEX_LEN = 16  # 16 hex chars from sha256; ~64 bits entropy, plenty

# Patterns of frames to drop before hashing. Two categories:
# (1) OS / runtime stubs that appear in every crash and add no signal
#     (KiUserExceptionDispatcher etc.).
# (2) WPF Dispatcher / event-pump frames that surround every crash on
#     a .NET WPF app like Hermes -- if we keep them the top-10 fills
#     up with dispatcher noise and the bug-site frames fall off.
# Patterns are compared against the lowercased normalized frame
# string. Add to this list when a real campaign shows a frame
# repeatedly polluting the top-N.
_IRRELEVANT_FRAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    # OS exception dispatch / unwind stubs
    re.compile(r"\bkiuser(exception|callback)dispatcher\b"),
    re.compile(r"\braiseexception\b"),
    re.compile(r"\brtldispatchexception\b"),
    re.compile(r"\brtluser(threadstart|fiberstart)\b"),
    re.compile(r"\bbaseth?readinit(thunk|ialthunk)\b"),
    re.compile(r"\bunhandledexceptionfilter\b"),
    # .NET runtime exception / dispatch helpers
    re.compile(r"\bjit_(throw|rethrow|rngchkfail|stackprobe)\b"),
    re.compile(r"\bdispatchclrexception\b"),
    re.compile(r"\bcoreclr\.dll!.*exception"),
    # WPF dispatcher / message-pump scaffolding -- present in every
    # crash on a WPF app, never the actual bug site.
    re.compile(r"system\.windows\.threading\.dispatcher\."),
    re.compile(r"system\.windows\.threading\.dispatcheroperation\."),
    re.compile(r"presentationcore\.dll!.*dispatcher"),
    re.compile(r"presentationframework\.dll!.*dispatcher"),
    # ETW / instrumentation frames (rare; safe to drop)
    re.compile(r"\betw(write|enabled|provider)"),
)

# Tokens we strip from each frame string before hashing. Stripping
# these guards against churn (offsets change between builds, JIT
# instruction pointers change every run) without losing signal
# (function names + IL offsets + module names stay stable).
_STRIP_TEMPLATE_PARAMS = re.compile(r"<[^<>]*>")
_STRIP_OFFSET = re.compile(r"\s*\+\s*0x[0-9a-fA-F]+")
_STRIP_LAMBDA_DISPLAY_CLASS = re.compile(r"<>c__displayclass\d+_\d+")
_STRIP_LAMBDA_NUMBERED = re.compile(r"<[a-z_]+>b__\d+_\d+", re.IGNORECASE)


@dataclass
class StackSignature:
    """The output of compute_signature: a deterministic cluster bucket.

    Two crashes whose ``primary`` matches are in the same Phase 3
    cluster. ``minor`` is used as a fuzzy fall-back when ``primary``
    splits crashes that are probably the same bug but happen to have
    slightly different middle-of-stack frames (e.g. different inlining
    decisions between Hermes builds).

    ``top_frames`` is the post-normalization, post-fold list that the
    cluster report renders for humans -- so the operator can read the
    bug site directly out of the cluster file.

    ``algorithm_version`` lets a future change to the algorithm produce
    a different signature for the same input without confusing old
    cluster reports; bump it whenever the hash recipe changes.
    """

    primary: str
    minor: str
    top_frames: list[str] = field(default_factory=list)
    algorithm_version: int = 1


def compute_signature(
    frames: list[StackFrame],
    exception_name: str | None = None,
) -> StackSignature | None:
    """Compute a stack-hash signature from analyzer-produced frames.

    Returns None when ``frames`` is empty (after filtering); the caller
    should fall back to the exception-code-only cluster key in that
    case.

    Args:
        frames: Frames from ``dump_analyzer.analyze_dump``, in
            top-of-stack-first order (faulting frame at index 0).
        exception_name: The faulting exception class name. Triggers the
            stack-overflow special case when it matches an overflow
            class. Pass either the raw Win32 name ("STACK_OVERFLOW")
            or the .NET name ("StackOverflowException") -- both work.

    """
    if not frames:
        return None

    is_overflow = _is_stack_overflow(exception_name)

    # IMPORTANT: fold BEFORE truncating to MAX_FRAMES. Stack-overflow
    # dumps from .NET frequently contain thousands of repeated frames
    # before reaching the actual caller; if we truncated first the
    # caller would fall off the end and recursion-depth variance would
    # leak back into the signature.
    normalized = [normalize_frame(f) for f in frames[:MAX_RAW_FRAMES]]
    normalized = [n for n in normalized if n and not _is_irrelevant(n)]
    if not normalized:
        return None

    folded = _fold_consecutive_duplicates(normalized)[:MAX_FRAMES]
    prefix = "stackoverflow:" if is_overflow else None
    return _signature_from_folded(folded, prefix=prefix)


def normalize_frame(frame: StackFrame) -> str:
    """Reduce a StackFrame to a stable canonical string.

    Form: ``module!type.method+IL_<offset>`` for managed frames,
    ``module!<native>`` for native frames where we know the module,
    and the bare IP for fully unknown native frames. Everything is
    lowercased and stripped of template params, JIT offsets, and
    lambda-display-class numeric suffixes.
    """
    parts: list[str] = []
    if frame.module:
        parts.append(frame.module.lower())

    if frame.is_managed:
        type_name = (frame.type or "<no-type>").lower()
        method_name = (frame.method or "<no-method>").lower()
        body = f"{type_name}.{method_name}"
        # Canonicalize lambda display classes so different invocations
        # of the same compiler-generated closure collide.
        body = _STRIP_LAMBDA_DISPLAY_CLASS.sub("<displayclass>", body)
        body = _STRIP_LAMBDA_NUMBERED.sub("<lambda>", body)
        body = _STRIP_TEMPLATE_PARAMS.sub("", body)
        body = _STRIP_OFFSET.sub("", body)
        if frame.il_offset_hex:
            body = f"{body}+il_{frame.il_offset_hex.lower()}"
        if parts:
            return f"{parts[0]}!{body}"
        return body

    # Native frame: module name (if any) + literal <native> sentinel.
    # We deliberately do NOT include the IP -- IPs are ASLR-randomized
    # across runs and would push the same native crash into different
    # clusters every campaign.
    if frame.module:
        return f"{parts[0]}!<native>"
    return "<unknown-native>"


def _is_stack_overflow(exception_name: str | None) -> bool:
    if not exception_name:
        return False
    n = exception_name.upper()
    return "STACK_OVERFLOW" in n or "STACKOVERFLOWEXCEPTION" in n


def _is_irrelevant(normalized: str) -> bool:
    return any(p.search(normalized) for p in _IRRELEVANT_FRAME_PATTERNS)


def _fold_consecutive_duplicates(frames: list[str]) -> list[str]:
    """Collapse runs of identical frames to a single entry.

    Done on the NORMALIZED form so recursive calls with slightly
    different JIT addresses still collapse. This is the specific fix
    for our CWE-674 dicomdir case where the same Hermes parser
    function recurses to varying depths and would otherwise put each
    crash in a separate bucket.
    """
    folded: list[str] = []
    for f in frames:
        if not folded or f != folded[-1]:
            folded.append(f)
    return folded


def _signature_from_folded(folded: list[str], prefix: str | None) -> StackSignature:
    primary_tail = folded[:PRIMARY_N]
    minor_tail = folded[:MINOR_N]

    primary_body = (prefix or "") + "|".join(primary_tail)
    minor_body = (prefix or "") + "|".join(minor_tail)

    return StackSignature(
        primary=_short_hash(primary_body),
        minor=_short_hash(minor_body),
        top_frames=primary_tail,
    )


def _short_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:HASH_HEX_LEN]
