"""Symbolic stack-trace extraction from Windows minidumps.

Phase 2 of the stack-trace capture work. Phase 1 (--dump-tool /
GUITargetRunner.dump_path) captures the minidump; this module turns
each .dmp into a structured frame list that Phase 3's Socorro-style
clusterer hashes into a stable signature.

Primary path: shell out to ``tools/dump-analyzer/dump-analyzer.exe``,
a small C# console exe that uses ClrMD to walk managed stacks. ClrMD
reads method names from each assembly's MethodDef metadata table, so
this works on closed-source .NET targets like Hermes without PDBs.

Fallback path: ``dotnet-dump analyze -c clrstack -c exit`` and a
best-effort regex over the SOS output. Lower fidelity (no IL offsets,
no method tokens, format brittleness across .NET versions) but means
a campaign run can still produce *some* stack signal even on machines
where the C# helper hasn't been built. The Python side flags which
backend produced the result via ``StackResult.backend``.

Either backend always returns a ``StackResult`` -- never raises -- so
callers can safely chain into the clustering pipeline without
defensive try/except. Errors land on ``StackResult.error`` for
logging; the rest of the fields then degrade to empty/None and the
clusterer falls back to exception-code-only signatures.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

SCHEMA_VERSION = 1

# Where build.ps1 publishes the helper, relative to repo root.
_DEFAULT_HELPER = Path(
    "tools/dump-analyzer/bin/Release/net8.0/win-x64/publish/dump-analyzer.exe"
)


@dataclass
class StackFrame:
    """One frame in a faulting thread's call stack.

    Fields match the C# helper's JSON output 1:1 so a round-trip via
    StackResult.to_json() reproduces the helper's payload (the Phase 3
    cluster reports include the JSON inline for human inspection).
    """

    is_managed: bool
    module: str | None
    type: str | None
    method: str | None
    signature: str | None
    md_token: str | None
    il_offset_hex: str | None
    ip_hex: str


@dataclass
class ExceptionInfo:
    """Faulting-thread exception details, when ClrMD could read them.

    For native crashes (no managed runtime in the dump) this is None
    and the Python caller relies on the runner's process exit code.
    """

    code_hex: str
    name: str
    address_hex: str


@dataclass
class StackResult:
    """Parsed stack-trace info for one minidump.

    ``backend`` tells you which extractor produced the result so a
    Phase 3 cluster report can flag low-fidelity (dotnet-dump fallback)
    signatures distinctly from high-fidelity (ClrMD-direct) ones.

    ``error`` is non-None when the dump could not be analyzed at all
    (helper missing, malformed dump, no managed runtime, etc.). When
    ``error`` is set the other fields are typically empty/None.
    """

    backend: str  # "clrmd", "dotnet-dump", or "none"
    schema_version: int = SCHEMA_VERSION
    dump_path: str | None = None
    exception: ExceptionInfo | None = None
    faulting_thread_id: int | None = None
    frames: list[StackFrame] = field(default_factory=list)
    error: str | None = None

    def to_json(self) -> str:
        """Serialize to JSON. Used by Phase 3 cluster reports."""
        return json.dumps(asdict(self), indent=2)


def analyze_dump(
    dump_path: Path | str,
    helper_path: Path | str | None = None,
    dotnet_dump: str | None = None,
    timeout_sec: float = 60.0,
) -> StackResult:
    """Extract a structured stack trace from a minidump.

    Tries the ClrMD helper first; falls back to ``dotnet-dump analyze``
    if the helper isn't built. Returns ``StackResult(backend="none")``
    with ``error`` set when neither backend is available -- never
    raises, so the caller can chain into clustering unconditionally.

    Args:
        dump_path: Path to a .dmp captured by ProcDump.
        helper_path: Override for the built dump-analyzer.exe. Defaults
            to ``tools/dump-analyzer/...../dump-analyzer.exe`` relative
            to cwd; useful for tests + non-standard layouts.
        dotnet_dump: Override for the ``dotnet-dump`` CLI. Defaults to
            whatever ``shutil.which("dotnet-dump")`` returns.
        timeout_sec: Wall-clock cap on the helper subprocess. Stack
            walking on a 30MB minidump takes <1s in practice; 60s
            tolerates symbol-server warmup on first run.

    """
    dump = Path(dump_path)
    if not dump.exists():
        return StackResult(
            backend="none",
            dump_path=str(dump),
            error=f"dump file not found: {dump}",
        )

    helper = Path(helper_path) if helper_path else _DEFAULT_HELPER
    if helper.exists():
        return _run_clrmd_helper(helper, dump, timeout_sec)

    dotnet_dump_bin = dotnet_dump or shutil.which("dotnet-dump")
    if dotnet_dump_bin:
        return _run_dotnet_dump_fallback(dotnet_dump_bin, dump, timeout_sec)

    return StackResult(
        backend="none",
        dump_path=str(dump),
        error=(
            f"no stack-trace backend available: helper {helper} not built "
            "(run tools/dump-analyzer/build.ps1) and 'dotnet-dump' not on PATH "
            "(install via 'dotnet tool install -g dotnet-dump')"
        ),
    )


def _run_clrmd_helper(helper: Path, dump: Path, timeout_sec: float) -> StackResult:
    """Invoke the C# dump-analyzer and parse its JSON output."""
    try:
        proc = subprocess.run(
            [str(helper), str(dump)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return StackResult(
            backend="clrmd",
            dump_path=str(dump),
            error=f"dump-analyzer.exe timed out after {timeout_sec}s",
        )
    except OSError as e:
        return StackResult(
            backend="clrmd",
            dump_path=str(dump),
            error=f"failed to invoke dump-analyzer.exe: {e}",
        )

    if proc.returncode != 0 and not proc.stdout.strip():
        return StackResult(
            backend="clrmd",
            dump_path=str(dump),
            error=(
                f"dump-analyzer.exe exited {proc.returncode} with no stdout; "
                f"stderr={proc.stderr.strip()[:500]!r}"
            ),
        )

    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return StackResult(
            backend="clrmd",
            dump_path=str(dump),
            error=f"dump-analyzer.exe stdout was not JSON: {e}",
        )
    return _result_from_helper_doc(doc, backend="clrmd")


def _result_from_helper_doc(doc: dict, backend: str) -> StackResult:
    """Map the C# helper's JSON schema onto StackResult."""
    exc_raw = doc.get("exception")
    exc = (
        ExceptionInfo(
            code_hex=exc_raw["code_hex"],
            name=exc_raw["name"],
            address_hex=exc_raw["address_hex"],
        )
        if exc_raw
        else None
    )
    frames = [
        StackFrame(
            is_managed=bool(f.get("is_managed")),
            module=f.get("module"),
            type=f.get("type"),
            method=f.get("method"),
            signature=f.get("signature"),
            md_token=f.get("md_token"),
            il_offset_hex=f.get("il_offset_hex"),
            ip_hex=f.get("ip_hex", "0x0"),
        )
        for f in doc.get("frames", []) or []
    ]
    return StackResult(
        backend=backend,
        schema_version=int(doc.get("schema_version", SCHEMA_VERSION)),
        dump_path=doc.get("dump_path"),
        exception=exc,
        faulting_thread_id=doc.get("faulting_thread_id"),
        frames=frames,
        error=doc.get("error"),
    )


# dotnet-dump's `clrstack` output looks like:
#
#     OS Thread Id: 0x3210 (1)
#             Child SP               IP Call Site
#     000000a3b25fea90 00007ffd91234567 Hermes.Parser.DicomReader.ReadSequence(...)
#     000000a3b25feb20 00007ffd91234abc Hermes.Parser.DicomReader.ReadSequence(...)
#     ...
#
# We parse the "Call Site" column into Module / Type / Method best-effort.
_CLRSTACK_FRAME = re.compile(
    r"^[0-9a-fA-F]+\s+(?P<ip>[0-9a-fA-F]+)\s+(?P<call>.+?)\s*$"
)


def _run_dotnet_dump_fallback(
    dotnet_dump: str, dump: Path, timeout_sec: float
) -> StackResult:
    """Lower-fidelity fallback: shell out to dotnet-dump analyze."""
    try:
        proc = subprocess.run(
            [dotnet_dump, "analyze", str(dump), "-c", "clrstack -all", "-c", "exit"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return StackResult(
            backend="dotnet-dump",
            dump_path=str(dump),
            error=f"dotnet-dump analyze timed out after {timeout_sec}s",
        )
    except OSError as e:
        return StackResult(
            backend="dotnet-dump",
            dump_path=str(dump),
            error=f"failed to invoke dotnet-dump: {e}",
        )

    if proc.returncode != 0:
        return StackResult(
            backend="dotnet-dump",
            dump_path=str(dump),
            error=(
                f"dotnet-dump analyze exited {proc.returncode}: "
                f"{proc.stderr.strip()[:500]!r}"
            ),
        )

    frames = _parse_clrstack_output(proc.stdout)
    return StackResult(
        backend="dotnet-dump",
        dump_path=str(dump),
        exception=None,  # clrstack alone doesn't emit the exception record
        faulting_thread_id=None,
        frames=frames,
        error=None if frames else "dotnet-dump produced no parsable frames",
    )


def _parse_clrstack_output(output: str) -> list[StackFrame]:
    """Best-effort parse of SOS ``!clrstack`` rows into StackFrame.

    Format is documented but not formally stable across .NET versions;
    we keep parsing minimal so a column-order tweak in a future SOS
    doesn't silently drop frames. Anything we can't parse is skipped.
    """
    frames: list[StackFrame] = []
    in_stack = False
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # The frame block starts after a "Call Site" header line.
        if "Call Site" in stripped:
            in_stack = True
            continue
        if not in_stack:
            continue
        # Blank line or new section ends the block.
        if stripped.startswith("OS Thread Id"):
            in_stack = False
            continue
        m = _CLRSTACK_FRAME.match(stripped)
        if not m:
            continue
        call = m.group("call").strip()
        module, type_name, method = _split_call_site(call)
        frames.append(
            StackFrame(
                is_managed=True,
                module=module,
                type=type_name,
                method=method,
                signature=call,
                md_token=None,
                il_offset_hex=None,
                ip_hex=f"0x{m.group('ip').lower()}",
            )
        )
    return frames


def _split_call_site(call: str) -> tuple[str | None, str | None, str | None]:
    """Approximately split ``Namespace.Type.Method(args)`` into parts.

    We never see the assembly/module name in clrstack output -- it's
    only the fully-qualified managed name. ``module`` returns None for
    this backend; Phase 3 hashing treats that as a lower-confidence
    signal (different bucket from the same crash via ClrMD).
    """
    paren = call.find("(")
    head = call[:paren] if paren != -1 else call
    parts = head.split(".")
    if len(parts) < 2:
        return None, None, head or None
    method = parts[-1]
    type_name = ".".join(parts[:-1])
    return None, type_name or None, method or None
