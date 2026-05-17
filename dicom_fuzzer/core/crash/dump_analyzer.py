"""Symbolic stack-trace extraction from Windows minidumps.

Loads Microsoft's ClrMD library (Microsoft.Diagnostics.Runtime.dll)
in-process via ``pythonnet`` and walks the faulting thread's managed
stack. Managed frames are resolved through each assembly's MethodDef
metadata table, so this works on stripped/closed-source .NET targets
like Hermes without PDBs. Native frames are reported as module +
instruction pointer (we deliberately do not include the IP in the
clustering hash because it is ASLR-randomized).

Design notes:

- **Lazy init.** pythonnet + CoreCLR + ClrMD all load on the first
  call to ``analyze_dump``, never at import time. A campaign with no
  crashes never pays the ~150 ms init cost.
- **Never raises.** Every failure path returns a ``StackResult`` with
  ``error`` populated so callers (``crash_triage._stack_signature``,
  ``triage_report._collect_stack_info``) can stay free of try/except.
- **Single backend.** The previous "ClrMD helper exe with dotnet-dump
  fallback" split was abandoned in Phase 5: shipping a 2 MB DLL is
  cheaper than maintaining two parsers. If pythonnet/ClrMD/.NET 8 is
  missing, ``backend`` stays ``"none"`` and the cluster pipeline falls
  back to exception-code-only signatures (same degraded mode as
  before).
"""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

SCHEMA_VERSION = 2  # bumped from 1 (Phase 2 helper-exe schema)

_VENDOR_DIR = Path(__file__).parent.parent.parent / "_vendor" / "clrmd"
_CLRMD_DLL = _VENDOR_DIR / "Microsoft.Diagnostics.Runtime.dll"
_RUNTIME_CONFIG = _VENDOR_DIR / "runtimeconfig.json"

# pythonnet's CoreCLR loader has to be invoked exactly once per
# process. We track init state via a tri-valued cache (None = untried,
# True/False = result) guarded by a lock so the first concurrent
# caller wins and the rest see the cached outcome.
_init_lock = threading.Lock()
_init_state: bool | None = None
_init_error: str | None = None


@dataclass
class StackFrame:
    """One frame in a faulting thread's call stack.

    Field shape is preserved across the Phase 2 / Phase 5 transition
    so ``stack_hash.normalize_frame`` and the cluster-report renderer
    don't need to change. ``md_token`` and ``il_offset_hex`` are
    populated only for managed frames; native frames report
    ``module`` + ``ip_hex`` and leave the rest None.
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
    """Faulting-thread exception details, when ClrMD could read them."""

    code_hex: str
    name: str
    address_hex: str


@dataclass
class StackResult:
    """Parsed stack-trace info for one minidump.

    ``backend`` is ``"clrmd"`` when the pythonnet/ClrMD path produced
    a result (even an empty one), or ``"none"`` when the analyzer
    could not be loaded at all (pythonnet missing, DLL not vendored,
    no .NET runtime). The cluster pipeline reads this to decide
    whether to include the stack section in reports.
    """

    backend: str  # "clrmd" or "none"
    schema_version: int = SCHEMA_VERSION
    dump_path: str | None = None
    exception: ExceptionInfo | None = None
    faulting_thread_id: int | None = None
    frames: list[StackFrame] = field(default_factory=list)
    error: str | None = None

    def to_json(self) -> str:
        """Serialize to JSON (cluster reports embed this for inspection)."""
        import json

        return json.dumps(asdict(self), indent=2)


def analyze_dump(dump_path: Path | str) -> StackResult:
    """Extract a structured stack trace from a Windows minidump.

    Always returns a ``StackResult``; on any failure the ``error``
    field is populated and the rest of the fields degrade gracefully.

    Args:
        dump_path: Path to a .dmp written by the .NET runtime
            (``DOTNET_DbgEnableMiniDump``) or by ``createdump.exe``.

    """
    dump = Path(dump_path)
    if not dump.exists():
        return StackResult(
            backend="none",
            dump_path=str(dump),
            error=f"dump file not found: {dump}",
        )

    if not _ensure_clrmd_ready():
        return StackResult(
            backend="none",
            dump_path=str(dump),
            error=_init_error or "ClrMD not initialized",
        )

    return _walk_with_clrmd(dump)


def _ensure_clrmd_ready() -> bool:
    """One-time setup: load CoreCLR, AddReference the vendored DLL.

    Result is cached for the lifetime of the process. Returns True on
    success, False on any failure (with ``_init_error`` set so the
    caller can surface the message).
    """
    global _init_state, _init_error

    if _init_state is not None:
        return _init_state

    with _init_lock:
        # Double-checked locking: another thread may have completed
        # init between our outer check and acquiring the lock.
        if _init_state is not None:
            return _init_state  # type: ignore[unreachable]

        try:
            from pythonnet import load as _pythonnet_load
        except ImportError:
            _init_state = False
            _init_error = (
                "pythonnet is not installed; managed-stack symbolication "
                "is unavailable. Install with `pip install dicom-fuzzer"
                "[stack-trace]` or run `dicom-fuzzer install-stack-trace`."
            )
            return False

        if not _CLRMD_DLL.exists():
            _init_state = False
            _init_error = (
                f"ClrMD DLL not vendored at {_CLRMD_DLL}. Run "
                "`dicom-fuzzer install-stack-trace` to fetch it from NuGet."
            )
            return False

        try:
            _pythonnet_load("coreclr", runtime_config=str(_RUNTIME_CONFIG))
        except Exception as exc:
            _init_state = False
            _init_error = (
                f".NET 8 runtime not loadable via pythonnet: {exc}. "
                "Ensure the .NET 8 desktop runtime is installed."
            )
            return False

        try:
            import clr

            clr.AddReference(str(_CLRMD_DLL))
        except Exception as exc:
            _init_state = False
            _init_error = f"ClrMD DLL failed to load: {exc}"
            return False

        _init_state = True
        return True


def _walk_with_clrmd(dump: Path) -> StackResult:
    """Open the dump with ClrMD's DataTarget and extract the stack."""
    try:
        from Microsoft.Diagnostics.Runtime import DataTarget
    except Exception as exc:
        return StackResult(
            backend="none",
            dump_path=str(dump),
            error=f"Microsoft.Diagnostics.Runtime namespace not importable: {exc}",
        )

    try:
        target = DataTarget.LoadDump(str(dump))
    except Exception as exc:
        return StackResult(
            backend="clrmd",
            dump_path=str(dump),
            error=f"DataTarget.LoadDump failed: {exc}",
        )

    try:
        runtimes = list(target.ClrVersions)
        if not runtimes:
            return StackResult(
                backend="clrmd",
                dump_path=str(dump),
                error="no CLR runtime present in dump (pure-native crash?)",
            )
        runtime = runtimes[0].CreateRuntime()
        return _walk_faulting_thread(runtime, dump)
    except Exception as exc:
        return StackResult(
            backend="clrmd",
            dump_path=str(dump),
            error=f"stack walk failed: {exc}",
        )
    finally:
        try:
            target.Dispose()
        except Exception:
            pass


def _walk_faulting_thread(runtime: Any, dump: Path) -> StackResult:
    """Locate the thread that holds the current exception and unwind it.

    Falls back to the thread with the deepest stack when no managed
    exception is recorded (e.g. createdump captured a hung process
    rather than a crashing one).
    """
    threads = list(runtime.Threads)
    faulting: Any | None = next(
        (t for t in threads if getattr(t, "CurrentException", None) is not None),
        None,
    )
    if faulting is None:
        # Pick the deepest stack as a heuristic -- better than nothing
        # for hang/timeout dumps with no managed exception object.
        deepest = -1
        for t in threads:
            depth = sum(1 for _ in t.EnumerateStackTrace())
            if depth > deepest:
                deepest = depth
                faulting = t
    if faulting is None:
        return StackResult(
            backend="clrmd",
            dump_path=str(dump),
            error="no threads in dump",
        )

    exception_info: ExceptionInfo | None = None
    exc = getattr(faulting, "CurrentException", None)
    if exc is not None:
        exception_info = ExceptionInfo(
            code_hex=f"0x{int(getattr(exc, 'HResult', 0)) & 0xFFFFFFFF:08X}",
            name=str(getattr(exc, "Type", None) and exc.Type.Name) or "<unknown>",
            address_hex=f"0x{int(getattr(exc, 'Address', 0)):X}",
        )

    frames = [_to_frame(f) for f in faulting.EnumerateStackTrace()]

    return StackResult(
        backend="clrmd",
        dump_path=str(dump),
        exception=exception_info,
        faulting_thread_id=int(faulting.OSThreadId),
        frames=frames,
        error=None,
    )


def _to_frame(clr_frame: Any) -> StackFrame:
    """Convert a ClrMD ClrStackFrame to our StackFrame dataclass."""
    method = getattr(clr_frame, "Method", None)
    module = getattr(clr_frame, "ModuleName", None) or (
        method
        and getattr(method, "Type", None)
        and method.Type.Module
        and method.Type.Module.Name
    )
    if module is not None:
        # ClrMD returns full paths sometimes; reduce to basename
        module = Path(str(module)).name

    if method is not None:
        type_obj = getattr(method, "Type", None)
        return StackFrame(
            is_managed=True,
            module=str(module) if module else None,
            type=str(type_obj.Name) if type_obj else None,
            method=str(method.Name),
            signature=str(getattr(method, "Signature", None)) or None,
            md_token=f"0x{int(getattr(method, 'MetadataToken', 0)):08X}",
            il_offset_hex=_il_offset(clr_frame),
            ip_hex=f"0x{int(getattr(clr_frame, 'InstructionPointer', 0)):X}",
        )

    # Native frame
    return StackFrame(
        is_managed=False,
        module=str(module) if module else None,
        type=None,
        method=None,
        signature=None,
        md_token=None,
        il_offset_hex=None,
        ip_hex=f"0x{int(getattr(clr_frame, 'InstructionPointer', 0)):X}",
    )


def _il_offset(clr_frame: Any) -> str | None:
    """ClrMD exposes IL offset via Method.GetILOffset(IP). Be defensive."""
    method = getattr(clr_frame, "Method", None)
    if method is None:
        return None
    ip = int(getattr(clr_frame, "InstructionPointer", 0))
    try:
        offset = method.GetILOffset(ip)
    except Exception:
        return None
    if offset is None or int(offset) < 0:
        return None
    return f"0x{int(offset):X}"


def _reset_for_tests() -> None:
    """Clear init cache so each test starts fresh.

    Used only by the test suite; the production code initialises once
    per process and stays cached.
    """
    global _init_state, _init_error
    with _init_lock:
        _init_state = None
        _init_error = None
