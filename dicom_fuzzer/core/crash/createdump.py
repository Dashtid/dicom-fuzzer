r"""On-demand minidump capture via ``createdump.exe``.

``DOTNET_DbgEnableMiniDump`` (set by ``gui_runner`` when ``--dump-dir``
is enabled) handles the *crash* path: the .NET runtime invokes
createdump itself when an uncatchable exception fires. This module
handles the *hang* path: when our timeout fires and the target is
still alive, we want a dump of the *current* state so the cluster
report can show which method was looping or deadlocked.

createdump ships with every .NET runtime install at::

    %ProgramFiles%\\dotnet\\shared\\Microsoft.NETCore.App\\<ver>\\createdump.exe

so the user never installs it separately. We discover the newest
matching binary and invoke it against the still-running PID.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

# Standard install locations to probe, newest framework version first.
# The %ProgramFiles% expansion covers both 64- and 32-bit hosts.
_PROGRAM_FILES_CANDIDATES = (
    r"%ProgramFiles%\dotnet\shared\Microsoft.NETCore.App",
    r"%ProgramFiles(x86)%\dotnet\shared\Microsoft.NETCore.App",
)


def find_createdump() -> Path | None:
    """Locate the highest-version createdump.exe under standard paths.

    Returns None when no .NET runtime is installed. The standard
    install path is Windows-only; on other OSes the directories below
    simply don't exist and we fall through to the empty-candidates
    return. Callers should treat None as "hang dumps unavailable" and
    continue without a dump.
    """
    candidates: list[Path] = []
    for raw in _PROGRAM_FILES_CANDIDATES:
        expanded = os.path.expandvars(raw)
        if "%" in expanded:
            continue  # env var wasn't set; skip
        base = Path(expanded)
        if not base.is_dir():
            continue
        for version_dir in base.iterdir():
            if not version_dir.is_dir():
                continue
            exe = version_dir / "createdump.exe"
            if exe.is_file():
                candidates.append(exe)

    if not candidates:
        return None

    # Sort by parent dir name (the version string). Newer .NET versions
    # have newer createdump fixes — we want the latest available.
    def version_key(p: Path) -> tuple[int, ...]:
        parts = p.parent.name.split(".")
        try:
            return tuple(int(x) for x in parts[:3])
        except ValueError:
            return (0,)

    return max(candidates, key=version_key)


def capture_dump(
    pid: int,
    output_path: Path | str,
    timeout_sec: float = 30.0,
    full_heap: bool = True,
) -> tuple[bool, str | None]:
    """Run createdump against a live PID.

    Args:
        pid: Process to dump. Must still be alive when invoked.
        output_path: Destination .dmp filename.
        timeout_sec: Wall-clock cap on createdump itself. 30s is plenty;
            on a 50 MB heap createdump typically finishes in 1-3s.
        full_heap: True -> ``--withheap`` (default; ClrMD needs heap
            data to resolve managed objects). False -> ``--normal``
            (smaller dump, no heap; only thread stacks).

    Returns:
        (success, error_message). On success error_message is None.

    """
    exe = find_createdump()
    if exe is None:
        return False, (
            "createdump.exe not found on this host; .NET runtime "
            "(net5+) does not appear to be installed."
        )

    out = Path(output_path).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    cmd = [str(exe), "-f", str(out)]
    cmd.append("--withheap" if full_heap else "--normal")
    cmd.append(str(pid))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"createdump timed out after {timeout_sec}s"
    except OSError as exc:
        return False, f"failed to invoke createdump: {exc}"

    if proc.returncode != 0:
        return False, (
            f"createdump exited {proc.returncode}: "
            f"{proc.stderr.strip()[:300] or proc.stdout.strip()[:300]!r}"
        )

    if not out.is_file():
        return False, f"createdump reported success but {out} not present"

    logger.info("createdump wrote %s (pid=%d, %d bytes)", out, pid, out.stat().st_size)
    return True, None
