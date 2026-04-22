"""pydicom smoke harness.

Walks a directory of (likely-malformed) DICOM files, parses each with
pydicom and traverses the dataset, bucketing exceptions by
(type_name, message_stem). Emits a JSON report plus a short markdown
summary identifying candidate pydicom bugs worth filing upstream.

Not part of the CLI. One-shot analysis script invoked directly.

Usage:
    python examples/pydicom-smoke/pydicom_smoke.py <corpus_dir> [--out DIR] [--timeout SEC]

The corpus is expected to contain files produced by a dicom-fuzzer
campaign (so most files ARE malformed on purpose). We are looking for
exceptions whose traceback passes through pydicom internals rather than
`pydicom.errors`, and for crash classes that no well-behaved parser
should raise on input: RecursionError, MemoryError, segfault, hang.
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import sys
import traceback
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pydicom

# Exception classes pydicom is EXPECTED to raise on malformed input.
# These go in the "boring" bucket and don't need investigation, whether
# or not the traceback passes through pydicom internals -- the exception
# is explicitly designed to report malformed input.
_EXPECTED_TYPES = {
    "InvalidDicomError",
    "BytesLengthException",  # VR length/multiple mismatch; by design
    "NotImplementedError",  # some transfer syntaxes
    "KeyError",
    "AttributeError",
    "ValueError",
    "TypeError",
    "OverflowError",
    "UnicodeDecodeError",
    "UnicodeEncodeError",
    "FileNotFoundError",
    "IsADirectoryError",
    "PermissionError",
    "EOFError",
}

# Exception classes that indicate a REAL parser bug. Any of these on
# input should be a pydicom issue.
_INTERESTING_TYPES = {
    "RecursionError",
    "MemoryError",
    "SystemError",
    "AssertionError",
    "RuntimeError",
}


def _message_stem(msg: str, max_len: int = 80) -> str:
    """Strip variable bits (numbers, hex, paths) so similar messages cluster."""
    # Replace runs of digits and hex with placeholders
    s = re.sub(r"0x[0-9a-fA-F]+", "0xN", msg)
    s = re.sub(r"\d+", "N", s)
    # Normalize whitespace
    s = " ".join(s.split())
    return s[:max_len]


def _handler_alarm(signum: int, frame: Any) -> None:
    raise TimeoutError("per-file parse timeout exceeded")


def _traverse_dataset(ds: pydicom.Dataset) -> int:
    """Walk every element and read its value. Returns element count.

    The traversal is what exercises pydicom's value-parsing code paths
    (IS, DS, PN, etc.). Bare `dcmread` only parses the tag structure.

    Uses an explicit stack rather than recursion so this helper does not
    consume Python frames proportional to sequence nesting depth; that
    way any RecursionError we observe comes from pydicom's own value
    conversion and not from our own traversal.
    """
    n = 0
    stack: list[pydicom.Dataset] = [ds]
    while stack:
        current = stack.pop()
        for elem in current:
            n += 1
            _ = elem.value  # triggers VR conversion
            if elem.VR == "SQ" and elem.value is not None:
                for item in elem.value:
                    stack.append(item)
    return n


def _parse_one(path: Path, timeout_sec: int) -> dict[str, Any]:
    """Parse one file, return a result dict describing what happened."""
    # Per-file SIGALRM timeout (Unix only; on Windows this no-ops and we
    # fall back to the outer campaign-level timeout). pydicom can hang on
    # some pathological sequence structures -- worth catching even if
    # only works on POSIX.
    had_alarm = False
    sig_alarm = getattr(signal, "alarm", None)  # POSIX only
    sigalrm = getattr(signal, "SIGALRM", None)
    if sig_alarm is not None and sigalrm is not None:
        signal.signal(sigalrm, _handler_alarm)
        sig_alarm(timeout_sec)
        had_alarm = True

    try:
        ds = pydicom.dcmread(str(path), force=True)
        elem_count = _traverse_dataset(ds)
        return {"status": "ok", "elements": elem_count}
    except Exception as e:
        tb = traceback.format_exc()
        # Determine whether the traceback passes through pydicom
        # internals (interesting) vs. surfaces directly from user code
        # (less interesting -- malformed file, handled).
        in_pydicom_internals = any(
            "pydicom" in line and "pydicom/errors" not in line
            for line in tb.splitlines()
            if line.lstrip().startswith("File ")
        )
        return {
            "status": "error",
            "type": type(e).__name__,
            "message": str(e),
            "stem": _message_stem(str(e)),
            "traceback": tb,
            "in_pydicom_internals": in_pydicom_internals,
        }
    finally:
        if had_alarm and sig_alarm is not None:
            sig_alarm(0)


def run_smoke(corpus: Path, out_dir: Path, timeout_sec: int) -> dict[str, Any]:
    """Run pydicom against every .dcm in corpus; emit report."""
    out_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(corpus.glob("*.dcm"))
    if not files:
        raise SystemExit(f"no .dcm files in {corpus}")

    print(f"Scanning {len(files)} files in {corpus}")

    buckets: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "examples": [], "in_internals": False, "traceback": None}
    )
    ok_count = 0
    timeouts: list[str] = []

    for i, f in enumerate(files, 1):
        if i % 50 == 0 or i == len(files):
            print(f"  [{i}/{len(files)}]")
        result = _parse_one(f, timeout_sec)
        if result["status"] == "ok":
            ok_count += 1
            continue
        if result["type"] == "TimeoutError":
            timeouts.append(f.name)
        key = (result["type"], result["stem"])
        bucket = buckets[key]
        bucket["count"] += 1
        if len(bucket["examples"]) < 3:
            bucket["examples"].append(f.name)
        if result["in_pydicom_internals"]:
            bucket["in_internals"] = True
        if bucket["traceback"] is None:
            bucket["traceback"] = result["traceback"]

    # Classify buckets
    report_buckets = []
    for (etype, stem), data in sorted(buckets.items(), key=lambda kv: -kv[1]["count"]):
        if etype in _INTERESTING_TYPES:
            severity = "interesting"
        elif etype in _EXPECTED_TYPES:
            # Designed-for-malformed-input exceptions are always expected,
            # regardless of whether the traceback traverses pydicom code.
            severity = "expected"
        elif data["in_internals"]:
            severity = "review"
        else:
            severity = "expected"
        report_buckets.append(
            {
                "severity": severity,
                "type": etype,
                "stem": stem,
                "count": data["count"],
                "in_pydicom_internals": data["in_internals"],
                "example_files": data["examples"],
                "traceback": data["traceback"],
            }
        )

    report = {
        "corpus": str(corpus),
        "timestamp": datetime.now(UTC).isoformat(),
        "total_files": len(files),
        "ok": ok_count,
        "errors": sum(b["count"] for b in report_buckets),
        "timeouts": timeouts,
        "buckets": report_buckets,
    }

    json_path = out_dir / "pydicom_smoke_report.json"
    json_path.write_text(json.dumps(report, indent=2))
    print(f"JSON report: {json_path}")

    md_path = out_dir / "pydicom_smoke_summary.md"
    md_path.write_text(_render_markdown(report))
    print(f"Markdown summary: {md_path}")

    return report


def _render_markdown(report: dict[str, Any]) -> str:
    """Render the report as a short markdown summary."""
    lines = [
        "# pydicom smoke report",
        "",
        f"- **Corpus:** `{report['corpus']}`",
        f"- **Timestamp:** {report['timestamp']}",
        f"- **Files scanned:** {report['total_files']}",
        f"- **Parsed cleanly:** {report['ok']}",
        f"- **Errors:** {report['errors']}",
        f"- **Timeouts:** {len(report['timeouts'])}",
        "",
    ]
    for label in ("interesting", "review", "expected"):
        subset = [b for b in report["buckets"] if b["severity"] == label]
        if not subset:
            continue
        lines.append(f"## {label.title()} clusters ({len(subset)})")
        lines.append("")
        lines.append("| Type | Count | In pydicom internals | Stem |")
        lines.append("| --- | --- | --- | --- |")
        for b in subset[:15]:
            escaped_stem = b["stem"].replace("|", "\\|")
            yes_no = "yes" if b["in_pydicom_internals"] else "no"
            lines.append(
                f"| `{b['type']}` | {b['count']} | {yes_no} | {escaped_stem} |"
            )
        lines.append("")
        if label == "interesting" and subset:
            lines.append("### Example tracebacks")
            lines.append("")
            for b in subset[:3]:
                lines.append(f"**{b['type']} — {b['stem']}**")
                lines.append("")
                lines.append(f"Example: `{b['example_files'][0]}`")
                lines.append("")
                lines.append("```")
                lines.append(b["traceback"].strip())
                lines.append("```")
                lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse args, run smoke, print cluster counts."""
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("corpus", type=Path, help="directory containing .dcm files")
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output directory (default: artifacts/pydicom-smoke/<timestamp>/)",
    )
    p.add_argument(
        "--timeout", type=int, default=30, help="per-file parse timeout in seconds"
    )
    args = p.parse_args(argv)

    if args.out is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.out = Path("artifacts/pydicom-smoke") / ts

    report = run_smoke(args.corpus, args.out, args.timeout)

    interesting = sum(1 for b in report["buckets"] if b["severity"] == "interesting")
    review = sum(1 for b in report["buckets"] if b["severity"] == "review")
    print()
    print(f"interesting clusters: {interesting}")
    print(f"review clusters: {review}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
