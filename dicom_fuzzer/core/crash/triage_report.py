"""Markdown reports for triaged crash clusters.

After `CrashTriageEngine.cluster_crashes()` groups duplicate crashes, this
module renders one markdown file per unique cluster plus an index. The
output is human-readable triage notes -- not a substitute for a full
debugger session, but enough to:

- Confirm two crashes are or are not the same bug
- Pull the mutation sequence and reproduction command without opening JSON
- Prioritise which clusters to investigate first
"""

from __future__ import annotations

from pathlib import Path

from dicom_fuzzer.core.crash.crash_triage import CrashTriage, CrashTriageEngine
from dicom_fuzzer.core.crash.models import CrashRecord
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)

__all__ = ["write_cluster_reports"]


def write_cluster_reports(
    crashes: list[CrashRecord],
    output_dir: Path,
    engine: CrashTriageEngine | None = None,
) -> list[Path]:
    """Cluster crashes by signature and write one markdown report per cluster.

    Args:
        crashes: All crash records from a session.
        output_dir: Directory to write reports into. Created if missing.
        engine: Optional pre-existing CrashTriageEngine. If None, a fresh
            one is created. Reusing an engine is useful when the caller has
            already triaged the same crashes and wants the cached results.

    Returns:
        List of paths written, with the index first. Empty list if there
        were no crashes.

    """
    if not crashes:
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    eng = engine or CrashTriageEngine()
    clusters = eng.cluster_crashes(crashes)

    # Sort clusters by representative crash priority (descending)
    sorted_clusters = sorted(
        clusters.items(),
        key=lambda kv: eng.triage_crash(kv[1][0]).priority_score,
        reverse=True,
    )

    written: list[Path] = []
    index_path = output_dir / "index.md"
    written.append(index_path)

    index_lines = [
        "# Crash Triage Index",
        "",
        f"Total crashes: **{len(crashes)}**  ",
        f"Unique clusters: **{len(clusters)}**",
        "",
        "| # | Signature | Crashes | Priority | Severity | Summary |",
        "| -- | --------- | ------- | -------- | -------- | ------- |",
    ]

    for i, (signature, cluster_crashes) in enumerate(sorted_clusters, start=1):
        triage = eng.triage_crash(cluster_crashes[0])
        cluster_path = output_dir / f"cluster_{i:03d}_{signature[:8]}.md"
        _write_one_cluster(cluster_path, signature, cluster_crashes, triage)
        written.append(cluster_path)
        index_lines.append(
            f"| {i} | `{signature[:12]}` | {len(cluster_crashes)} | "
            f"{triage.priority_score:.1f} | {triage.severity.value} | "
            f"{triage.summary[:60]} |"
        )

    index_path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    logger.info(
        "Wrote %d cluster reports + index to %s", len(sorted_clusters), output_dir
    )
    return written


def _write_one_cluster(
    path: Path,
    signature: str,
    cluster_crashes: list[CrashRecord],
    triage: CrashTriage,
) -> None:
    """Render a single cluster's markdown file."""
    representative = cluster_crashes[0]
    lines: list[str] = [
        f"# Cluster {signature[:12]}",
        "",
        f"**Crashes in cluster:** {len(cluster_crashes)}  ",
        f"**Severity:** {triage.severity.value}  ",
        f"**Exploitability:** {triage.exploitability.value}  ",
        f"**Priority:** {triage.priority_score:.1f} / 100",
        "",
        "## Summary",
        "",
        triage.summary or "(no summary)",
        "",
    ]

    if triage.indicators:
        lines.append("## Indicators")
        lines.append("")
        for ind in triage.indicators:
            lines.append(f"- {ind}")
        lines.append("")

    if triage.tags:
        lines.append(f"**Tags:** {', '.join(sorted(triage.tags))}")
        lines.append("")

    lines.append("## Representative Crash")
    lines.append("")
    lines.append(f"- **crash_id**: `{representative.crash_id}`")
    lines.append(f"- **fuzzed_file_path**: `{representative.fuzzed_file_path}`")
    lines.append(f"- **timestamp**: {representative.timestamp.isoformat()}")
    lines.append(f"- **crash_type**: `{representative.crash_type}`")
    if representative.return_code is not None:
        lines.append(f"- **return_code**: `{representative.return_code}`")
    if representative.exception_type:
        lines.append(f"- **exception_type**: `{representative.exception_type}`")

    if representative.exception_message:
        lines.append("")
        lines.append("### Exception message")
        lines.append("")
        lines.append("```")
        lines.append(representative.exception_message.strip())
        lines.append("```")

    if representative.stack_trace:
        lines.append("")
        lines.append("### Stack trace")
        lines.append("")
        lines.append("```")
        lines.append(representative.stack_trace.strip())
        lines.append("```")

    if representative.mutation_sequence:
        lines.append("")
        lines.append("### Mutation sequence")
        lines.append("")
        for step in representative.mutation_sequence:
            lines.append(f"- `{step}`")

    if representative.reproduction_command:
        lines.append("")
        lines.append("### Reproduction")
        lines.append("")
        lines.append("```sh")
        lines.append(representative.reproduction_command)
        lines.append("```")

    if triage.recommendations:
        lines.append("")
        lines.append("## Recommendations")
        lines.append("")
        for rec in triage.recommendations:
            lines.append(f"- {rec}")

    if len(cluster_crashes) > 1:
        lines.append("")
        lines.append("## Other crashes in cluster")
        lines.append("")
        lines.append("| crash_id | fuzzed_file_path |")
        lines.append("| -------- | ---------------- |")
        for c in cluster_crashes[1:]:
            lines.append(f"| `{c.crash_id}` | `{c.fuzzed_file_path}` |")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
