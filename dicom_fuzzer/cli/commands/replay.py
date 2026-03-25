"""Replay subcommand - decompose fuzzed DICOM files into per-mutation variants.

Applies each recorded mutation in isolation against the original seed file,
producing one output file per mutation method. This enables delta debugging:
open each variant in the target viewer to isolate which specific mutation
triggered a crash.

Usage:
    dicom-fuzzer replay --decompose <fuzzed_file.dcm>
    dicom-fuzzer replay --decompose <fuzzed_file.dcm> --session session.json
    dicom-fuzzer replay --decompose <fuzzed_file.dcm> --output-dir ./decomposed/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

import pydicom

from dicom_fuzzer.cli.base import SubcommandBase
from dicom_fuzzer.utils.logger import get_logger

__all__ = ["ReplayCommand", "main"]

logger = get_logger(__name__)

# Lazy strategy registry — populated on first use, then cached
_STRATEGY_REGISTRY: dict[str, Any] | None = None


def _get_strategy_registry() -> dict[str, Any]:
    """Build and cache the strategy name -> fuzzer instance mapping."""
    global _STRATEGY_REGISTRY
    if _STRATEGY_REGISTRY is not None:
        return _STRATEGY_REGISTRY

    from dicom_fuzzer.attacks.format import (
        CalibrationFuzzer,
        CompressedPixelFuzzer,
        ConformanceFuzzer,
        DictionaryFuzzer,
        EncapsulatedPdfFuzzer,
        EncodingFuzzer,
        HeaderFuzzer,
        MetadataFuzzer,
        NuclearMedicineFuzzer,
        PetFuzzer,
        PixelFuzzer,
        PrivateTagFuzzer,
        ReferenceFuzzer,
        RTDoseFuzzer,
        RTStructureSetFuzzer,
        SegmentationFuzzer,
        SequenceFuzzer,
        StructureFuzzer,
    )

    instances = [
        CalibrationFuzzer(),
        CompressedPixelFuzzer(),
        ConformanceFuzzer(),
        DictionaryFuzzer(),
        EncapsulatedPdfFuzzer(),
        EncodingFuzzer(),
        HeaderFuzzer(),
        MetadataFuzzer(),
        NuclearMedicineFuzzer(),
        PetFuzzer(),
        PixelFuzzer(),
        PrivateTagFuzzer(),
        ReferenceFuzzer(),
        RTDoseFuzzer(),
        RTStructureSetFuzzer(),
        SegmentationFuzzer(),
        SequenceFuzzer(),
        StructureFuzzer(),
    ]
    _STRATEGY_REGISTRY = {inst.strategy_name: inst for inst in instances}
    return _STRATEGY_REGISTRY


def _find_session(
    fuzzed_path: Path, explicit_session: Path | None
) -> tuple[Path, dict[str, Any]] | None:
    """Locate the session JSON that recorded this fuzzed file.

    If ``explicit_session`` is given, loads it directly.  Otherwise globs
    ``artifacts/reports/json/session_*.json`` (newest first) and returns the
    first one that contains a ``fuzzed_files`` record whose ``output_file``
    stem matches ``fuzzed_path.stem``.

    Returns:
        (session_path, session_data) or None if no match found.

    """
    if explicit_session is not None:
        if not explicit_session.exists():
            return None
        with open(explicit_session) as f:
            return explicit_session, json.load(f)

    stem = fuzzed_path.stem
    candidates = sorted(Path("artifacts/reports/json").glob("session_*.json"))
    for session_path in reversed(candidates):  # newest first
        try:
            with open(session_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        for record in data.get("fuzzed_files", []):
            if Path(record.get("output_file", "")).stem == stem:
                return session_path, data

    return None


def _find_fuzzed_record(
    session_data: dict[str, Any], fuzzed_path: Path
) -> dict[str, Any] | None:
    """Return the fuzzed_files entry whose output_file stem matches fuzzed_path."""
    stem = fuzzed_path.stem
    for record in session_data.get("fuzzed_files", []):
        if Path(record.get("output_file", "")).stem == stem:
            return cast(dict[str, Any], record)
    return None


def _update_reproduction_commands(
    session_path: Path,
    session_data: dict,
    fuzzed_record: dict,
    fuzzed_path: Path,
) -> None:
    """Set reproduction_command on crash records that reference this fuzzed file.

    Writes the updated session JSON back atomically (write-to-temp, then rename).
    """
    file_id = fuzzed_record.get("file_id")
    reproduction_cmd = (
        f"dicom-fuzzer replay --decompose {fuzzed_path} --session {session_path}"
    )

    updated = 0
    for crash in session_data.get("crashes", []):
        if crash.get("fuzzed_file_id") == file_id:
            crash["reproduction_command"] = reproduction_cmd
            updated += 1

    if updated == 0:
        return

    tmp = session_path.with_suffix(".tmp")
    try:
        with open(tmp, "w") as f:
            json.dump(session_data, f, indent=2, default=str)
        tmp.replace(session_path)
        print(f"[+] Updated {updated} crash record(s) with reproduction_command")
    except OSError as e:
        print(f"[!] Could not update session file: {e}", file=sys.stderr)
        tmp.unlink(missing_ok=True)


def _decompose(
    fuzzed_path: Path,
    fuzzed_record: dict,
    output_dir: Path,
    session_path: Path,
    session_data: dict,
) -> int:
    """Apply each mutation in isolation and write the resulting DICOM files.

    For each MutationRecord:
    - If ``variant`` is set (comma-joined method names), apply each method
      separately against a fresh copy of the source file.
    - If ``variant`` is None, call ``strategy.mutate()`` on a fresh copy.

    Output filenames: ``{stem}_mut{i:02d}_{strategy_name}_{method_name}.dcm``
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    source_file = fuzzed_record.get("source_file")
    if not source_file or not Path(source_file).exists():
        print(f"[-] Source file not found: {source_file}", file=sys.stderr)
        return 1

    registry = _get_strategy_registry()
    mutations = fuzzed_record.get("mutations", [])
    stem = fuzzed_path.stem
    written: list[Path] = []

    for i, mutation in enumerate(mutations):
        strategy_name = mutation.get("strategy_name", "")
        variant = mutation.get("variant")
        strategy = registry.get(strategy_name)

        if strategy is None:
            print(
                f"[!] Unknown strategy '{strategy_name}' for mutation {i}, skipping",
                file=sys.stderr,
            )
            continue

        if variant:
            for method_name in [m.strip() for m in variant.split(",")]:
                method = getattr(strategy, method_name, None)
                if method is None:
                    print(
                        f"[!] Method '{method_name}' not found on {strategy_name}, skipping",
                        file=sys.stderr,
                    )
                    continue
                ds = pydicom.dcmread(source_file, force=True)
                try:
                    ds = method(ds)
                except Exception as e:
                    logger.debug(
                        "Method %s.%s failed: %s", strategy_name, method_name, e
                    )
                    continue
                out_name = (
                    f"{stem}_mut{i:02d}_{strategy_name}_{method_name.lstrip('_')}.dcm"
                )
                out_path = output_dir / out_name
                ds.save_as(str(out_path), write_like_original=False)
                written.append(out_path)
                print(f"[+] {out_path}")
        else:
            ds = pydicom.dcmread(source_file, force=True)
            try:
                ds = strategy.mutate(ds)
            except Exception as e:
                logger.debug("Strategy %s.mutate() failed: %s", strategy_name, e)
                continue
            out_name = f"{stem}_mut{i:02d}_{strategy_name}_full.dcm"
            out_path = output_dir / out_name
            ds.save_as(str(out_path), write_like_original=False)
            written.append(out_path)
            print(f"[+] {out_path}")

    print(f"\n[i] Wrote {len(written)} decomposed files to {output_dir}")

    _update_reproduction_commands(
        session_path, session_data, fuzzed_record, fuzzed_path
    )

    return 0


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser for replay subcommand."""
    parser = argparse.ArgumentParser(
        prog="dicom-fuzzer replay",
        description="Replay and decompose fuzzed DICOM files into per-mutation variants",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  dicom-fuzzer replay --decompose fuzzed.dcm
  dicom-fuzzer replay --decompose fuzzed.dcm --session artifacts/reports/json/session_abc.json
  dicom-fuzzer replay --decompose fuzzed.dcm --output-dir ./decomposed/
        """,
    )

    parser.add_argument(
        "--decompose",
        metavar="FUZZED_FILE",
        dest="fuzzed_file",
        type=Path,
        required=True,
        help="Fuzzed DICOM file to decompose into per-mutation variants",
    )

    parser.add_argument(
        "--session",
        type=Path,
        default=None,
        help=(
            "Session JSON file containing mutation records "
            "(auto-discovered from artifacts/reports/json/ if not specified)"
        ),
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        dest="output_dir",
        help="Output directory for decomposed files (default: <fuzzed_dir>/decomposed/)",
    )

    return parser


class ReplayCommand(SubcommandBase):
    """Decompose a fuzzed DICOM file into per-mutation variants."""

    @classmethod
    def build_parser(cls) -> argparse.ArgumentParser:
        """Return the argument parser for this subcommand."""
        return create_parser()

    @classmethod
    def execute(cls, args: argparse.Namespace) -> int:
        """Run the replay --decompose subcommand."""
        fuzzed_path: Path = args.fuzzed_file
        if not fuzzed_path.exists():
            print(f"[-] File not found: {fuzzed_path}", file=sys.stderr)
            return 1

        explicit_session: Path | None = args.session
        result = _find_session(fuzzed_path, explicit_session)

        if result is None:
            if explicit_session:
                print(
                    f"[-] Session file not found: {explicit_session}", file=sys.stderr
                )
            else:
                print(
                    f"[-] No session JSON found for '{fuzzed_path.name}'. "
                    "Use --session to specify one.",
                    file=sys.stderr,
                )
            return 1

        session_path, session_data = result
        fuzzed_record = _find_fuzzed_record(session_data, fuzzed_path)
        if fuzzed_record is None:
            print(
                f"[-] No record for '{fuzzed_path.name}' in {session_path}",
                file=sys.stderr,
            )
            return 1

        output_dir = args.output_dir or fuzzed_path.parent / "decomposed"
        return _decompose(
            fuzzed_path, fuzzed_record, output_dir, session_path, session_data
        )


def main(argv: list[str] | None = None) -> int:
    """Main entry point for replay subcommand."""
    return ReplayCommand.main(argv)


if __name__ == "__main__":
    sys.exit(main())
