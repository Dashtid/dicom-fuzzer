#!/usr/bin/env python3
"""Seed Corpus Import Tool

Import real DICOM files into the fuzzer's corpus for use as fuzzing seeds.
Supports directory scanning, validation, optional PixelData stripping, and metadata generation.

USAGE:
    python scripts/import_seed_corpus.py /path/to/dicom/files --output ./corpus
    python scripts/import_seed_corpus.py /path/to/dicom/files --strip-pixels --output ./corpus
    python scripts/import_seed_corpus.py /path/to/dicom/files --max-size 1MB --output ./corpus

FEATURES:
    - Recursive directory scanning for .dcm files
    - DICOM format validation (header check)
    - Optional PixelData removal (focuses fuzzing on parser, not image processing)
    - File size filtering (skip huge files that slow fuzzing)
    - Modality categorization (CT, MRI, US, etc.)
    - Duplicate detection via hash
    - Corpus statistics report (JSON + human-readable)
"""

import argparse
import hashlib
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import pydicom
    from pydicom.dataset import Dataset
except ImportError:
    print("[!] Error: pydicom not installed. Run: pip install pydicom")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class CorpusImporter:
    """Import real DICOM files as fuzzing seeds."""

    def __init__(
        self,
        source_dir: Path,
        output_dir: Path,
        strip_pixels: bool = False,
        max_file_size: int | None = None,
        min_file_size: int | None = 100,
        skip_corrupted: bool = True,
    ):
        """Initialize corpus importer.

        Args:
            source_dir: Directory containing DICOM files to import
            output_dir: Directory to save processed corpus
            strip_pixels: Remove PixelData tag to focus on parser fuzzing
            max_file_size: Skip files larger than this (bytes)
            min_file_size: Skip files smaller than this (bytes)
            skip_corrupted: Continue on corrupted files vs fail

        """
        self.source_dir = Path(source_dir)
        self.output_dir = Path(output_dir)
        self.strip_pixels = strip_pixels
        self.max_file_size = max_file_size
        self.min_file_size = min_file_size
        self.skip_corrupted = skip_corrupted

        # Statistics
        self.stats: dict[str, Any] = {
            "files_found": 0,
            "files_imported": 0,
            "files_skipped": 0,
            "files_corrupted": 0,
            "duplicates_skipped": 0,
            "total_bytes_original": 0,
            "total_bytes_processed": 0,
            "modalities": {},
            "file_sizes": [],
            "errors": [],
        }

        # Track seen file hashes to detect duplicates
        self.seen_hashes: set[str] = set()

        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file for duplicate detection."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _validate_dicom(self, file_path: Path) -> bool:
        """Quick DICOM validation without full parse.

        Checks for DICOM magic bytes (128-byte preamble + 'DICM').
        """
        try:
            with open(file_path, "rb") as f:
                preamble = f.read(132)  # 128 bytes preamble + 4 bytes 'DICM'
                if len(preamble) < 132:
                    return False
                if preamble[128:132] != b"DICM":
                    return False
            return True
        except Exception as e:
            logger.debug(f"Validation failed for {file_path}: {e}")
            return False

    def _process_file(self, file_path: Path) -> tuple[Dataset, dict] | None:
        """Process a single DICOM file.

        Returns:
            Tuple of (dataset, metadata) or None if should skip

        """
        # Check file size constraints
        file_size = file_path.stat().st_size
        if self.min_file_size and file_size < self.min_file_size:
            logger.debug(f"Skipping {file_path.name}: too small ({file_size} bytes)")
            self.stats["files_skipped"] += 1
            return None

        if self.max_file_size and file_size > self.max_file_size:
            logger.debug(f"Skipping {file_path.name}: too large ({file_size} bytes)")
            self.stats["files_skipped"] += 1
            return None

        # Check for duplicates
        file_hash = self._calculate_file_hash(file_path)
        if file_hash in self.seen_hashes:
            logger.debug(f"Skipping {file_path.name}: duplicate")
            self.stats["duplicates_skipped"] += 1
            return None
        self.seen_hashes.add(file_hash)

        # Validate DICOM format
        if not self._validate_dicom(file_path):
            logger.warning(f"Invalid DICOM file (missing header): {file_path}")
            self.stats["files_corrupted"] += 1
            if not self.skip_corrupted:
                raise ValueError(f"Corrupted DICOM file: {file_path}")
            return None

        # Load DICOM dataset
        try:
            dataset = pydicom.dcmread(file_path, force=True)
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            self.stats["files_corrupted"] += 1
            self.stats["errors"].append({"file": str(file_path), "error": str(e)})
            if not self.skip_corrupted:
                raise
            return None

        # Extract metadata
        metadata = {
            "original_path": str(file_path),
            "original_size": file_size,
            "hash": file_hash,
            "modality": str(dataset.get("Modality", "UNKNOWN")),
            "sop_class_uid": str(dataset.get("SOPClassUID", "UNKNOWN")),
            "transfer_syntax": str(dataset.file_meta.TransferSyntaxUID)
            if hasattr(dataset, "file_meta")
            else "UNKNOWN",
            "has_pixel_data": hasattr(dataset, "PixelData"),
            "num_tags": len(dataset),
            "import_date": datetime.now(UTC).isoformat(),
        }

        # Optionally strip PixelData
        if self.strip_pixels and hasattr(dataset, "PixelData"):
            original_size = file_size
            del dataset.PixelData
            # Also remove pixel-related tags
            for tag in ["PixelData", "PixelPaddingValue", "PixelPaddingRangeLimit"]:
                if tag in dataset:
                    delattr(dataset, tag)
            metadata["pixel_data_stripped"] = True
            metadata["original_size_with_pixels"] = original_size
            logger.debug(f"Stripped PixelData from {file_path.name}")
        else:
            metadata["pixel_data_stripped"] = False

        return dataset, metadata

    def import_corpus(self) -> dict:
        """Import all DICOM files from source directory.

        Returns:
            Statistics dictionary

        """
        logger.info(f"Scanning for DICOM files in: {self.source_dir}")

        # Find all .dcm files recursively
        dicom_files = list(self.source_dir.rglob("*.dcm"))
        self.stats["files_found"] = len(dicom_files)

        if not dicom_files:
            logger.warning(f"No .dcm files found in {self.source_dir}")
            return self.stats

        logger.info(f"Found {len(dicom_files)} DICOM files")

        # Process each file
        for idx, file_path in enumerate(dicom_files, 1):
            logger.info(f"[{idx}/{len(dicom_files)}] Processing: {file_path.name}")

            result = self._process_file(file_path)
            if result is None:
                continue

            dataset, metadata = result

            # Generate output filename
            output_filename = f"seed_{self.stats['files_imported']:05d}.dcm"
            output_path = self.output_dir / output_filename

            # Save processed DICOM file
            try:
                dataset.save_as(output_path, enforce_file_format=True)
                processed_size = output_path.stat().st_size

                # Save metadata
                metadata_path = output_path.with_suffix(".json")
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)

                # Update statistics
                self.stats["files_imported"] += 1
                self.stats["total_bytes_original"] += metadata["original_size"]
                self.stats["total_bytes_processed"] += processed_size
                self.stats["file_sizes"].append(processed_size)

                # Track modality distribution
                modality = metadata["modality"]
                self.stats["modalities"][modality] = (
                    self.stats["modalities"].get(modality, 0) + 1
                )

                logger.info(
                    f"  [OK] Imported as {output_filename} "
                    f"({processed_size} bytes, {modality})"
                )

            except Exception as e:
                logger.error(f"  [FAIL] Failed to save {output_filename}: {e}")
                self.stats["errors"].append(
                    {"file": str(file_path), "error": f"Save failed: {e}"}
                )
                if not self.skip_corrupted:
                    raise

        return self.stats

    def generate_report(self) -> str:
        """Generate human-readable corpus import report."""
        report_lines = [
            "=" * 80,
            "DICOM SEED CORPUS IMPORT REPORT",
            "=" * 80,
            "",
            f"Source Directory: {self.source_dir}",
            f"Output Directory: {self.output_dir}",
            f"Import Date: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "SUMMARY:",
            f"  Files Found:      {self.stats['files_found']}",
            f"  Files Imported:   {self.stats['files_imported']}",
            f"  Files Skipped:    {self.stats['files_skipped']}",
            f"  Duplicates:       {self.stats['duplicates_skipped']}",
            f"  Corrupted:        {self.stats['files_corrupted']}",
            "",
            "FILE SIZE:",
            f"  Original Total:   {self._format_bytes(self.stats['total_bytes_original'])}",
            f"  Processed Total:  {self._format_bytes(self.stats['total_bytes_processed'])}",
        ]

        if self.strip_pixels:
            reduction = (
                self.stats["total_bytes_original"] - self.stats["total_bytes_processed"]
            )
            pct = (
                (reduction / self.stats["total_bytes_original"] * 100)
                if self.stats["total_bytes_original"] > 0
                else 0
            )
            report_lines.append(
                f"  Reduction:        {self._format_bytes(reduction)} ({pct:.1f}%)"
            )

        if self.stats["file_sizes"]:
            report_lines.extend(
                [
                    f"  Average Size:     {self._format_bytes(sum(self.stats['file_sizes']) / len(self.stats['file_sizes']))}",
                    f"  Min Size:         {self._format_bytes(min(self.stats['file_sizes']))}",
                    f"  Max Size:         {self._format_bytes(max(self.stats['file_sizes']))}",
                ]
            )

        report_lines.append("")
        report_lines.append("MODALITY DISTRIBUTION:")
        for modality, count in sorted(
            self.stats["modalities"].items(), key=lambda x: x[1], reverse=True
        ):
            pct = (
                (count / self.stats["files_imported"] * 100)
                if self.stats["files_imported"] > 0
                else 0
            )
            report_lines.append(f"  {modality:15s} {count:5d} ({pct:5.1f}%)")

        if self.stats["errors"]:
            report_lines.append("")
            report_lines.append(f"ERRORS ({len(self.stats['errors'])}):")
            for error in self.stats["errors"][:10]:  # Show first 10
                report_lines.append(f"  - {error['file']}: {error['error']}")
            if len(self.stats["errors"]) > 10:
                report_lines.append(
                    f"  ... and {len(self.stats['errors']) - 10} more errors"
                )

        report_lines.append("")
        report_lines.append("=" * 80)

        return "\n".join(report_lines)

    def _format_bytes(self, bytes_val: float) -> str:
        """Format bytes as human-readable string."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} TB"


def parse_size(size_str: str) -> int:
    """Parse human-readable size string to bytes."""
    size_str = size_str.upper().strip()
    multipliers = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}

    for suffix, multiplier in multipliers.items():
        if size_str.endswith(suffix):
            return int(float(size_str[: -len(suffix)]) * multiplier)

    # No suffix, assume bytes
    return int(size_str)


def main() -> None:
    """Import real DICOM files as fuzzing seed corpus."""
    parser = argparse.ArgumentParser(
        description="Import real DICOM files as fuzzing seed corpus",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Import all DICOM files from a directory
  python scripts/import_seed_corpus.py /path/to/dicom --output ./corpus

  # Strip PixelData to focus on parser fuzzing
  python scripts/import_seed_corpus.py /path/to/dicom --strip-pixels --output ./corpus

  # Skip large files (> 1MB)
  python scripts/import_seed_corpus.py /path/to/dicom --max-size 1MB --output ./corpus

  # Verbose output with debugging
  python scripts/import_seed_corpus.py /path/to/dicom --output ./corpus -v
        """,
    )

    parser.add_argument(
        "source", type=Path, help="Source directory containing DICOM files"
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("./artifacts/corpus"),
        help="Output directory for processed corpus (default: ./corpus)",
    )
    parser.add_argument(
        "--strip-pixels",
        action="store_true",
        help="Remove PixelData tag to focus fuzzing on parser (recommended)",
    )
    parser.add_argument(
        "--max-size",
        type=str,
        help="Skip files larger than this (e.g., '1MB', '500KB')",
    )
    parser.add_argument(
        "--min-size",
        type=str,
        default="100",
        help="Skip files smaller than this (default: 100 bytes)",
    )
    parser.add_argument(
        "--fail-on-error",
        action="store_true",
        help="Stop on first error instead of skipping corrupted files",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose debug output"
    )

    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate source directory
    if not args.source.exists():
        logger.error(f"Source directory does not exist: {args.source}")
        sys.exit(1)

    if not args.source.is_dir():
        logger.error(f"Source path is not a directory: {args.source}")
        sys.exit(1)

    # Parse size constraints
    max_size = parse_size(args.max_size) if args.max_size else None
    min_size = parse_size(args.min_size) if args.min_size else 100

    # Create importer and run
    importer = CorpusImporter(
        source_dir=args.source,
        output_dir=args.output,
        strip_pixels=args.strip_pixels,
        max_file_size=max_size,
        min_file_size=min_size,
        skip_corrupted=not args.fail_on_error,
    )

    try:
        logger.info("Starting corpus import...")
        stats = importer.import_corpus()

        # Generate and display report
        report = importer.generate_report()
        print("\n" + report)

        # Save statistics to JSON
        stats_file = args.output / "corpus_stats.json"
        with open(stats_file, "w") as f:
            json.dump(stats, f, indent=2)
        logger.info(f"Statistics saved to: {stats_file}")

        # Exit with appropriate code
        if stats["files_imported"] == 0:
            logger.error("No files imported! Check source directory and filters.")
            sys.exit(1)
        elif stats["errors"]:
            logger.warning(f"Import completed with {len(stats['errors'])} errors")
            sys.exit(0)
        else:
            logger.info("Import completed successfully!")
            sys.exit(0)

    except KeyboardInterrupt:
        logger.warning("\nImport interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Import failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
