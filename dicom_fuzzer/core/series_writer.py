"""DICOM Series Writer

This module provides SeriesWriter for writing fuzzed DICOM series to disk with
comprehensive metadata tracking and reproduction capabilities.

KEY FEATURES:
- Write complete 3D series (all slices) to organized directory structure
- Preserve SeriesInstanceUID relationships between slices
- Generate detailed metadata JSON comparing original vs fuzzed series
- Create reproduction scripts for debugging and verification
- Support both 2D (single slice) and 3D (multi-slice) series

DIRECTORY STRUCTURE:
output_dir/
+-- series_<series_uid>/
    +-- slice_001.dcm
    +-- slice_002.dcm
    +-- ...
    +-- metadata.json
    +-- reproduce.py

SECURITY NOTE: Based on CVE-2025-35975, CVE-2025-36521, CVE-2025-5943,
fuzzed series must maintain valid DICOM structure to reach parser vulnerabilities.
Invalid structure causes early rejection, never reaching vulnerable code paths.
"""

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from pydicom.dataset import Dataset

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.core.serialization import SerializableMixin
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SeriesMetadata(SerializableMixin):
    """Metadata about a written DICOM series.

    Tracks both original and fuzzed series characteristics for debugging,
    analysis, and reproduction.
    """

    series_uid: str
    study_uid: str
    modality: str
    slice_count: int
    output_directory: Path
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    # Original series info
    original_series_uid: str | None = None
    original_slice_count: int | None = None
    original_slice_spacing: float | None = None

    # Fuzzed series info
    mutation_strategy: str | None = None
    mutation_count: int = 0
    mutations_applied: list[dict[str, Any]] = field(default_factory=list)

    # File info
    slice_files: list[str] = field(default_factory=list)
    total_size_bytes: int = 0

    def get_output_paths(self) -> list[Path]:
        """Get list of full output file paths.

        Returns:
            List of Path objects to written DICOM files

        """
        return [self.output_directory / fname for fname in self.slice_files]


class SeriesWriter:
    """Write DICOM series to disk with comprehensive metadata tracking.

    This class handles the output of fuzzed DICOM series, creating organized
    directory structures, metadata files, and reproduction scripts.
    """

    def __init__(self, output_root: Path):
        """Initialize SeriesWriter.

        Args:
            output_root: Root directory for all output (e.g., ./fuzzed_output/)

        """
        self.output_root = Path(output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)
        logger.info(f"SeriesWriter initialized with output root: {self.output_root}")

    def write_series(
        self,
        series: DicomSeries,
        datasets: list[Dataset] | None = None,
        mutation_strategy: str | None = None,
        mutations_applied: list[dict[str, Any]] | None = None,
        original_series: DicomSeries | None = None,
    ) -> SeriesMetadata:
        """Write a complete DICOM series to disk with metadata.

        Args:
            series: DicomSeries object with metadata
            datasets: List of pydicom Dataset objects to write (one per slice).
                     If None, loads datasets from series.slices paths.
            mutation_strategy: Name of mutation strategy applied (if any)
            mutations_applied: List of mutation records (if any)
            original_series: Original series before fuzzing (for comparison)

        Returns:
            SeriesMetadata object with write details

        Raises:
            ValueError: If series and datasets count mismatch
            IOError: If write fails

        """
        # Load datasets from series if not provided
        if datasets is None:
            import pydicom

            datasets = []
            for slice_path in series.slices:
                try:
                    ds = pydicom.dcmread(slice_path)
                    datasets.append(ds)
                except Exception as e:
                    logger.error(f"Failed to read slice {slice_path}: {e}")
                    raise OSError(f"Failed to read slice {slice_path}: {e}") from e

        if len(datasets) != series.slice_count:
            raise ValueError(
                f"Dataset count ({len(datasets)}) does not match series slice count "
                f"({series.slice_count})"
            )

        # Create series directory
        series_dir = self._create_series_directory(series)
        logger.info(
            f"Writing {series.slice_count} slices to {series_dir.name}/ "
            f"({series.modality} series)"
        )

        # Write all slices
        slice_files = []
        total_size = 0
        for i, (dataset, original_path) in enumerate(
            zip(datasets, series.slices, strict=False), start=1
        ):
            slice_filename = f"slice_{i:03d}.dcm"
            slice_path = series_dir / slice_filename

            try:
                # Write DICOM file
                dataset.save_as(slice_path, write_like_original=False)
                file_size = slice_path.stat().st_size
                total_size += file_size
                slice_files.append(slice_filename)

                logger.debug(
                    f"  Wrote {slice_filename} ({file_size:,} bytes) "
                    f"[original: {original_path.name}]"
                )
            except Exception as e:
                logger.error(f"Failed to write slice {i}: {e}")
                raise OSError(f"Failed to write slice {slice_filename}") from e

        # Create metadata
        metadata = SeriesMetadata(
            series_uid=series.series_uid,
            study_uid=series.study_uid,
            modality=series.modality,
            slice_count=series.slice_count,
            output_directory=series_dir,
            mutation_strategy=mutation_strategy,
            mutation_count=len(mutations_applied) if mutations_applied else 0,
            mutations_applied=mutations_applied or [],
            slice_files=slice_files,
            total_size_bytes=total_size,
        )

        # Add original series info if provided
        if original_series:
            metadata.original_series_uid = original_series.series_uid
            metadata.original_slice_count = original_series.slice_count
            metadata.original_slice_spacing = original_series.slice_spacing

        # Write metadata JSON
        self._write_metadata_json(series_dir, metadata)

        # Create reproduction script
        self._create_reproduction_script(series_dir, metadata)

        logger.info(
            f"Successfully wrote series to {series_dir.name}/ "
            f"({total_size:,} bytes total)"
        )

        return metadata

    def write_single_slice(
        self,
        dataset: Dataset,
        output_name: str,
        mutation_strategy: str | None = None,
        mutations_applied: list[dict[str, Any]] | None = None,
    ) -> Path:
        """Write a single DICOM slice to disk (for backward compatibility).

        Args:
            dataset: pydicom Dataset to write
            output_name: Filename for output (e.g., "fuzzed_001.dcm")
            mutation_strategy: Name of mutation strategy applied (if any)
            mutations_applied: List of mutation records (if any)

        Returns:
            Path to written file

        """
        output_path = self.output_root / output_name

        try:
            dataset.save_as(output_path, write_like_original=False)
            file_size = output_path.stat().st_size
            logger.info(f"Wrote single slice: {output_name} ({file_size:,} bytes)")

            # Write simple metadata if mutations provided
            if mutations_applied:
                metadata_path = output_path.with_suffix(".json")
                metadata = {
                    "filename": output_name,
                    "timestamp": datetime.now().isoformat(),
                    "mutation_strategy": mutation_strategy,
                    "mutation_count": len(mutations_applied),
                    "mutations_applied": mutations_applied,
                    "file_size_bytes": file_size,
                }
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)

            return output_path
        except Exception as e:
            logger.error(f"Failed to write single slice {output_name}: {e}")
            raise OSError(f"Failed to write {output_name}") from e

    def _create_series_directory(self, series: DicomSeries) -> Path:
        """Create output directory for series.

        Args:
            series: DicomSeries object

        Returns:
            Path to created directory

        """
        # Use shortened UID for directory name
        short_uid = (
            series.series_uid[:16] if len(series.series_uid) > 16 else series.series_uid
        )
        dir_name = f"series_{short_uid}_{series.modality}"

        series_dir = self.output_root / dir_name

        # Handle existing directory (append counter)
        counter = 1
        while series_dir.exists():
            series_dir = self.output_root / f"{dir_name}_{counter}"
            counter += 1

        series_dir.mkdir(parents=True, exist_ok=True)
        return series_dir

    def _write_metadata_json(self, series_dir: Path, metadata: SeriesMetadata) -> None:
        """Write metadata.json file to series directory.

        Args:
            series_dir: Series output directory
            metadata: SeriesMetadata object

        """
        metadata_path = series_dir / "metadata.json"

        try:
            with open(metadata_path, "w") as f:
                json.dump(metadata.to_dict(), f, indent=2)
            logger.debug(f"Wrote metadata.json ({metadata_path.stat().st_size} bytes)")
        except Exception as e:
            logger.warning(f"Failed to write metadata.json: {e}")

    def _create_reproduction_script(
        self, series_dir: Path, metadata: SeriesMetadata
    ) -> None:
        """Create reproduce.py script for debugging and verification.

        Args:
            series_dir: Series output directory
            metadata: SeriesMetadata object

        """
        script_path = series_dir / "reproduce.py"

        script_content = f'''#!/usr/bin/env python3
"""
Reproduction Script for Fuzzed DICOM Series

Generated: {metadata.timestamp}
Series UID: {metadata.series_uid}
Modality: {metadata.modality}
Slice Count: {metadata.slice_count}
Mutation Strategy: {metadata.mutation_strategy or "None"}
Mutations Applied: {metadata.mutation_count}

This script loads and displays the fuzzed DICOM series for debugging.
"""

import json
from pathlib import Path
import pydicom

def main():
    series_dir = Path(__file__).parent

    # Load metadata
    with open(series_dir / "metadata.json") as f:
        metadata = json.load(f)

    print("=" * 60)
    print("FUZZED DICOM SERIES")
    print("=" * 60)
    print(f"Series UID: {{metadata['series_uid']}}")
    print(f"Modality: {{metadata['modality']}}")
    print(f"Slice Count: {{metadata['slice_count']}}")
    print(f"Mutation Strategy: {{metadata.get('mutation_strategy', 'None')}}")
    print(f"Mutations Applied: {{metadata['mutation_count']}}")
    print(f"Total Size: {{metadata['total_size_bytes']:,}} bytes")
    print()

    # Load and display each slice
    print("Slices:")
    for slice_file in metadata['slice_files']:
        slice_path = series_dir / slice_file
        try:
            ds = pydicom.dcmread(slice_path)
            print(f"  {{slice_file}}: {{ds.SOPInstanceUID[:32]}}...")
            if hasattr(ds, "ImagePositionPatient"):
                pos = ds.ImagePositionPatient
                print(f"    Position: ({{pos[0]:.2f}}, {{pos[1]:.2f}}, {{pos[2]:.2f}})")
        except Exception as e:
            print(f"  {{slice_file}}: ERROR - {{e}}")

    print()
    print("Mutations Applied:")
    for i, mutation in enumerate(metadata.get('mutations_applied', []), start=1):
        print(f"  {{i}}. {{mutation}}")
    print()

if __name__ == "__main__":
    main()
'''

        try:
            with open(script_path, "w") as f:
                f.write(script_content)
            script_path.chmod(0o755)  # Make executable
            logger.debug(f"Created reproduce.py ({script_path.stat().st_size} bytes)")
        except Exception as e:
            logger.warning(f"Failed to create reproduce.py: {e}")

    def cleanup_old_series(self, days: int = 7) -> int:
        """Clean up series directories older than specified days.

        Args:
            days: Delete series older than this many days

        Returns:
            Number of directories deleted

        """
        import time

        cutoff_time = time.time() - (days * 86400)
        deleted_count = 0

        for series_dir in self.output_root.iterdir():
            if not series_dir.is_dir():
                continue

            if series_dir.stat().st_mtime < cutoff_time:
                try:
                    shutil.rmtree(series_dir)
                    logger.info(f"Deleted old series: {series_dir.name}")
                    deleted_count += 1
                except Exception as e:
                    logger.warning(f"Failed to delete {series_dir.name}: {e}")

        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old series directories")

        return deleted_count
