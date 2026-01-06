"""DICOM Series Detection

This module provides SeriesDetector for grouping DICOM files into complete 3D series
based on SeriesInstanceUID.

CONCEPT: Medical imaging often consists of multiple files per acquisition. A CT scan
might have 130 separate .dcm files, each representing one 2D slice. These files are
linked by their SeriesInstanceUID. The SeriesDetector finds and groups these related
files into DicomSeries objects.

WHY THIS MATTERS FOR FUZZING:
- Individual file fuzzing misses series-level vulnerabilities (CVE-2025-35975, etc.)
- Viewers load entire series at once, not individual slices
- Series-level corruption can cause memory exhaustion, infinite loops, crashes
- Inconsistencies across slices (mixed modalities, conflicting metadata) are attack vectors

BEST PRACTICES (2025):
- Use ImagePositionPatient[2] for slice sorting (more reliable than SliceLocation)
- Validate SeriesInstanceUID uniqueness within series
- Handle missing metadata gracefully
- Support both multi-slice and single-slice series
"""

from collections import defaultdict
from pathlib import Path
from typing import Any

import pydicom

from dicom_fuzzer.core.dicom_series import DicomSeries
from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


class SeriesDetector:
    """Detect and group DICOM files into series based on SeriesInstanceUID.

    This class scans directories of DICOM files and organizes them into DicomSeries
    objects, properly sorting slices by their spatial position.
    """

    def __init__(self) -> None:
        """Initialize the series detector."""
        self._series_cache: dict[str, DicomSeries] = {}

    def detect_series(
        self, dicom_files: list[Path] | Path, validate: bool = True
    ) -> list[DicomSeries]:
        """Detect all series in a list of DICOM files or a directory.

        Args:
            dicom_files: List of paths to DICOM files OR a directory path
            validate: If True, validate series consistency after grouping

        Returns:
            List of DicomSeries objects, one per unique SeriesInstanceUID

        """
        # Handle directory path (backward compatibility)
        if isinstance(dicom_files, Path):
            return self.detect_series_in_directory(
                dicom_files, recursive=True, validate=validate
            )

        if not dicom_files:
            logger.warning("No DICOM files provided to detect_series")
            return []

        logger.info(f"Detecting series in {len(dicom_files)} DICOM files...")

        # Group files by SeriesInstanceUID
        series_groups = self._group_by_series_uid(dicom_files)

        # Create DicomSeries objects
        series_list = []
        for series_uid, file_info in series_groups.items():
            try:
                series = self._create_series(
                    series_uid=series_uid,
                    files=file_info["files"],
                    study_uid=file_info["study_uid"],
                    modality=file_info["modality"],
                )

                # Validate if requested
                if validate:
                    errors = series.validate_series_consistency()
                    if errors:
                        logger.warning(
                            f"Series {series_uid[:16]}... has validation errors: "
                            f"{len(errors)} issues"
                        )
                        for error in errors[:3]:  # Log first 3 errors
                            logger.warning(f"  - {error}")

                series_list.append(series)
                logger.info(
                    f"Detected series: {series.modality} with {series.slice_count} slices "
                    f"(UID: {series_uid[:16]}...)"
                )

            except Exception as e:
                logger.error(f"Error creating series {series_uid[:16]}...: {e}")
                continue

        logger.info(f"Detected {len(series_list)} series total")
        return series_list

    def detect_series_in_directory(
        self, directory: Path, recursive: bool = True, validate: bool = True
    ) -> list[DicomSeries]:
        """Scan directory for DICOM files and detect all series.

        Args:
            directory: Root directory to scan
            recursive: If True, scan subdirectories recursively
            validate: If True, validate series consistency

        Returns:
            List of detected DicomSeries objects

        """
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        logger.info(f"Scanning directory for DICOM files: {directory}")

        # Find all DICOM files
        dicom_files = self._find_dicom_files(directory, recursive=recursive)

        if not dicom_files:
            logger.warning(f"No DICOM files found in {directory}")
            return []

        return self.detect_series(dicom_files, validate=validate)

    # Common non-DICOM extensions to skip when scanning for extension-less files
    _NON_DICOM_EXTENSIONS = frozenset(
        {
            ".txt",
            ".xml",
            ".json",
            ".csv",
            ".log",
            ".md",
            ".html",
            ".htm",
            ".py",
            ".js",
            ".ts",
            ".zip",
            ".gz",
            ".tar",
            ".exe",
            ".dll",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".pdf",
            ".doc",
            ".docx",
        }
    )

    def _scan_extensionless_files(
        self,
        directory: Path,
        dicom_files_set: set[Path],
        recursive: bool,
    ) -> None:
        """Scan for DICOM files without standard extensions."""
        glob_func = directory.rglob if recursive else directory.glob
        for file_path in glob_func("*"):
            if not file_path.is_file():
                continue
            suffix = file_path.suffix.lower()
            if suffix and suffix in self._NON_DICOM_EXTENSIONS:
                continue
            if file_path not in dicom_files_set and self._is_dicom_file(file_path):
                dicom_files_set.add(file_path)

    def _find_dicom_files(self, directory: Path, recursive: bool = True) -> list[Path]:
        """Find all DICOM files in directory.

        Args:
            directory: Directory to scan
            recursive: If True, scan subdirectories

        Returns:
            List of paths to DICOM files (deduplicated)

        """
        dicom_files_set: set[Path] = set()
        patterns = ["*.dcm", "*.DCM", "*.dicom", "*.DICOM"]
        glob_func = directory.rglob if recursive else directory.glob

        for pattern in patterns:
            dicom_files_set.update(glob_func(pattern))

        # Also check files without typical extension (common in DICOM)
        self._scan_extensionless_files(directory, dicom_files_set, recursive)

        dicom_files = list(dicom_files_set)
        logger.info(f"Found {len(dicom_files)} DICOM files")
        return dicom_files

    def _is_dicom_file(self, file_path: Path) -> bool:
        """Check if file is a valid DICOM file.

        Args:
            file_path: Path to check

        Returns:
            True if file is valid DICOM

        """
        try:
            pydicom.dcmread(file_path, stop_before_pixels=True, force=False)
            return True
        except Exception:
            return False

    def _group_by_series_uid(
        self, dicom_files: list[Path]
    ) -> dict[str, dict[str, Any]]:
        """Group DICOM files by SeriesInstanceUID.

        Args:
            dicom_files: List of DICOM file paths

        Returns:
            Dict mapping SeriesInstanceUID to file info:
            {
                "series_uid_1": {
                    "files": [Path, Path, ...],
                    "study_uid": "study_uid",
                    "modality": "CT"
                },
                ...
            }

        """
        series_groups: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"files": [], "study_uid": None, "modality": None}
        )

        for file_path in dicom_files:
            try:
                # Read metadata only (stop before pixel data for speed)
                ds = pydicom.dcmread(file_path, stop_before_pixels=True)

                # Extract required attributes
                if not hasattr(ds, "SeriesInstanceUID"):
                    file_name = (
                        file_path.name
                        if isinstance(file_path, Path)
                        else Path(file_path).name
                    )
                    logger.warning(
                        f"File {file_name} missing SeriesInstanceUID, skipping"
                    )
                    continue

                series_uid = ds.SeriesInstanceUID
                study_uid = (
                    ds.StudyInstanceUID
                    if hasattr(ds, "StudyInstanceUID")
                    else "UNKNOWN"
                )
                modality = ds.Modality if hasattr(ds, "Modality") else "UNKNOWN"

                # Add to group
                files_list: list[Path] = series_groups[series_uid]["files"]
                files_list.append(file_path)

                # Set study_uid and modality from first file in series
                if series_groups[series_uid]["study_uid"] is None:
                    series_groups[series_uid]["study_uid"] = study_uid
                    series_groups[series_uid]["modality"] = modality

            except Exception as e:
                file_name = (
                    file_path.name
                    if isinstance(file_path, Path)
                    else Path(file_path).name
                )
                logger.warning(f"Error reading {file_name}: {e}")
                continue

        return dict(series_groups)

    def _create_series(
        self, series_uid: str, files: list[Path], study_uid: str, modality: str
    ) -> DicomSeries:
        """Create a DicomSeries object from grouped files.

        Sorts files by ImagePositionPatient[2] (z-coordinate) as per 2025 best practices.

        Args:
            series_uid: SeriesInstanceUID
            files: List of file paths in this series
            study_uid: StudyInstanceUID
            modality: Imaging modality

        Returns:
            DicomSeries object with sorted slices

        """
        # Sort slices by position
        sorted_files = self._sort_slices_by_position(files)

        # Create series object
        series = DicomSeries(
            series_uid=series_uid,
            study_uid=study_uid,
            modality=modality,
            slices=sorted_files,
        )

        # Calculate slice spacing
        series.slice_spacing = series.calculate_slice_spacing()

        # Extract orientation from first slice
        if sorted_files:
            try:
                first_ds = pydicom.dcmread(sorted_files[0], stop_before_pixels=True)
                if hasattr(first_ds, "ImageOrientationPatient"):
                    series.orientation = tuple(first_ds.ImageOrientationPatient)
            except Exception as e:
                logger.warning(f"Could not extract orientation: {e}")

        return series

    def _sort_slices_by_position(self, files: list[Path]) -> list[Path]:
        """Sort DICOM slices by spatial position.

        Uses ImagePositionPatient[2] (z-coordinate) as primary sort key.
        Falls back to InstanceNumber if ImagePositionPatient not available.
        Falls back to filename if neither available.

        Args:
            files: List of DICOM file paths

        Returns:
            Sorted list of file paths (superior to inferior)

        """
        if not files:
            return []

        # Extract position information
        file_positions: list[tuple[Path, float, int]] = []

        for file_path in files:
            try:
                ds = pydicom.dcmread(file_path, stop_before_pixels=True)

                # Try ImagePositionPatient[2] (preferred method)
                if hasattr(ds, "ImagePositionPatient"):
                    z_pos = float(ds.ImagePositionPatient[2])
                else:
                    z_pos = 0.0

                # Try InstanceNumber (fallback)
                instance_num = (
                    int(ds.InstanceNumber) if hasattr(ds, "InstanceNumber") else 0
                )

                file_positions.append((file_path, z_pos, instance_num))

            except Exception as e:
                file_name = (
                    file_path.name
                    if isinstance(file_path, Path)
                    else Path(file_path).name
                )
                logger.warning(f"Error reading position for {file_name}: {e}")
                file_positions.append((file_path, 0.0, 0))

        # Sort by z_position (descending for superior to inferior)
        # If z_positions are same, sort by instance number
        # If both same, sort by filename
        file_positions.sort(
            key=lambda x: (-x[1], x[2], x[0].name)
        )  # Note: negative z for descending

        sorted_files = [fp[0] for fp in file_positions]
        return sorted_files

    def get_series_summary(self, series_list: list[DicomSeries]) -> dict[str, Any]:
        """Generate summary statistics for detected series.

        Args:
            series_list: List of DicomSeries objects

        Returns:
            Dict with summary statistics

        """
        if not series_list:
            return {
                "total_series": 0,
                "total_slices": 0,
                "modalities": {},
                "multislice_series": 0,
                "single_slice_series": 0,
            }

        modality_counts: dict[str, int] = defaultdict(int)
        total_slices = 0
        multislice = 0
        single_slice = 0

        for series in series_list:
            modality_counts[series.modality] += 1
            total_slices += series.slice_count

            if series.is_3d:
                multislice += 1
            else:
                single_slice += 1

        return {
            "total_series": len(series_list),
            "total_slices": total_slices,
            "modalities": dict(modality_counts),
            "multislice_series": multislice,
            "single_slice_series": single_slice,
            "avg_slices_per_series": total_slices / len(series_list),
        }
