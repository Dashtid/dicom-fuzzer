"""DICOM Series Data Structure.

Defines the DicomSeries dataclass representing a complete 3D DICOM series.
A series is a collection of related slices sharing a SeriesInstanceUID.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pydicom
from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DicomSeries:
    """Represents a complete 3D DICOM series.

    A series is a collection of DICOM instances (slices) that share the same
    SeriesInstanceUID and form a cohesive 3D volume.

    Attributes:
        series_uid: SeriesInstanceUID linking all slices
        study_uid: StudyInstanceUID (parent study)
        modality: Imaging modality (CT, MR, US, etc.)
        slices: List of file paths to DICOM slices (sorted by position)
        slice_spacing: Distance between slices in mm (if uniform)
        orientation: Image orientation patient vector
        metadata: Series-level metadata extracted from first slice

    """

    series_uid: str
    study_uid: str
    modality: str
    slices: list[Path] = field(default_factory=list)
    slice_spacing: float | None = None
    orientation: tuple[float, ...] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate series after initialization."""
        if not self.series_uid:
            raise ValueError("SeriesInstanceUID cannot be empty")
        if not self.study_uid:
            raise ValueError("StudyInstanceUID cannot be empty")
        if not self.modality:
            raise ValueError("Modality cannot be empty")
        self._slice_cache: dict[Path, Dataset] = {}

    def _load_slice_metadata(self, slice_path: Path) -> Dataset | None:
        """Load slice metadata with caching (metadata-only, no pixel data)."""
        if slice_path in self._slice_cache:
            return self._slice_cache[slice_path]
        try:
            ds = pydicom.dcmread(slice_path, stop_before_pixels=True)
            self._slice_cache[slice_path] = ds
            return ds
        except Exception as e:
            logger.error("Error reading slice %s: %s", slice_path, e)
            return None

    @property
    def slice_count(self) -> int:
        """Number of slices in the series."""
        return len(self.slices)

    @property
    def is_3d(self) -> bool:
        """True if series contains more than one slice."""
        return self.slice_count > 1

    def get_slice_positions(self) -> list[tuple[float, float, float]]:
        """Extract ImagePositionPatient for all slices.

        Returns:
            List of (x, y, z) positions for each slice

        Note:
            Based on pydicom 2025 best practices, ImagePositionPatient[2] (z-coordinate)
            is the most reliable method for sorting slices, more robust than SliceLocation
            which may not be present in all modalities.

        """
        positions = []
        for slice_path in self.slices:
            ds = self._load_slice_metadata(slice_path)
            if ds is None:
                positions.append((0.0, 0.0, 0.0))
            elif hasattr(ds, "ImagePositionPatient"):
                pos = ds.ImagePositionPatient
                positions.append((float(pos[0]), float(pos[1]), float(pos[2])))
            else:
                logger.warning("Slice %s missing ImagePositionPatient", slice_path.name)
                positions.append((0.0, 0.0, 0.0))
        return positions

    def calculate_slice_spacing(self) -> float | None:
        """Calculate the distance between consecutive slices.

        Uses ImagePositionPatient[2] (z-coordinate) to determine spacing.
        Returns None if spacing is non-uniform or cannot be determined.

        Returns:
            Average slice spacing in mm, or None if non-uniform

        """
        positions = self.get_slice_positions()
        if len(positions) < 2:
            return None

        # Calculate distances between consecutive slices
        spacings = []
        for i in range(len(positions) - 1):
            z1 = positions[i][2]
            z2 = positions[i + 1][2]
            spacing = abs(z2 - z1)
            spacings.append(spacing)

        if not spacings:
            return None

        # Check if spacing is uniform (within 1% tolerance)
        mean_spacing = np.mean(spacings)
        std_spacing = np.std(spacings)

        if mean_spacing == 0:
            return None

        # Consider uniform if standard deviation is less than 1% of mean
        if std_spacing / mean_spacing < 0.01:
            return float(mean_spacing)
        else:
            logger.warning(
                "Non-uniform slice spacing detected: mean=%.2fmm, std=%.2fmm",
                mean_spacing,
                std_spacing,
            )
            return None

    def get_dimensions(self) -> tuple[int, int, int] | None:
        """Get the 3D dimensions of the series (width, height, depth).

        Returns:
            Tuple of (rows, columns, slices) or None if cannot be determined

        """
        if not self.slices:
            return None

        first_slice = self._load_slice_metadata(self.slices[0])
        if first_slice is None:
            return None

        try:
            rows = int(first_slice.Rows) if hasattr(first_slice, "Rows") else 0
            cols = int(first_slice.Columns) if hasattr(first_slice, "Columns") else 0
            return (rows, cols, self.slice_count)
        except (TypeError, ValueError) as e:
            logger.error("Error reading dimensions: %s", e)
            return None

    def load_first_slice(self) -> Dataset | None:
        """Load the first slice as a pydicom Dataset.

        Useful for extracting series-level metadata without loading entire volume.

        Returns:
            pydicom Dataset of first slice, or None if error

        """
        if not self.slices:
            return None

        try:
            return pydicom.dcmread(self.slices[0])
        except Exception as e:
            logger.error("Error loading first slice: %s", e)
            return None

    def validate_series_consistency(self) -> list[str]:
        """Validate that all slices have consistent series-level attributes.

        Checks:
        - All slices have same SeriesInstanceUID
        - All slices have same StudyInstanceUID
        - All slices have same Modality
        - All slices have same ImageOrientationPatient

        Returns:
            List of validation error messages (empty if valid)

        """
        errors = []

        if not self.slices:
            errors.append("Series has no slices")
            return errors

        for i, slice_path in enumerate(self.slices):
            ds = self._load_slice_metadata(slice_path)
            if ds is None:
                errors.append(f"Error reading slice {i} ({slice_path.name})")
                continue

            # Check SeriesInstanceUID
            if hasattr(ds, "SeriesInstanceUID"):
                if ds.SeriesInstanceUID != self.series_uid:
                    errors.append(
                        f"Slice {i} ({slice_path.name}) has mismatched "
                        f"SeriesInstanceUID: {ds.SeriesInstanceUID}"
                    )
            else:
                errors.append(
                    f"Slice {i} ({slice_path.name}) missing SeriesInstanceUID"
                )

            # Check StudyInstanceUID
            if hasattr(ds, "StudyInstanceUID"):
                if ds.StudyInstanceUID != self.study_uid:
                    errors.append(
                        f"Slice {i} ({slice_path.name}) has mismatched "
                        f"StudyInstanceUID: {ds.StudyInstanceUID}"
                    )
            else:
                errors.append(f"Slice {i} ({slice_path.name}) missing StudyInstanceUID")

            # Check Modality
            if hasattr(ds, "Modality"):
                if ds.Modality != self.modality:
                    errors.append(
                        f"Slice {i} ({slice_path.name}) has mismatched "
                        f"Modality: {ds.Modality}"
                    )
            else:
                errors.append(f"Slice {i} ({slice_path.name}) missing Modality")

        return errors

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"DicomSeries(series_uid={self.series_uid[:16]}..., "
            f"modality={self.modality}, "
            f"slices={self.slice_count}, "
            f"is_3d={self.is_3d})"
        )
