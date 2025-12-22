"""Memory and Performance Stress Testing

This module provides StressTester for generating large DICOM series and
running extended stress tests against viewers and processing applications.

STRESS TEST CATEGORIES:
1. Large Series Generation - Create 1000+ slice series
2. Long-Duration Testing - Extended viewer sessions
3. Memory Monitoring - Track memory usage over time
4. Incremental Loading - Partial/interrupted series

SECURITY RATIONALE:
Medical imaging applications may have:
- Memory leaks in long-running sessions
- Buffer overflows with large datasets
- Resource exhaustion with extreme dimensions
- Crash-on-close issues after extended use

This module helps identify these issues before production deployment.

USAGE:
    config = StressTestConfig(max_slices=1000, max_dimensions=(2048, 2048))
    tester = StressTester(config)

    # Generate large series
    series_dir = tester.generate_large_series(slice_count=500)

    # Run duration test
    results = tester.run_duration_test(viewer_path, series_dir, duration_minutes=30)
"""

import os
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from pydicom.dataset import FileDataset, FileMetaDataset
from pydicom.uid import (
    UID,
    ExplicitVRLittleEndian,
    generate_uid,
)

from dicom_fuzzer.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class StressTestConfig:
    """Configuration for stress testing."""

    max_slices: int = 1000
    max_dimensions: tuple[int, int] = (2048, 2048)
    bits_allocated: int = 16
    duration_minutes: int = 60
    monitor_interval_seconds: float = 5.0
    memory_limit_mb: int = 4096
    disk_limit_mb: int = 10240


@dataclass
class MemorySnapshot:
    """Memory usage at a point in time."""

    timestamp: float
    process_memory_mb: float
    system_memory_percent: float
    details: dict = field(default_factory=dict)


@dataclass
class StressTestResult:
    """Results from a stress test run."""

    start_time: float
    end_time: float
    duration_seconds: float
    series_path: Path | None
    slice_count: int
    dimensions: tuple[int, int]
    memory_snapshots: list[MemorySnapshot] = field(default_factory=list)
    memory_peak_mb: float = 0.0
    crashes: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    success: bool = True

    def summary(self) -> str:
        """Generate human-readable summary."""
        return (
            f"Stress Test Results:\n"
            f"  Duration: {self.duration_seconds:.1f}s\n"
            f"  Slices: {self.slice_count}\n"
            f"  Dimensions: {self.dimensions[0]}x{self.dimensions[1]}\n"
            f"  Memory Peak: {self.memory_peak_mb:.1f} MB\n"
            f"  Crashes: {len(self.crashes)}\n"
            f"  Errors: {len(self.errors)}\n"
            f"  Success: {self.success}"
        )


class StressTester:
    """Stress tester for DICOM viewers and processing applications.

    Generates large series and monitors resource usage during extended tests.
    """

    def __init__(self, config: StressTestConfig | None = None):
        """Initialize StressTester.

        Args:
            config: Stress test configuration (uses defaults if None)

        """
        self.config = config or StressTestConfig()
        logger.info(
            f"StressTester initialized (max_slices={self.config.max_slices}, "
            f"max_dimensions={self.config.max_dimensions})"
        )

    def generate_large_series(
        self,
        output_dir: Path,
        slice_count: int = 100,
        dimensions: tuple[int, int] | None = None,
        modality: str = "CT",
        pixel_pattern: str = "gradient",
    ) -> Path:
        """Generate a large synthetic DICOM series.

        Args:
            output_dir: Directory to write DICOM files
            slice_count: Number of slices to generate
            dimensions: (rows, cols) or None for default
            modality: DICOM modality (CT, MR, etc.)
            pixel_pattern: Pattern for pixel data (gradient, random, anatomical)

        Returns:
            Path to the generated series directory

        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if dimensions is None:
            dimensions = (512, 512)

        # Limit to configured maximum
        dimensions = (
            min(dimensions[0], self.config.max_dimensions[0]),
            min(dimensions[1], self.config.max_dimensions[1]),
        )
        slice_count = min(slice_count, self.config.max_slices)

        logger.info(
            f"Generating {slice_count} slices at {dimensions[0]}x{dimensions[1]}"
        )

        # Generate consistent UIDs for the series
        study_uid = generate_uid()
        series_uid = generate_uid()
        frame_of_reference_uid = generate_uid()

        start_time = time.time()

        for i in range(slice_count):
            # Generate DICOM file
            ds = self._create_slice(
                slice_index=i,
                total_slices=slice_count,
                dimensions=dimensions,
                modality=modality,
                study_uid=study_uid,
                series_uid=series_uid,
                frame_of_reference_uid=frame_of_reference_uid,
                pixel_pattern=pixel_pattern,
            )

            # Write to file
            filename = f"slice_{i:05d}.dcm"
            filepath = output_dir / filename
            ds.save_as(filepath)

            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                logger.info(
                    f"Generated {i + 1}/{slice_count} slices ({rate:.1f} slices/sec)"
                )

        elapsed = time.time() - start_time
        logger.info(
            f"Generated {slice_count} slices in {elapsed:.1f}s "
            f"({slice_count / elapsed:.1f} slices/sec)"
        )

        return output_dir

    def _create_slice(
        self,
        slice_index: int,
        total_slices: int,
        dimensions: tuple[int, int],
        modality: str,
        study_uid: str,
        series_uid: str,
        frame_of_reference_uid: str,
        pixel_pattern: str,
    ) -> FileDataset:
        """Create a single DICOM slice.

        Args:
            slice_index: Index of this slice
            total_slices: Total number of slices
            dimensions: (rows, cols)
            modality: DICOM modality
            study_uid: StudyInstanceUID
            series_uid: SeriesInstanceUID
            frame_of_reference_uid: FrameOfReferenceUID
            pixel_pattern: Pixel data pattern

        Returns:
            FileDataset ready to save

        """
        rows, cols = dimensions

        # Create file meta
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = UID("1.2.840.10008.5.1.4.1.1.2")  # CT
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        file_meta.ImplementationClassUID = generate_uid()

        # Create dataset
        ds = FileDataset(
            "",  # Empty string for filename (will be set on save)
            {},
            file_meta=file_meta,
            preamble=b"\x00" * 128,
        )

        # Patient module
        ds.PatientName = "STRESS^TEST^PATIENT"
        ds.PatientID = "STRESS_TEST_001"
        ds.PatientBirthDate = "19700101"
        ds.PatientSex = "O"

        # Study module
        ds.StudyInstanceUID = study_uid
        ds.StudyDate = "20250101"
        ds.StudyTime = "120000"
        ds.StudyID = "STRESS_STUDY"
        ds.AccessionNumber = "STRESS001"

        # Series module
        ds.SeriesInstanceUID = series_uid
        ds.SeriesNumber = 1
        ds.Modality = modality
        ds.SeriesDescription = f"Stress Test Series ({total_slices} slices)"

        # Frame of Reference
        ds.FrameOfReferenceUID = frame_of_reference_uid

        # Instance module
        ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.InstanceNumber = slice_index + 1

        # Image module
        ds.Rows = rows
        ds.Columns = cols
        ds.BitsAllocated = self.config.bits_allocated
        ds.BitsStored = self.config.bits_allocated
        ds.HighBit = self.config.bits_allocated - 1
        ds.PixelRepresentation = 0  # Unsigned
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"

        # Geometry
        slice_spacing = 1.0  # mm
        ds.ImagePositionPatient = [0.0, 0.0, slice_index * slice_spacing]
        ds.ImageOrientationPatient = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0]
        ds.PixelSpacing = [0.5, 0.5]  # mm
        ds.SliceThickness = slice_spacing
        ds.SliceLocation = slice_index * slice_spacing

        # CT-specific
        if modality == "CT":
            ds.RescaleSlope = 1.0
            ds.RescaleIntercept = -1024.0
            ds.WindowCenter = 40
            ds.WindowWidth = 400

        # Generate pixel data
        pixel_array = self._generate_pixel_data(
            rows, cols, slice_index, total_slices, pixel_pattern
        )
        ds.PixelData = pixel_array.tobytes()

        return ds

    def _generate_pixel_data(
        self,
        rows: int,
        cols: int,
        slice_index: int,
        total_slices: int,
        pattern: str,
    ) -> np.ndarray:
        """Generate pixel data with specified pattern.

        Args:
            rows: Number of rows
            cols: Number of columns
            slice_index: Current slice index
            total_slices: Total slices
            pattern: gradient, random, anatomical, or noise

        Returns:
            Numpy array with pixel data

        """
        if self.config.bits_allocated == 16:
            dtype = np.uint16
            max_val = 65535
        else:
            dtype = np.uint8
            max_val = 255

        if pattern == "gradient":
            # Gradient pattern varying with slice
            x = np.linspace(0, 1, cols)
            y = np.linspace(0, 1, rows)
            xx, yy = np.meshgrid(x, y)
            z = slice_index / max(total_slices - 1, 1)

            # Combine gradients
            pixel_array = ((xx + yy + z) / 3 * max_val).astype(dtype)

        elif pattern == "random":
            # Random noise
            pixel_array = np.random.randint(0, max_val + 1, (rows, cols), dtype=dtype)

        elif pattern == "anatomical":
            # Simplified anatomical-like pattern (circular structures)
            y, x = np.ogrid[:rows, :cols]
            center_y, center_x = rows // 2, cols // 2

            # Create circular pattern
            r = np.sqrt((x - center_x) ** 2 + (y - center_y) ** 2)
            max_r = min(rows, cols) // 2

            # Base tissue
            pixel_array = np.ones((rows, cols), dtype=dtype) * (max_val // 4)

            # Body outline
            body_mask = r < max_r * 0.9
            pixel_array[body_mask] = max_val // 2

            # "Bone" ring
            bone_mask = (r > max_r * 0.7) & (r < max_r * 0.8)
            pixel_array[bone_mask] = int(max_val * 0.8)

            # Central structure varying with slice
            core_size = max_r * 0.3 * (0.5 + 0.5 * np.sin(slice_index * 0.1))
            core_mask = r < core_size
            pixel_array[core_mask] = int(max_val * 0.6)

        else:  # noise
            # Gaussian noise
            noise = np.random.normal(max_val / 2, max_val / 6, (rows, cols))
            pixel_array = np.clip(noise, 0, max_val).astype(dtype)

        return pixel_array

    def estimate_memory_usage(
        self, slice_count: int, dimensions: tuple[int, int]
    ) -> dict[str, float | int | str]:
        """Estimate memory usage for a series.

        Args:
            slice_count: Number of slices
            dimensions: (rows, cols)

        Returns:
            Dictionary with memory estimates in MB

        """
        rows, cols = dimensions
        bytes_per_pixel = self.config.bits_allocated // 8

        # Single slice
        slice_bytes = rows * cols * bytes_per_pixel
        slice_mb = slice_bytes / (1024 * 1024)

        # Full series (pixel data only)
        series_bytes = slice_bytes * slice_count
        series_mb = series_bytes / (1024 * 1024)

        # Estimated overhead (metadata, viewer buffers, etc.)
        # Typically 2-3x for viewing applications
        estimated_viewer_mb = series_mb * 2.5

        return {
            "slice_mb": slice_mb,
            "series_pixel_data_mb": series_mb,
            "estimated_viewer_mb": estimated_viewer_mb,
            "slice_count": slice_count,
            "dimensions": f"{rows}x{cols}",
        }

    def get_current_memory(self) -> MemorySnapshot:
        """Get current memory usage.

        Returns:
            MemorySnapshot with current memory info

        """
        process_memory_mb = 0.0
        system_memory_percent = 0.0
        details: dict[str, Any] = {}

        try:
            import psutil

            process = psutil.Process(os.getpid())
            process_memory_mb = process.memory_info().rss / (1024 * 1024)

            system_memory = psutil.virtual_memory()
            system_memory_percent = system_memory.percent

            details = {
                "process_rss_mb": process_memory_mb,
                "system_total_mb": system_memory.total / (1024 * 1024),
                "system_available_mb": system_memory.available / (1024 * 1024),
                "system_percent": system_memory_percent,
            }
        except ImportError:
            # psutil not available
            details["error"] = "psutil not installed"
        except Exception as e:
            details["error"] = str(e)

        return MemorySnapshot(
            timestamp=time.time(),
            process_memory_mb=process_memory_mb,
            system_memory_percent=system_memory_percent,
            details=details,
        )

    def generate_incremental_series(
        self,
        output_dir: Path,
        slice_count: int = 100,
        missing_pattern: str = "middle",
    ) -> tuple[Path, list[int]]:
        """Generate a series with intentionally missing slices.

        Simulates interrupted transfers or partial data.

        Args:
            output_dir: Directory to write files
            slice_count: Total slices if complete
            missing_pattern: "middle", "boundary", "random", "every_nth"

        Returns:
            Tuple of (series path, list of missing slice indices)

        """
        output_dir = Path(output_dir)

        # First generate complete series
        self.generate_large_series(
            output_dir=output_dir,
            slice_count=slice_count,
            dimensions=(256, 256),
        )

        # Determine which slices to remove
        missing_indices: list[int] = []

        if missing_pattern == "middle":
            # Remove middle 30%
            start = slice_count // 3
            end = 2 * slice_count // 3
            missing_indices = list(range(start, end))

        elif missing_pattern == "boundary":
            # Remove first and last 10%
            boundary = slice_count // 10
            missing_indices = list(range(boundary)) + list(
                range(slice_count - boundary, slice_count)
            )

        elif missing_pattern == "random":
            # Remove random 20%
            remove_count = slice_count // 5
            missing_indices = random.sample(range(slice_count), remove_count)

        elif missing_pattern == "every_nth":
            # Remove every 5th slice
            missing_indices = list(range(0, slice_count, 5))

        # Remove the files
        for idx in missing_indices:
            filepath = output_dir / f"slice_{idx:05d}.dcm"
            if filepath.exists():
                filepath.unlink()

        logger.info(
            f"Generated incremental series: {slice_count - len(missing_indices)} of "
            f"{slice_count} slices ({len(missing_indices)} missing, pattern={missing_pattern})"
        )

        return output_dir, missing_indices

    def run_memory_stress_test(
        self,
        output_dir: Path,
        escalation_steps: list[int] | None = None,
    ) -> list[StressTestResult]:
        """Run escalating memory stress tests.

        Generates increasingly larger series to find memory limits.

        Args:
            output_dir: Base directory for test files
            escalation_steps: List of slice counts to test (default: [100, 250, 500, 1000])

        Returns:
            List of results for each step

        """
        if escalation_steps is None:
            escalation_steps = [100, 250, 500, 1000]

        output_dir = Path(output_dir)
        results: list[StressTestResult] = []

        for step, slice_count in enumerate(escalation_steps):
            step_dir = output_dir / f"step_{step:02d}_{slice_count}_slices"

            logger.info(f"Memory stress test step {step + 1}: {slice_count} slices")

            start_time = time.time()
            memory_before = self.get_current_memory()

            try:
                # Generate series
                series_path = self.generate_large_series(
                    output_dir=step_dir,
                    slice_count=slice_count,
                    dimensions=(512, 512),
                )

                memory_after = self.get_current_memory()
                end_time = time.time()

                result = StressTestResult(
                    start_time=start_time,
                    end_time=end_time,
                    duration_seconds=end_time - start_time,
                    series_path=series_path,
                    slice_count=slice_count,
                    dimensions=(512, 512),
                    memory_snapshots=[memory_before, memory_after],
                    memory_peak_mb=max(
                        memory_before.process_memory_mb,
                        memory_after.process_memory_mb,
                    ),
                    success=True,
                )

            except Exception as e:
                logger.error(f"Stress test failed at {slice_count} slices: {e}")
                result = StressTestResult(
                    start_time=start_time,
                    end_time=time.time(),
                    duration_seconds=time.time() - start_time,
                    series_path=None,
                    slice_count=slice_count,
                    dimensions=(512, 512),
                    errors=[str(e)],
                    success=False,
                )

            results.append(result)
            logger.info(result.summary())

            # Check if we should stop
            if not result.success:
                logger.warning("Stopping stress test due to failure")
                break

            if result.memory_peak_mb > self.config.memory_limit_mb:
                logger.warning(
                    f"Memory limit exceeded: {result.memory_peak_mb:.1f} MB > "
                    f"{self.config.memory_limit_mb} MB"
                )
                break

        return results
