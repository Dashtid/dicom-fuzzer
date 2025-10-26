#!/usr/bin/env python3
"""
Generate Synthetic 3D DICOM Series for Testing

Creates a multi-slice CT series suitable for fuzzing campaigns.
Based on the existing CT_small.dcm sample, this generates a complete 3D series.

USAGE:
    python scripts/generate_test_series.py --output campaigns/campaign_001_initial/input --slices 30

SECURITY NOTICE:
This is for defensive security testing only. Use ONLY on systems you own.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

import pydicom
from pydicom.dataset import Dataset, FileDataset

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from dicom_fuzzer.utils.logger import get_logger, setup_logging

logger = get_logger(__name__)


def generate_ct_slice(
    slice_number: int,
    total_slices: int,
    series_uid: str,
    study_uid: str,
    output_dir: Path,
) -> Path:
    """
    Generate a single CT slice with proper DICOM metadata.

    Args:
        slice_number: Slice index (0-based)
        total_slices: Total number of slices in series
        series_uid: Series Instance UID
        study_uid: Study Instance UID
        output_dir: Directory to save the slice

    Returns:
        Path to the generated DICOM file
    """
    # Create new dataset
    file_meta = Dataset()
    file_meta.FileMetaInformationGroupLength = 192
    file_meta.FileMetaInformationVersion = b"\x00\x01"
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
    file_meta.MediaStorageSOPInstanceUID = pydicom.uid.generate_uid()
    file_meta.TransferSyntaxUID = pydicom.uid.ImplicitVRLittleEndian
    file_meta.ImplementationClassUID = pydicom.uid.PYDICOM_IMPLEMENTATION_UID
    file_meta.ImplementationVersionName = "PYDICOM 2.4.4"

    # Create file dataset
    ds = FileDataset(
        filename=None,
        dataset={},
        file_meta=file_meta,
        preamble=b"\0" * 128,
    )

    # Patient Information
    ds.PatientName = "TEST^FUZZER^CAMPAIGN"
    ds.PatientID = "FUZZ001"
    ds.PatientBirthDate = "19900101"
    ds.PatientSex = "M"

    # Study Information
    ds.StudyInstanceUID = study_uid
    ds.StudyDate = datetime.now().strftime("%Y%m%d")
    ds.StudyTime = datetime.now().strftime("%H%M%S")
    ds.StudyID = "1"
    ds.AccessionNumber = "ACC001"
    ds.ReferringPhysicianName = "DR^FUZZER"

    # Series Information
    ds.SeriesInstanceUID = series_uid
    ds.SeriesNumber = "1"
    ds.Modality = "CT"
    ds.SeriesDescription = "Fuzzing Test Series"

    # Instance Information
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.InstanceNumber = str(slice_number + 1)

    # Image Position and Orientation
    # Standard axial CT orientation
    ds.ImageOrientationPatient = [1, 0, 0, 0, 1, 0]

    # Position varies by slice (Z-axis spacing of 1.0mm)
    slice_position = slice_number * 1.0  # 1mm spacing
    ds.ImagePositionPatient = [0.0, 0.0, slice_position]

    ds.SliceLocation = slice_position
    ds.SliceThickness = "1.0"

    # Image Pixel Data
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 12
    ds.HighBit = 11
    ds.PixelRepresentation = 0

    # Create simple gradient pixel data (simulated CT intensities)
    import numpy as np

    # Create a gradient pattern with some variation per slice
    pixel_array = np.zeros((512, 512), dtype=np.uint16)

    # Add some structure to make it look more like medical data
    center_x, center_y = 256, 256
    radius = 200

    for i in range(512):
        for j in range(512):
            distance = np.sqrt((i - center_x) ** 2 + (j - center_y) ** 2)
            if distance < radius:
                # Inside circle: simulate tissue density
                intensity = int(1000 + (slice_number * 10) - (distance / 2))
                pixel_array[i, j] = max(0, min(4095, intensity))  # 12-bit range
            else:
                # Outside circle: air
                pixel_array[i, j] = 0

    ds.PixelData = pixel_array.tobytes()

    # Additional Required Tags
    ds.SpecificCharacterSet = "ISO_IR 100"
    ds.ImageType = ["ORIGINAL", "PRIMARY", "AXIAL"]
    ds.AcquisitionNumber = "1"
    ds.PixelSpacing = [0.5, 0.5]  # 0.5mm pixel spacing

    # Save file
    filename = f"slice_{slice_number:04d}.dcm"
    output_path = output_dir / filename
    ds.save_as(output_path, write_like_original=False)

    return output_path


def generate_series(output_dir: Path, slice_count: int = 30) -> None:
    """
    Generate a complete 3D DICOM series.

    Args:
        output_dir: Directory to save the series
        slice_count: Number of slices to generate
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique UIDs for the series
    study_uid = pydicom.uid.generate_uid()
    series_uid = pydicom.uid.generate_uid()

    logger.info(f"[+] Generating {slice_count}-slice CT series")
    logger.info(f"    Study UID: {study_uid}")
    logger.info(f"    Series UID: {series_uid}")
    logger.info(f"    Output: {output_dir}")

    generated_files = []

    for i in range(slice_count):
        output_path = generate_ct_slice(
            slice_number=i,
            total_slices=slice_count,
            series_uid=series_uid,
            study_uid=study_uid,
            output_dir=output_dir,
        )
        generated_files.append(output_path)

        if (i + 1) % 10 == 0:
            logger.info(f"    Generated {i + 1}/{slice_count} slices...")

    logger.info(f"[+] Successfully generated {len(generated_files)} slices")
    logger.info(f"[+] Series ready for fuzzing at: {output_dir}")

    # Create a summary file
    summary_path = output_dir / "series_info.txt"
    with open(summary_path, "w") as f:
        f.write("Generated Test Series\n")
        f.write("====================\n\n")
        f.write(f"Study UID: {study_uid}\n")
        f.write(f"Series UID: {series_uid}\n")
        f.write("Modality: CT\n")
        f.write(f"Slice Count: {slice_count}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("\nFiles:\n")
        for file_path in generated_files:
            f.write(f"  - {file_path.name}\n")

    logger.info(f"[+] Summary saved to: {summary_path}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate synthetic 3D DICOM series for fuzzing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--output",
        type=str,
        required=True,
        help="Output directory for the generated series",
    )

    parser.add_argument(
        "--slices",
        type=int,
        default=30,
        help="Number of slices to generate (default: 30)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(log_level=log_level)

    # Generate series
    output_dir = Path(args.output)
    generate_series(output_dir, args.slices)

    return 0


if __name__ == "__main__":
    sys.exit(main())
