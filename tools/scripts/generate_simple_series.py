#!/usr/bin/env python3
"""Generate Simple Synthetic 3D DICOM Series

Standalone script without dicom_fuzzer imports to avoid dependency issues.
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pydicom
from pydicom.dataset import Dataset, FileDataset


def generate_ct_slice(
    slice_number: int,
    total_slices: int,
    series_uid: str,
    study_uid: str,
    output_dir: Path,
) -> Path:
    """Generate a single CT slice with proper DICOM metadata."""
    # Create file metadata
    file_meta = Dataset()
    file_meta.FileMetaInformationGroupLength = 192
    file_meta.FileMetaInformationVersion = b"\x00\x01"
    file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"
    file_meta.MediaStorageSOPInstanceUID = pydicom.uid.generate_uid()
    file_meta.TransferSyntaxUID = pydicom.uid.ImplicitVRLittleEndian
    file_meta.ImplementationClassUID = pydicom.uid.PYDICOM_IMPLEMENTATION_UID

    # Create file dataset
    ds = FileDataset(
        "",  # filename
        {},  # dataset
        file_meta=file_meta,
        preamble=b"\0" * 128,
    )

    # Patient Information
    ds.PatientName = "TEST^FUZZER"
    ds.PatientID = "FUZZ001"
    ds.PatientBirthDate = "19900101"
    ds.PatientSex = "M"

    # Study Information
    ds.StudyInstanceUID = study_uid
    ds.StudyDate = datetime.now().strftime("%Y%m%d")
    ds.StudyTime = datetime.now().strftime("%H%M%S")
    ds.StudyID = "1"

    # Series Information
    ds.SeriesInstanceUID = series_uid
    ds.SeriesNumber = "1"
    ds.Modality = "CT"

    # Instance Information
    ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
    ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
    ds.InstanceNumber = str(slice_number + 1)

    # Image Position
    ds.ImageOrientationPatient = [1, 0, 0, 0, 1, 0]
    slice_position = slice_number * 1.0
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
    ds.PixelSpacing = [0.5, 0.5]

    # Create simple gradient pixel data
    pixel_array = np.zeros((512, 512), dtype=np.uint16)
    center_x, center_y = 256, 256
    radius = 200

    for i in range(512):
        for j in range(512):
            distance = np.sqrt((i - center_x) ** 2 + (j - center_y) ** 2)
            if distance < radius:
                intensity = int(1000 + (slice_number * 10) - (distance / 2))
                pixel_array[i, j] = max(0, min(4095, intensity))

    ds.PixelData = pixel_array.tobytes()

    # Save file
    filename = f"slice_{slice_number:04d}.dcm"
    output_path = output_dir / filename
    ds.save_as(output_path, write_like_original=False)

    return output_path


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Generate synthetic 3D DICOM series")
    parser.add_argument("--output", type=str, required=True, help="Output directory")
    parser.add_argument("--slices", type=int, default=30, help="Number of slices")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate unique UIDs
    study_uid = pydicom.uid.generate_uid()
    series_uid = pydicom.uid.generate_uid()

    print(f"[+] Generating {args.slices}-slice CT series")
    print(f"    Study UID: {study_uid}")
    print(f"    Series UID: {series_uid}")
    print(f"    Output: {output_dir}")

    for i in range(args.slices):
        generate_ct_slice(
            slice_number=i,
            total_slices=args.slices,
            series_uid=series_uid,
            study_uid=study_uid,
            output_dir=output_dir,
        )
        if (i + 1) % 10 == 0:
            print(f"    Generated {i + 1}/{args.slices} slices...")

    print(f"[+] Successfully generated {args.slices} slices")
    print(f"[+] Series ready at: {output_dir}")

    # Create summary
    summary_path = output_dir / "series_info.txt"
    with open(summary_path, "w") as f:
        f.write("Generated Test Series\n")
        f.write("====================\n\n")
        f.write(f"Study UID: {study_uid}\n")
        f.write(f"Series UID: {series_uid}\n")
        f.write("Modality: CT\n")
        f.write(f"Slice Count: {args.slices}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
