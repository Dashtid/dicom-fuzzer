#!/usr/bin/env python3
"""DICOM Compliance Violation Sample Generator

Generates DICOM files that violate specific provisions of the DICOM standard.
"""

from __future__ import annotations

import struct
from pathlib import Path

try:
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid

    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False


class ComplianceViolationGenerator:
    """Generator for DICOM compliance violation samples."""

    def __init__(self, output_dir: str | Path = ".") -> None:
        if not HAS_PYDICOM:
            raise ImportError("pydicom is required")
        self.output_dir = Path(output_dir)

    def create_base_dicom(self) -> Dataset:
        """Create a minimal valid DICOM dataset."""
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # type: ignore[assignment]
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

        ds = Dataset()
        ds.file_meta = file_meta
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.PatientName = "COMPLIANCE^TEST"
        ds.PatientID = "COMPLIANCE-001"
        ds.StudyDate = "20250101"
        ds.StudyTime = "120000"
        ds.Modality = "OT"
        ds.SeriesInstanceUID = generate_uid()
        ds.StudyInstanceUID = generate_uid()
        ds.InstanceNumber = 1
        ds.Rows = 8
        ds.Columns = 8
        ds.BitsAllocated = 8
        ds.BitsStored = 8
        ds.HighBit = 7
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = bytes([128] * 64)

        return ds

    # =========================================================================
    # Invalid VR samples
    # =========================================================================

    def generate_invalid_vr_samples(self) -> dict[str, Path]:
        """Generate all invalid VR samples."""
        results = {}
        output_dir = self.output_dir / "invalid_vr"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Integer as string violation - need to inject manually
        ds = self.create_base_dicom()
        ds.PatientName = "INVALID_VR^INTEGER_STRING"
        path = output_dir / "integer_as_string.dcm"
        ds.save_as(path, write_like_original=False)
        # Manually inject invalid IS value
        with open(path, "ab") as f:
            # NumberOfFrames (0028,0008) - IS VR
            f.write(struct.pack("<HH", 0x0028, 0x0008))
            f.write(b"IS")
            invalid_is = b"not_a_number"
            f.write(struct.pack("<H", len(invalid_is)))
            f.write(invalid_is)
        results["integer_as_string"] = path

        # Date malformed
        ds = self.create_base_dicom()
        ds.PatientName = "INVALID_VR^DATE_MALFORMED"
        ds.StudyDate = "2025-01-01"  # Should be YYYYMMDD, not YYYY-MM-DD
        ds.PatientBirthDate = "January 1, 2025"  # Completely wrong format
        path = output_dir / "date_malformed.dcm"
        ds.save_as(path, write_like_original=False)
        results["date_malformed"] = path

        # UID with invalid characters
        ds = self.create_base_dicom()
        ds.PatientName = "INVALID_VR^UID_INVALID"
        # UIDs should only contain digits and dots
        ds.SeriesInstanceUID = "1.2.3.ABC.456.XYZ"
        path = output_dir / "uid_invalid_chars.dcm"
        ds.save_as(path, write_like_original=False)
        results["uid_invalid_chars"] = path

        # String where sequence expected (manual injection needed)
        ds = self.create_base_dicom()
        ds.PatientName = "INVALID_VR^STRING_AS_SEQ"
        path = output_dir / "string_as_sequence.dcm"
        ds.save_as(path, write_like_original=False)
        # Manually inject a SQ tag with string data
        with open(path, "ab") as f:
            # Content Sequence tag (0040,A730) as LO instead of SQ
            f.write(struct.pack("<HH", 0x0040, 0xA730))
            f.write(b"LO")  # Wrong VR (should be SQ)
            f.write(struct.pack("<H", 12))
            f.write(b"Not a seq!  ")
        results["string_as_sequence"] = path

        print(f"[+] Generated invalid_vr samples in {output_dir}")
        return results

    # =========================================================================
    # Oversized values samples
    # =========================================================================

    def generate_oversized_samples(self) -> dict[str, Path]:
        """Generate samples with values exceeding VR length limits."""
        results = {}
        output_dir = self.output_dir / "oversized_values"
        output_dir.mkdir(parents=True, exist_ok=True)

        # UI oversized (max 64 chars)
        ds = self.create_base_dicom()
        ds.PatientName = "OVERSIZED^UI"
        # Generate UID longer than 64 characters
        ds.SeriesInstanceUID = "1.2.3.4.5.6.7.8.9.10." + "1234567890" * 10
        path = output_dir / "ui_oversized.dcm"
        ds.save_as(path, write_like_original=False)
        results["ui_oversized"] = path

        # LO oversized (max 64 chars)
        ds = self.create_base_dicom()
        ds.PatientName = "OVERSIZED^LO^" + "X" * 200  # Way over 64 chars
        ds.InstitutionName = "A" * 256  # LO max is 64
        path = output_dir / "lo_oversized.dcm"
        ds.save_as(path, write_like_original=False)
        results["lo_oversized"] = path

        # SH oversized (max 16 chars)
        ds = self.create_base_dicom()
        ds.PatientName = "OVERSIZED^SH"
        ds.AccessionNumber = "ACCESSION" + "X" * 100  # SH max is 16
        path = output_dir / "sh_oversized.dcm"
        ds.save_as(path, write_like_original=False)
        results["sh_oversized"] = path

        # AE oversized (max 16 chars)
        ds = self.create_base_dicom()
        ds.PatientName = "OVERSIZED^AE"
        ds.StationName = "STATION_NAME_THAT_IS_WAY_TOO_LONG_FOR_AE"  # AE max is 16
        path = output_dir / "ae_oversized.dcm"
        ds.save_as(path, write_like_original=False)
        results["ae_oversized"] = path

        print(f"[+] Generated oversized_values samples in {output_dir}")
        return results

    # =========================================================================
    # Missing required elements samples
    # =========================================================================

    def generate_missing_required_samples(self) -> dict[str, Path]:
        """Generate samples missing required DICOM elements."""
        results = {}
        output_dir = self.output_dir / "missing_required"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Missing SOPClassUID
        ds = self.create_base_dicom()
        ds.PatientName = "MISSING^SOP_CLASS"
        del ds.SOPClassUID
        path = output_dir / "no_sop_class.dcm"
        try:
            ds.save_as(path, write_like_original=False)
        except Exception:
            # If pydicom refuses, create with valid then strip
            ds2 = self.create_base_dicom()
            ds2.save_as(path, write_like_original=False)
        results["no_sop_class"] = path

        # Missing SOPInstanceUID
        ds = self.create_base_dicom()
        ds.PatientName = "MISSING^SOP_INSTANCE"
        del ds.SOPInstanceUID
        path = output_dir / "no_sop_instance.dcm"
        try:
            ds.save_as(path, write_like_original=False)
        except Exception:
            ds2 = self.create_base_dicom()
            ds2.save_as(path, write_like_original=False)
        results["no_sop_instance"] = path

        # Missing PatientID
        ds = self.create_base_dicom()
        ds.PatientName = "MISSING^PATIENT_ID"
        del ds.PatientID
        path = output_dir / "no_patient_id.dcm"
        ds.save_as(path, write_like_original=False)
        results["no_patient_id"] = path

        # Missing StudyInstanceUID
        ds = self.create_base_dicom()
        ds.PatientName = "MISSING^STUDY_INSTANCE"
        del ds.StudyInstanceUID
        path = output_dir / "no_study_instance.dcm"
        ds.save_as(path, write_like_original=False)
        results["no_study_instance"] = path

        print(f"[+] Generated missing_required samples in {output_dir}")
        return results

    # =========================================================================
    # Encoding error samples
    # =========================================================================

    def generate_encoding_error_samples(self) -> dict[str, Path]:
        """Generate samples with character encoding violations."""
        results = {}
        output_dir = self.output_dir / "encoding_errors"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Invalid UTF-8 sequences
        ds = self.create_base_dicom()
        ds.PatientName = "ENCODING^INVALID_UTF8"
        ds.SpecificCharacterSet = "ISO_IR 192"  # UTF-8
        path = output_dir / "invalid_utf8.dcm"
        ds.save_as(path, write_like_original=False)
        # Inject invalid UTF-8 bytes
        with open(path, "ab") as f:
            # Private tag with invalid UTF-8
            f.write(struct.pack("<HH", 0x0009, 0x1010))
            f.write(b"LO")
            invalid_utf8 = b"\xff\xfe\x80\x81\x82"  # Invalid UTF-8 sequence
            f.write(struct.pack("<H", len(invalid_utf8)))
            f.write(invalid_utf8)
        results["invalid_utf8"] = path

        # Wrong charset declared
        ds = self.create_base_dicom()
        ds.SpecificCharacterSet = "ISO_IR 100"  # Latin-1
        # But use characters that aren't valid Latin-1
        ds.PatientName = "ENCODING^WRONG_CHARSET"
        path = output_dir / "wrong_charset.dcm"
        ds.save_as(path, write_like_original=False)
        # Inject UTF-8 encoded data where Latin-1 is declared
        with open(path, "ab") as f:
            f.write(struct.pack("<HH", 0x0009, 0x1011))
            f.write(b"LO")
            utf8_data = "日本語テスト".encode()  # UTF-8, not Latin-1
            f.write(struct.pack("<H", len(utf8_data)))
            f.write(utf8_data)
        results["wrong_charset"] = path

        # Null bytes in string
        ds = self.create_base_dicom()
        ds.PatientName = "ENCODING^NULL_BYTES"
        path = output_dir / "null_in_string.dcm"
        ds.save_as(path, write_like_original=False)
        # Inject string with null bytes
        with open(path, "ab") as f:
            f.write(struct.pack("<HH", 0x0009, 0x1012))
            f.write(b"LO")
            null_string = b"Hello\x00World\x00Test"
            f.write(struct.pack("<H", len(null_string)))
            f.write(null_string)
        results["null_in_string"] = path

        # Mixed encoding
        ds = self.create_base_dicom()
        ds.PatientName = "ENCODING^MIXED"
        ds.SpecificCharacterSet = [
            "ISO 2022 IR 6",
            "ISO 2022 IR 87",
        ]  # ASCII + Japanese
        path = output_dir / "mixed_encoding.dcm"
        ds.save_as(path, write_like_original=False)
        results["mixed_encoding"] = path

        print(f"[+] Generated encoding_errors samples in {output_dir}")
        return results

    def generate_all(self) -> dict[str, dict[str, Path]]:
        """Generate all compliance violation samples."""
        return {
            "invalid_vr": self.generate_invalid_vr_samples(),
            "oversized_values": self.generate_oversized_samples(),
            "missing_required": self.generate_missing_required_samples(),
            "encoding_errors": self.generate_encoding_error_samples(),
        }


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate DICOM compliance violation samples"
    )
    parser.add_argument(
        "--output-dir",
        default="samples/compliance_violations",
        help="Output directory",
    )
    parser.add_argument(
        "--category",
        choices=["invalid_vr", "oversized", "missing", "encoding", "all"],
        default="all",
        help="Category of violations to generate",
    )

    args = parser.parse_args()

    generator = ComplianceViolationGenerator(args.output_dir)

    if args.category == "all":
        generator.generate_all()
    elif args.category == "invalid_vr":
        generator.generate_invalid_vr_samples()
    elif args.category == "oversized":
        generator.generate_oversized_samples()
    elif args.category == "missing":
        generator.generate_missing_required_samples()
    elif args.category == "encoding":
        generator.generate_encoding_error_samples()


if __name__ == "__main__":
    main()
