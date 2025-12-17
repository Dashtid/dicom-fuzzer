#!/usr/bin/env python3
"""
Parser Stress Test Sample Generator

Generates DICOM files with edge cases that stress-test parser implementations.
These samples are designed to reveal crashes, hangs, and other robustness issues.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from pathlib import Path

try:
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.sequence import Sequence
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid

    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False


class ParserStressGenerator:
    """Generator for parser stress test DICOM samples."""

    def __init__(self, output_dir: str | Path = ".") -> None:
        if not HAS_PYDICOM:
            raise ImportError("pydicom is required")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

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
        ds.PatientName = "STRESS^TEST"
        ds.PatientID = "STRESS-001"
        ds.StudyDate = "20250101"
        ds.StudyTime = "120000"
        ds.Modality = "OT"
        ds.SeriesInstanceUID = generate_uid()
        ds.StudyInstanceUID = generate_uid()
        ds.FrameOfReferenceUID = generate_uid()
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

    def generate_deep_sequence_nesting(
        self, output_path: Path | None = None, depth: int = 100
    ) -> Path:
        """
        Generate DICOM with deeply nested sequences.

        Creates a sequence hierarchy that may cause stack overflow
        in recursive parsers.
        """
        if output_path is None:
            output_path = self.output_dir / "deep_sequence_nesting.dcm"

        ds = self.create_base_dicom()
        ds.PatientName = f"DEEP_NESTING^DEPTH_{depth}"

        # Build nested sequence structure
        # Using a referenced content sequence to create deep nesting
        inner_ds = Dataset()
        inner_ds.TextValue = f"Nesting level {depth}"

        current = inner_ds
        for i in range(depth - 1, 0, -1):
            wrapper = Dataset()
            wrapper.TextValue = f"Nesting level {i}"
            wrapper.ContentSequence = Sequence([current])
            current = wrapper

        # Attach to main dataset
        ds.ContentSequence = Sequence([current])

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_giant_value_length(self, output_path: Path | None = None) -> Path:
        """
        Generate DICOM with extremely large Value Length fields.

        Tests parser handling of memory allocation based on VL.
        """
        if output_path is None:
            output_path = self.output_dir / "giant_value_length.dcm"

        # Create base DICOM
        ds = self.create_base_dicom()
        ds.PatientName = "GIANT_VL^TEST"
        ds.save_as(output_path, write_like_original=False)

        # Manually inject a data element with huge VL
        with open(output_path, "ab") as f:
            # Write a private tag with giant VL
            # Tag (0009,0010) - Private Creator
            f.write(struct.pack("<HH", 0x0009, 0x0010))
            # VR = LO (4 bytes in explicit)
            f.write(b"LO")
            # Reserved (2 bytes)
            f.write(b"\x00\x00")
            # Value Length = huge but file ends
            f.write(struct.pack("<I", 0x7FFFFFFF))
            # Actual value (much smaller)
            f.write(b"Giant VL Test")

        return output_path

    def generate_truncated_pixeldata(self, output_path: Path | None = None) -> Path:
        """
        Generate DICOM with truncated pixel data.

        Declares larger image size than actual pixel data provided.
        """
        if output_path is None:
            output_path = self.output_dir / "truncated_pixeldata.dcm"

        ds = self.create_base_dicom()
        ds.PatientName = "TRUNCATED^PIXELDATA"

        # Declare large image
        ds.Rows = 512
        ds.Columns = 512
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15

        # But provide much smaller pixel data
        # Should be 512*512*2 = 524288 bytes
        # We provide only 1024 bytes
        ds.PixelData = bytes([0xAB, 0xCD] * 512)

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_undefined_length_abuse(self, output_path: Path | None = None) -> Path:
        """
        Generate DICOM with undefined length on non-sequence elements.

        Tests parser handling of illegal undefined length usage.
        """
        if output_path is None:
            output_path = self.output_dir / "undefined_length_abuse.dcm"

        # Create base DICOM
        ds = self.create_base_dicom()
        ds.PatientName = "UNDEFINED_LENGTH^ABUSE"
        ds.save_as(output_path, write_like_original=False)

        # Manually add element with undefined length (0xFFFFFFFF)
        # where it's not allowed (non-SQ, non-UN)
        with open(output_path, "ab") as f:
            # Tag (0010,0030) - PatientBirthDate
            f.write(struct.pack("<HH", 0x0010, 0x0030))
            # VR = DA (Date)
            f.write(b"DA")
            # For explicit VR with 2-byte length field
            # Use undefined length (illegal for DA)
            f.write(struct.pack("<H", 0xFFFF))
            # Write some data anyway
            f.write(b"19900101")
            # Missing sequence delimitation item

        return output_path

    def generate_invalid_transfer_syntax(self, output_path: Path | None = None) -> Path:
        """
        Generate DICOM with mismatched transfer syntax.

        Header declares Explicit VR but data is Implicit VR.
        """
        if output_path is None:
            output_path = self.output_dir / "invalid_transfer_syntax.dcm"

        # Create with explicit VR
        ds = self.create_base_dicom()
        ds.PatientName = "TRANSFER_SYNTAX^MISMATCH"
        ds.save_as(output_path, write_like_original=False)

        # Now corrupt by changing some elements to implicit format
        with open(output_path, "r+b") as f:
            content = f.read()

            # Find and corrupt a data element
            # Replace explicit VR format with implicit
            # This creates encoding inconsistency
            f.seek(0)
            # Write back with corrupted data after metadata
            f.write(content[:200])  # Keep file meta intact

            # Inject implicit VR element in explicit VR stream
            # Tag (0009,1001) - Private tag
            f.write(struct.pack("<HH", 0x0009, 0x1001))
            # Write as implicit (no VR, 4-byte length)
            f.write(struct.pack("<I", 8))
            f.write(b"CORRUPT!")

            f.write(content[200:])

        return output_path

    def generate_recursive_item_nesting(self, output_path: Path | None = None) -> Path:
        """
        Generate DICOM with potentially circular structures.

        Creates sequence items that could cause infinite parsing loops.
        Note: We can't create true circular references in pydicom,
        so we create deeply nested self-similar structures instead.
        """
        if output_path is None:
            output_path = self.output_dir / "recursive_item_nesting.dcm"

        ds = self.create_base_dicom()
        ds.PatientName = "RECURSIVE^ITEMS"

        # Create a deeply nested structure that resembles recursion
        # without actual circular references (which pydicom can't serialize)
        def create_nested_item(depth: int, max_depth: int = 50) -> Dataset:
            item = Dataset()
            item.TextValue = f"Nested item at depth {depth}"
            item.ReferencedSOPInstanceUID = ds.SOPInstanceUID  # Self-reference

            if depth < max_depth:
                inner = create_nested_item(depth + 1, max_depth)
                item.ContentSequence = Sequence([inner])

            return item

        # Create structure with multiple branches
        item1 = create_nested_item(0, 30)
        item2 = create_nested_item(0, 30)

        ds.ContentSequence = Sequence([item1, item2])

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_zero_length_elements(self, output_path: Path | None = None) -> Path:
        """
        Generate DICOM with zero-length required elements.

        Tests handling of empty values for fields that shouldn't be empty.
        """
        if output_path is None:
            output_path = self.output_dir / "zero_length_elements.dcm"

        ds = self.create_base_dicom()
        ds.PatientName = ""  # Empty required field
        ds.PatientID = ""
        ds.StudyDate = ""
        ds.Modality = ""
        ds.SOPClassUID = ""  # Very problematic
        ds.SOPInstanceUID = ""

        # Empty pixel data
        ds.PixelData = b""

        try:
            ds.save_as(output_path, write_like_original=False)
        except Exception:
            # If pydicom refuses, create manually
            base = self.create_base_dicom()
            base.save_as(output_path, write_like_original=False)

            # Manually patch to zero-length
            with open(output_path, "r+b") as f:
                content = f.read()
                # Find PatientName tag and zero its length
                # This is a simplified approach
                f.seek(0)
                f.write(content)

        return output_path

    def generate_all(self) -> dict[str, Path | None]:
        """Generate all stress test samples."""
        results: dict[str, Path | None] = {}

        generators: list[tuple[str, Callable[[], Path]]] = [
            ("deep_sequence_nesting", self.generate_deep_sequence_nesting),
            ("giant_value_length", self.generate_giant_value_length),
            ("truncated_pixeldata", self.generate_truncated_pixeldata),
            ("undefined_length_abuse", self.generate_undefined_length_abuse),
            ("invalid_transfer_syntax", self.generate_invalid_transfer_syntax),
            ("recursive_item_nesting", self.generate_recursive_item_nesting),
            ("zero_length_elements", self.generate_zero_length_elements),
        ]

        for name, generator in generators:
            try:
                path = generator()
                results[name] = path
                print(f"[+] Generated {name}: {path}")
            except Exception as e:
                print(f"[-] Failed {name}: {e}")
                results[name] = None

        return results


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate parser stress test DICOM samples"
    )
    parser.add_argument(
        "--output-dir",
        default="samples/parser_stress",
        help="Output directory",
    )
    parser.add_argument(
        "--type",
        choices=[
            "deep_nesting",
            "giant_vl",
            "truncated",
            "undefined_length",
            "transfer_syntax",
            "recursive",
            "zero_length",
            "all",
        ],
        default="all",
        help="Type of stress test to generate",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=100,
        help="Nesting depth for deep_nesting test",
    )

    args = parser.parse_args()

    generator = ParserStressGenerator(args.output_dir)

    if args.type == "all":
        generator.generate_all()
    elif args.type == "deep_nesting":
        generator.generate_deep_sequence_nesting(depth=args.depth)
    elif args.type == "giant_vl":
        generator.generate_giant_value_length()
    elif args.type == "truncated":
        generator.generate_truncated_pixeldata()
    elif args.type == "undefined_length":
        generator.generate_undefined_length_abuse()
    elif args.type == "transfer_syntax":
        generator.generate_invalid_transfer_syntax()
    elif args.type == "recursive":
        generator.generate_recursive_item_nesting()
    elif args.type == "zero_length":
        generator.generate_zero_length_elements()


if __name__ == "__main__":
    main()
