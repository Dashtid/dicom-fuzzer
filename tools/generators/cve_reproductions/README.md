# CVE Reproduction Samples

This directory contains DICOM files specifically crafted to trigger known vulnerabilities in DICOM parsers, viewers, and servers.

> **WARNING**: These samples may cause crashes, memory corruption, or other unintended behavior in vulnerable software. Use only in isolated test environments.

## CVE Index

| CVE ID                            | Product        | Vulnerability Type            | CVSS | Year | Status          |
| --------------------------------- | -------------- | ----------------------------- | ---- | ---- | --------------- |
| [CVE-2019-11687](cve_2019_11687/) | DICOM Standard | Preamble executable embedding | N/A  | 2019 | Sample included |
| [CVE-2022-2119](cve_2022_2119/)   | DCMTK          | Path traversal (SCP)          | 7.5  | 2022 | Sample included |
| [CVE-2022-2120](cve_2022_2120/)   | DCMTK          | Path traversal (SCU)          | 7.5  | 2022 | Sample included |
| [CVE-2022-2121](cve_2022_2121/)   | DCMTK          | Null pointer dereference      | 6.5  | 2022 | Sample included |
| [CVE-2025-5943](cve_2025_5943/)   | MicroDicom     | Out-of-bounds write           | 8.8  | 2025 | Sample included |
| [CVE-2025-11266](cve_2025_11266/) | GDCM           | PixelData OOB write           | 6.6  | 2025 | Sample included |
| [CVE-2025-53618](cve_2025_53618/) | GDCM           | JPEG codec OOB read           | 7.5  | 2025 | Sample included |

## Usage

### Testing a Specific CVE

```bash
# Test CVE-2025-5943 against MicroDicom
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/cve_2025_5943/ \
    --viewer "C:/Path/To/MicroDicom.exe"

# Test all CVE samples
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/ \
    --viewer "C:/Path/To/Viewer.exe" \
    --recursive
```

### Checking Vulnerability Status

```python
from samples.cve_reproductions import CVERegistry

# List all CVEs
for cve in CVERegistry.list_all():
    print(f"{cve.id}: {cve.product} - {cve.description}")

# Get specific CVE info
cve = CVERegistry.get("CVE-2025-5943")
print(f"Affected: {cve.affected_versions}")
print(f"Fixed in: {cve.fixed_version}")
```

## CVE Details

### CVE-2019-11687 - DICOM Preamble Executable

**Product**: DICOM Standard (all implementations)
**Type**: Design flaw allowing executable embedding
**Impact**: Malware can be hidden in medical images

The DICOM standard allows 128 arbitrary bytes in the file preamble. This enables creation of polyglot files that are both valid DICOM images and executable programs.

**Sample**: Creates PE/DICOM polyglot with benign payload
**Detection**: Check preamble for executable headers (MZ, ELF, Mach-O)

### CVE-2022-2119 - DCMTK Path Traversal (SCP)

**Product**: DCMTK (all versions before 3.6.7)
**Type**: Path traversal in C-STORE SCP
**Impact**: Arbitrary file write on server

A malicious DICOM client can send files to arbitrary locations on the server by manipulating path components in the DICOM metadata.

**Sample**: DICOM file with `../../../` in filename metadata
**Trigger**: Send via C-STORE to vulnerable dcmqrscp

### CVE-2022-2120 - DCMTK Path Traversal (SCU)

**Product**: DCMTK (all versions before 3.6.7)
**Type**: Path traversal in C-GET SCU
**Impact**: Arbitrary file write on client

A malicious DICOM server can trick clients into writing files to arbitrary locations by including path traversal sequences in response filenames.

**Sample**: Server response with traversal paths
**Trigger**: C-GET request to malicious server

### CVE-2022-2121 - DCMTK Null Pointer Dereference

**Product**: DCMTK (all versions before 3.6.7)
**Type**: Null pointer dereference
**Impact**: Denial of service (crash)

Reading a malformed DICOM file from STDIN triggers a null pointer dereference in the parsing routine.

**Sample**: Truncated DICOM with specific structure
**Trigger**: Pipe to dcmdump or similar tool

### CVE-2025-5943 - MicroDicom Out-of-Bounds Write

**Product**: MicroDicom DICOM Viewer (< 2025.3)
**Type**: Out-of-bounds write
**Impact**: Remote code execution

Parsing a malformed DICOM file can trigger an out-of-bounds write, potentially allowing arbitrary code execution.

**Sample**: DICOM with malformed pixel data structure
**Trigger**: Open in MicroDicom Viewer

### CVE-2025-11266 - GDCM PixelData OOB Write

**Product**: Grassroots DICOM (GDCM) < 3.2.2
**Type**: Out-of-bounds write in PixelData parsing
**Impact**: Denial of service, potential RCE

Parsing encapsulated PixelData fragments can trigger an unsigned integer underflow leading to out-of-bounds memory access.

**Sample**: DICOM with malformed encapsulated fragments
**Trigger**: Process with GDCM-based tools (SimpleITK, medInria)

### CVE-2025-53618 - GDCM JPEG Codec OOB Read

**Product**: Grassroots DICOM (GDCM) < 3.0.24
**Type**: Out-of-bounds read in JPEG codec
**Impact**: Information leakage

The JPEGBITSCodec functionality contains an out-of-bounds read vulnerability when processing malformed JPEG-compressed DICOM images.

**Sample**: DICOM with malformed JPEG-LS compressed data
**Trigger**: Decompress with GDCM

## Sample Generation

Each CVE directory contains:

- `README.md` - Detailed vulnerability description
- `trigger.dcm` - Sample that triggers the vulnerability
- `generator.py` - Script to generate variants (where applicable)
- `mitigations.md` - Recommended fixes and workarounds

### Regenerating Samples

```bash
# Regenerate all CVE samples
python -m samples.cve_reproductions.generate_all

# Regenerate specific CVE
python samples/cve_reproductions/cve_2025_5943/generator.py
```

## Responsible Disclosure

These CVEs have all been publicly disclosed and patches are available. Before testing:

1. Verify your software version against affected versions
2. Apply available patches before production testing
3. Test only in isolated environments
4. Report any new vulnerabilities through proper channels

## References

- [CISA Medical Device Security Advisories](https://www.cisa.gov/topics/industrial-control-systems/medical-devices)
- [Claroty Team82 DCMTK Research](https://claroty.com/team82/research/dicom-demystified-exploring-the-underbelly-of-medical-imaging)
- [NVD DICOM Vulnerabilities](https://nvd.nist.gov/vuln/search/results?query=dicom)
