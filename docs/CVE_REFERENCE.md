# CVE Reference

DICOM vulnerabilities targeted by the fuzzer's security mutations.

**Total: 20 mutations across 14 CVEs** (expanded December 2025)

## CVE Database

| CVE ID         | Product    | Type                   | CVSS | Fixed In   | Mutations |
| -------------- | ---------- | ---------------------- | ---- | ---------- | --------- |
| CVE-2025-35975 | MicroDicom | OOB write              | 8.4  | 2025.2     | 1         |
| CVE-2025-5943  | MicroDicom | Heap overflow          | 8.8  | 2025.3     | 2         |
| CVE-2025-11266 | GDCM       | PixelData OOB write    | 6.6  | 3.2.2      | 2         |
| CVE-2025-53618 | GDCM       | JPEG codec OOB read    | 7.5  | 3.0.24     | 1         |
| CVE-2025-53619 | GDCM       | JPEG info disclosure   | 7.5  | 3.0.24     | 1         |
| CVE-2025-1001  | RadiAnt    | TLS cert bypass (MitM) | 5.7  | 2025.1     | 1         |
| CVE-2024-22100 | MicroDicom | Heap overflow          | 7.8  | 2024.1     | 1         |
| CVE-2024-25578 | MicroDicom | OOB write (validation) | 7.8  | 2024.1     | 1         |
| CVE-2024-28877 | MicroDicom | Stack overflow         | 8.7  | 2024.2     | 1         |
| CVE-2024-33606 | MicroDicom | URL scheme auth bypass | 8.8  | 2024.2     | 1         |
| CVE-2022-2119  | DCMTK      | Path traversal (SCP)   | 7.5  | 3.6.7      | sample    |
| CVE-2022-2120  | DCMTK      | Path traversal (SCU)   | 7.5  | 3.6.7      | sample    |
| CVE-2022-2121  | DCMTK      | Null pointer deref     | 6.5  | 3.6.7      | sample    |
| CVE-2019-11687 | DICOM Std  | Preamble executable    | N/A  | Mitigation | 2         |

## Mutation Types

The fuzzer applies these CVE-based mutations by default:

| Mutation                   | Target CVE     | Technique                         |
| -------------------------- | -------------- | --------------------------------- |
| `cve_heap_overflow`        | CVE-2025-5943  | Malformed pixel data dimensions   |
| `cve_integer_overflow`     | CVE-2025-5943  | Overflow in Rows/Columns          |
| `cve_oob_write`            | CVE-2025-35975 | Dimension/size mismatches         |
| `cve_oob_write_validation` | CVE-2024-25578 | Malformed element lengths         |
| `cve_heap_dcm_parsing`     | CVE-2024-22100 | Private element overflow          |
| `cve_stack_overflow`       | CVE-2024-28877 | Deep nesting + oversized strings  |
| `cve_url_scheme_bypass`    | CVE-2024-33606 | Malicious URLs in metadata        |
| `cve_cert_validation`      | CVE-2025-1001  | Update URL injection              |
| `cve_malformed_length`     | CVE-2020-29625 | Undefined/oversized length fields |
| `cve_path_traversal`       | CVE-2021-41946 | `../` in filename metadata        |
| `cve_deep_nesting`         | CVE-2022-24193 | 100+ level sequence nesting       |
| `cve_polyglot`             | CVE-2019-11687 | PE/ELF header in preamble         |
| `cve_encapsulated_pixel`   | CVE-2025-11266 | Fragment count mismatch           |
| `cve_jpeg_codec`           | CVE-2025-53618 | Truncated JPEG-LS stream          |
| `cve_random`               | Any            | Random CVE from registry          |

## Vulnerability Details

### CVE-2025-5943 - MicroDicom OOB Write

Parsing malformed DICOM files triggers out-of-bounds write, enabling RCE.

**Trigger:** Open crafted `.dcm` in MicroDicom < 2025.3
**Reference:** [CISA ICSMA-25-160-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-160-01)

### CVE-2025-11266 - GDCM PixelData OOB Write

Unsigned integer underflow in encapsulated PixelData fragment parsing.

**Trigger:** Process with GDCM-based tools (SimpleITK, medInria)
**Reference:** [CISA ICSMA-25-345-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-345-01)

### CVE-2025-53618/53619 - GDCM JPEG Codec

OOB read in JPEGBITSCodec when decompressing malformed JPEG-LS data.

**Trigger:** Decompress JPEG-compressed DICOM with GDCM < 3.0.24

### CVE-2025-35975 - MicroDicom OOB Write (June 2025)

Out-of-bounds write in MicroDicom DICOM Viewer due to insufficient validation.

**Trigger:** Open crafted `.dcm` in MicroDicom < 2025.2
**Reference:** [CISA ICSMA-25-160-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-160-01)

### CVE-2025-1001 - RadiAnt Certificate Validation Bypass

Improper certificate validation in RadiAnt DICOM Viewer update mechanism enables MITM attacks.

**Trigger:** Update check in RadiAnt < 2025.1
**Reference:** [CISA ICSMA-25-051-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-051-01)

### CVE-2024-22100/25578/28877/33606 - MicroDicom 2024

Multiple vulnerabilities in MicroDicom DICOM Viewer versions prior to 2024.1/2024.2:

- **CVE-2024-22100:** Heap-based buffer overflow (CVSS 7.8)
- **CVE-2024-25578:** Out-of-bounds write due to lack of validation (CVSS 7.8)
- **CVE-2024-28877:** Stack-based buffer overflow (CVSS 8.7)
- **CVE-2024-33606:** URL scheme bypass for arbitrary file access (CVSS 8.8)

**Trigger:** Open crafted `.dcm` in MicroDicom < 2024.2
**Reference:** [CISA ICSMA-24-060-01](https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-060-01)

### CVE-2022-2119/2120 - DCMTK Path Traversal

Path traversal in C-STORE SCP/SCU allows arbitrary file write via `../` sequences in filename metadata.

**Trigger:** Send/receive via DCMTK < 3.6.7
**Reference:** [Claroty Team82](https://claroty.com/team82/research/dicom-demystified)

### CVE-2019-11687 - DICOM Preamble Executable

DICOM preamble (128 bytes) can contain executable headers, creating polyglot files valid as both DICOM images and executables.

**Mitigation:** Validate preamble, reject PE/ELF/Mach-O headers
**Reference:** [pedicom](https://github.com/d00rt/pedicom)

## Usage

```bash
# CVE mutations enabled by default - just run:
dicom-fuzzer input.dcm -c 100 -o ./output

# Disable CVE mutations (not recommended):
dicom-fuzzer input.dcm --no-security

# Generate CVE reproduction samples:
dicom-fuzzer samples --cve-samples -o ./cve_samples

# Target specific CVEs:
dicom-fuzzer input.dcm --security-fuzz --target-cves CVE-2022-2119,CVE-2025-5943
```

## References

- [CISA Medical Device Advisories](https://www.cisa.gov/topics/industrial-control-systems/medical-devices)
- [NVD DICOM Vulnerabilities](https://nvd.nist.gov/vuln/search/results?query=dicom)
- [Claroty DICOM Research](https://claroty.com/team82/research/dicom-demystified)
