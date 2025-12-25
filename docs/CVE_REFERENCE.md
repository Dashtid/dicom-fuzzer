# CVE Reference

DICOM vulnerabilities targeted by the fuzzer's security mutations.

**Total: 26 mutations across 20 CVEs** (expanded December 2025)

## Security Testing Philosophy

These CVE-inspired mutations are **vulnerability-guided fuzzing** (also known as Directed
Greybox Fuzzing), not penetration testing or exploitation tools.

### Fuzzing vs Penetration Testing

| Aspect             | This Tool (Fuzzing)                 | Penetration Testing        |
| ------------------ | ----------------------------------- | -------------------------- |
| **Purpose**        | Find parsing bugs in YOUR software  | Exploit vulnerabilities    |
| **Output**         | Malformed test files                | Proof of exploitation      |
| **Target**         | File format parsers                 | Running production systems |
| **Automation**     | Fully automated                     | Manual/semi-automated      |
| **Question Asked** | "Does my parser have similar bugs?" | "Can I exploit this CVE?"  |

### Why CVE-Inspired Mutations?

CVE patterns guide the fuzzer toward known vulnerability classes, making it more effective
at finding similar bugs. This approach is:

- **Recommended by FDA** for medical device security testing (2025 guidance)
- **Industry standard** practice (AFL-GO, BEACON, SyzDirect all use directed fuzzing)
- **Proven effective** - directed fuzzers find 11x more bugs than random fuzzing

### Intended Use

```text
[+] Generate malformed DICOM files to test YOUR parser implementations
[+] Validate that your software handles edge cases safely
[+] Discover similar vulnerabilities before attackers do
[-] NOT for attacking production PACS/VNA systems
[-] NOT for exploiting known CVEs in third-party software
```

This tool generates test cases - it does not exploit running systems.

## CVE Database

| CVE ID         | Product      | Type                   | CVSS | Fixed In   | Mutations |
| -------------- | ------------ | ---------------------- | ---- | ---------- | --------- |
| CVE-2025-35975 | MicroDicom   | OOB write              | 8.4  | 2025.2     | 1         |
| CVE-2025-5943  | MicroDicom   | Heap overflow          | 8.8  | 2025.3     | 2         |
| CVE-2025-27578 | OsiriX MD    | Use-after-free (RCE)   | 9.8  | Unknown    | 1         |
| CVE-2025-31946 | OsiriX MD    | Use-after-free (local) | 7.8  | Unknown    | 1         |
| CVE-2025-5307  | Sante Viewer | OOB read               | 7.8  | Unknown    | 1         |
| CVE-2025-11266 | GDCM         | PixelData OOB write    | 6.6  | 3.2.2      | 2         |
| CVE-2025-53618 | GDCM         | JPEG codec OOB read    | 7.5  | 3.0.24     | 1         |
| CVE-2025-53619 | GDCM         | JPEG info disclosure   | 7.5  | 3.0.24     | 1         |
| CVE-2025-1001  | RadiAnt      | TLS cert bypass (MitM) | 5.7  | 2025.1     | 1         |
| CVE-2024-1453  | Sante Viewer | OOB read               | 7.8  | 4.0        | 1         |
| CVE-2024-22100 | MicroDicom   | Heap overflow          | 7.8  | 2024.1     | 1         |
| CVE-2024-25578 | MicroDicom   | OOB write (validation) | 7.8  | 2024.1     | 1         |
| CVE-2024-28877 | MicroDicom   | Stack overflow         | 8.7  | 2024.2     | 1         |
| CVE-2024-33606 | MicroDicom   | URL scheme auth bypass | 8.8  | 2024.2     | 1         |
| CVE-2024-47796 | DCMTK        | OOB write (nowindow)   | 8.4  | 3.6.9      | 1         |
| CVE-2024-52333 | DCMTK        | OOB write (minmax)     | 8.4  | 3.6.9      | 1         |
| CVE-2022-2119  | DCMTK        | Path traversal (SCP)   | 7.5  | 3.6.7      | sample    |
| CVE-2022-2120  | DCMTK        | Path traversal (SCU)   | 7.5  | 3.6.7      | sample    |
| CVE-2022-2121  | DCMTK        | Null pointer deref     | 6.5  | 3.6.7      | sample    |
| CVE-2019-11687 | DICOM Std    | Preamble executable    | N/A  | Mitigation | 2         |

## Mutation Types

The fuzzer applies these CVE-based mutations by default:

| Mutation                   | Target CVE     | Technique                           |
| -------------------------- | -------------- | ----------------------------------- |
| `cve_heap_overflow`        | CVE-2025-5943  | Malformed pixel data dimensions     |
| `cve_integer_overflow`     | CVE-2025-5943  | Overflow in Rows/Columns            |
| `cve_oob_write`            | CVE-2025-35975 | Dimension/size mismatches           |
| `cve_oob_write_validation` | CVE-2024-25578 | Malformed element lengths           |
| `cve_heap_dcm_parsing`     | CVE-2024-22100 | Private element overflow            |
| `cve_stack_overflow`       | CVE-2024-28877 | Deep nesting + oversized strings    |
| `cve_url_scheme_bypass`    | CVE-2024-33606 | Malicious URLs in metadata          |
| `cve_cert_validation`      | CVE-2025-1001  | Update URL injection                |
| `cve_use_after_free`       | CVE-2025-27578 | Premature sequence termination      |
| `cve_use_after_free_local` | CVE-2025-31946 | Invalid PixelData offset references |
| `cve_oob_read_sante_2024`  | CVE-2024-1453  | Oversized element length fields     |
| `cve_oob_read_sante_2025`  | CVE-2025-5307  | Dimension/buffer size mismatches    |
| `cve_malformed_length`     | CVE-2020-29625 | Undefined/oversized length fields   |
| `cve_path_traversal`       | CVE-2021-41946 | `../` in filename metadata          |
| `cve_deep_nesting`         | CVE-2022-24193 | 100+ level sequence nesting         |
| `cve_polyglot`             | CVE-2019-11687 | PE/ELF header in preamble           |
| `cve_encapsulated_pixel`   | CVE-2025-11266 | Fragment count mismatch             |
| `cve_jpeg_codec`           | CVE-2025-53618 | Truncated JPEG-LS stream            |
| `cve_dcmtk_nowindow`       | CVE-2024-47796 | LUT index overflow in nowindow      |
| `cve_dcmtk_minmax`         | CVE-2024-52333 | determineMinMax array overflow      |
| `cve_random`               | Any            | Random CVE from registry            |

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

### CVE-2025-27578/31946 - OsiriX MD Use-After-Free

Use-after-free vulnerabilities in OsiriX MD medical imaging software:

- **CVE-2025-27578:** Remote code execution via crafted DICOM file (CVSS 9.8)
- **CVE-2025-31946:** Local privilege escalation via malformed PixelData (CVSS 7.8)

**Trigger:** Open crafted `.dcm` in affected OsiriX MD versions
**Technique:** Premature sequence termination and invalid offset references cause dangling pointer dereference
**Reference:** [NVD CVE-2025-27578](https://nvd.nist.gov/vuln/detail/CVE-2025-27578)

### CVE-2024-1453/CVE-2025-5307 - Sante DICOM Viewer Pro OOB Read

Out-of-bounds read vulnerabilities in Sante DICOM Viewer Pro:

- **CVE-2024-1453:** OOB read via malformed element length fields (CVSS 7.8)
- **CVE-2025-5307:** OOB read via dimension/buffer size mismatches (CVSS 7.8)

**Trigger:** Open crafted `.dcm` in Sante DICOM Viewer Pro < 4.0
**Technique:** Oversized length fields and dimension values trigger reads beyond buffer boundaries
**Reference:** [CISA ICS-CERT](https://www.cisa.gov/topics/industrial-control-systems/medical-devices)

### CVE-2022-2119/2120 - DCMTK Path Traversal

Path traversal in C-STORE SCP/SCU allows arbitrary file write via `../` sequences in filename metadata.

**Trigger:** Send/receive via DCMTK < 3.6.7
**Reference:** [Claroty Team82](https://claroty.com/team82/research/dicom-demystified)

### CVE-2024-47796/CVE-2024-52333 - DCMTK Image Processing OOB Write

Out-of-bounds write vulnerabilities in DCMTK 3.6.8 image processing (Cisco Talos):

- **CVE-2024-47796:** OOB write in nowindow LUT processing when pixel count mismatches dimensions (CVSS 8.4)
- **CVE-2024-52333:** OOB write in determineMinMax when array bounds not validated (CVSS 8.4)

**Trigger:** Process crafted `.dcm` with DCMTK < 3.6.9 (dcmimgle library)
**Technique:** Dimension/pixel count mismatches trigger array index overflows
**Reference:** [TALOS-2024-2121](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2121), [TALOS-2024-2122](https://talosintelligence.com/vulnerability_reports/TALOS-2024-2122)

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
