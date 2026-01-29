# CVE Reference

DICOM vulnerabilities for security validation testing.

## Purpose

CVE replication generates deterministic test files to validate whether a DICOM parser is vulnerable to known CVEs. This is directed greybox fuzzing, not exploitation.

**Intended use:**

- Generate malformed DICOM files to test parser implementations
- Validate software handles edge cases safely
- Discover vulnerabilities before attackers do

## Usage

```bash
# List available CVEs
dicom-fuzzer cve --list

# Generate all CVE files
dicom-fuzzer cve --all -t template.dcm -o ./cve_output

# Generate specific CVE
dicom-fuzzer cve --cve CVE-2025-5943 -t template.dcm -o ./output

# Filter by product
dicom-fuzzer cve --product MicroDicom -t template.dcm -o ./output

# Filter by category
dicom-fuzzer cve --category heap_overflow -t template.dcm -o ./output

# Get CVE details
dicom-fuzzer cve --info CVE-2025-5943
```

## CVE Database

| CVE ID         | Severity | Product        | Type                |
| -------------- | -------- | -------------- | ------------------- |
| CVE-2025-5943  | critical | MicroDicom     | Heap overflow       |
| CVE-2025-35975 | critical | MicroDicom     | OOB write           |
| CVE-2025-27578 | critical | OsiriX MD      | Use-after-free      |
| CVE-2024-47796 | critical | DCMTK          | OOB write (LUT)     |
| CVE-2024-52333 | critical | DCMTK          | OOB write (minmax)  |
| CVE-2024-22100 | critical | MicroDicom     | Heap overflow       |
| CVE-2024-28877 | critical | MicroDicom     | Stack overflow      |
| CVE-2019-11687 | critical | Multiple       | Preamble polyglot   |
| CVE-2025-31946 | high     | OsiriX MD      | Use-after-free      |
| CVE-2025-11266 | high     | GDCM           | Integer underflow   |
| CVE-2025-53618 | high     | GDCM           | JPEG codec OOB      |
| CVE-2025-53619 | high     | GDCM           | JPEG truncation     |
| CVE-2025-36521 | high     | MicroDicom     | OOB read            |
| CVE-2025-5307  | high     | Sante Viewer   | OOB read            |
| CVE-2024-1453  | high     | Sante Viewer   | OOB read            |
| CVE-2024-25578 | high     | MicroDicom     | OOB write           |
| CVE-2024-33606 | high     | MicroDicom     | URL scheme bypass   |
| CVE-2020-29625 | high     | DCMTK          | Undefined length    |
| CVE-2021-41946 | high     | ClearCanvas    | Path traversal      |
| CVE-2025-1001  | medium   | RadiAnt        | Cert bypass (MITM)  |
| CVE-2025-1002  | medium   | MicroDicom     | Cert bypass (MITM)  |
| CVE-2022-24193 | medium   | OsiriX         | Deep nesting DoS    |

## Vulnerability Categories

| Category         | Description                          |
| ---------------- | ------------------------------------ |
| heap_overflow    | Heap-based buffer overflow           |
| stack_overflow   | Stack-based buffer overflow          |
| oob_write        | Out-of-bounds write                  |
| oob_read         | Out-of-bounds read                   |
| integer_overflow | Integer overflow/underflow           |
| use_after_free   | Use-after-free                       |
| path_traversal   | Directory traversal                  |
| cert_bypass      | Certificate validation bypass        |
| dos              | Denial of service                    |

## References

- [CISA Medical Device Advisories](https://www.cisa.gov/topics/industrial-control-systems/medical-devices)
- [NVD DICOM Vulnerabilities](https://nvd.nist.gov/vuln/search/results?query=dicom)
- [Claroty DICOM Research](https://claroty.com/team82/research/dicom-demystified)
