# CVE-2024-22100 - MicroDicom DICOM Viewer

## Overview

| Field    | Value                      |
| -------- | -------------------------- |
| CVE ID   | CVE-2024-22100             |
| Product  | MicroDicom DICOM Viewer    |
| Type     | Heap-based buffer overflow |
| CVSS     | 7.8                        |
| Year     | 2024                       |
| Affected | < 2024.1                   |
| Fixed    | 2024.1                     |

## Description

MicroDicom DICOM Viewer versions 2023.3 (Build 9342) and prior are affected by a heap-based buffer overflow vulnerability, which could allow an attacker to execute arbitrary code. A user must open a malicious DCM file in order to exploit the vulnerability.

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
dicom-fuzzer samples --scan samples/cve_reproductions/cve_2024_22100/

# Generate the sample
python -m samples.cve_reproductions.generator --cve CVE-2024-22100
```

## Mitigation

Update to version 2024.1 or later.

## References

- https://nvd.nist.gov/vuln/detail/CVE-2024-22100
- https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-163-01
