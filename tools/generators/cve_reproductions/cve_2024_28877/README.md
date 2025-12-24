# CVE-2024-28877 - MicroDicom DICOM Viewer

## Overview

| Field    | Value                       |
| -------- | --------------------------- |
| CVE ID   | CVE-2024-28877              |
| Product  | MicroDicom DICOM Viewer     |
| Type     | Stack-based buffer overflow |
| CVSS     | 8.7                         |
| Year     | 2024                        |
| Affected | < 2024.2                    |
| Fixed    | 2024.2                      |

## Description

MicroDicom DICOM Viewer is vulnerable to a stack-based buffer overflow, which may allow an attacker to execute arbitrary code on affected installations. A user must open a malicious DCM file to trigger the vulnerability.

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
dicom-fuzzer samples --scan samples/cve_reproductions/cve_2024_28877/

# Generate the sample
python -m samples.cve_reproductions.generator --cve CVE-2024-28877
```

## Mitigation

Update to version 2024.2 or later.

## References

- https://nvd.nist.gov/vuln/detail/CVE-2024-28877
- https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-163-01
