# CVE-2025-5943 - MicroDicom DICOM Viewer

## Overview

| Field    | Value                   |
| -------- | ----------------------- |
| CVE ID   | CVE-2025-5943           |
| Product  | MicroDicom DICOM Viewer |
| Type     | Out-of-bounds write     |
| CVSS     | 8.8                     |
| Year     | 2025                    |
| Affected | < 2025.3                |
| Fixed    | 2025.3                  |

## Description

OOB write when parsing malformed DICOM files

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/cve_2025_5943/ \
    --viewer "path/to/vulnerable/viewer"
```

## Mitigation

Update to version 2025.3 or later.

## References

- https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-160-01
