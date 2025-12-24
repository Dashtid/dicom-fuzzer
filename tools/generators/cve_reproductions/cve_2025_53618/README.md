# CVE-2025-53618 - Grassroots DICOM (GDCM)

## Overview

| Field    | Value                           |
| -------- | ------------------------------- |
| CVE ID   | CVE-2025-53618                  |
| Product  | Grassroots DICOM (GDCM)         |
| Type     | Out-of-bounds read (JPEG codec) |
| CVSS     | 7.5                             |
| Year     | 2025                            |
| Affected | < 3.0.24                        |
| Fixed    | 3.0.24                          |

## Description

OOB read in JPEGBITSCodec

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/cve_2025_53618/ \
    --viewer "path/to/vulnerable/viewer"
```

## Mitigation

Update to version 3.0.24 or later.

## References

- https://www.redpacketsecurity.com/cve-alert-cve-2025-53618
