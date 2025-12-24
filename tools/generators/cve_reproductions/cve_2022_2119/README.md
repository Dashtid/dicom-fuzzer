# CVE-2022-2119 - DCMTK

## Overview

| Field    | Value                |
| -------- | -------------------- |
| CVE ID   | CVE-2022-2119        |
| Product  | DCMTK                |
| Type     | Path traversal (SCP) |
| CVSS     | 7.5                  |
| Year     | 2022                 |
| Affected | < 3.6.7              |
| Fixed    | 3.6.7                |

## Description

Path traversal in C-STORE SCP allows arbitrary file write

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/cve_2022_2119/ \
    --viewer "path/to/vulnerable/viewer"
```

## Mitigation

Update to version 3.6.7 or later.

## References

- https://nvd.nist.gov/vuln/detail/CVE-2022-2119
- https://claroty.com/team82/research/dicom-demystified
