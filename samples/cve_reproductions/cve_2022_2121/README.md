# CVE-2022-2121 - DCMTK

## Overview

| Field    | Value                    |
| -------- | ------------------------ |
| CVE ID   | CVE-2022-2121            |
| Product  | DCMTK                    |
| Type     | Null pointer dereference |
| CVSS     | 6.5                      |
| Year     | 2022                     |
| Affected | < 3.6.7                  |
| Fixed    | 3.6.7                    |

## Description

Null pointer dereference when reading from STDIN

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/cve_2022_2121/ \
    --viewer "path/to/vulnerable/viewer"
```

## Mitigation

Update to version 3.6.7 or later.

## References

- https://nvd.nist.gov/vuln/detail/CVE-2022-2121
