# CVE-2025-11266 - Grassroots DICOM (GDCM)

## Overview

| Field    | Value                           |
| -------- | ------------------------------- |
| CVE ID   | CVE-2025-11266                  |
| Product  | Grassroots DICOM (GDCM)         |
| Type     | Out-of-bounds write (PixelData) |
| CVSS     | 6.6                             |
| Year     | 2025                            |
| Affected | < 3.2.2                         |
| Fixed    | 3.2.2                           |

## Description

OOB write in PixelData fragment parsing

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/cve_2025_11266/ \
    --viewer "path/to/vulnerable/viewer"
```

## Mitigation

Update to version 3.2.2 or later.

## References

- https://www.cisa.gov/news-events/ics-medical-advisories/icsma-25-345-01
