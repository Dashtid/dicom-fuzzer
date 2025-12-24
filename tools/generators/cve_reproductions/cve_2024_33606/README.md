# CVE-2024-33606 - MicroDicom DICOM Viewer

## Overview

| Field    | Value                                        |
| -------- | -------------------------------------------- |
| CVE ID   | CVE-2024-33606                               |
| Product  | MicroDicom DICOM Viewer                      |
| Type     | Improper authorization in URL scheme handler |
| CVSS     | 8.8                                          |
| Year     | 2024                                         |
| Affected | < 2024.2                                     |
| Fixed    | 2024.2                                       |

## Description

This is an 'improper authorization in handler for custom URL scheme' vulnerability. If exploited, it could allow an attacker to retrieve sensitive files (medical images) as well as plant new medical images or overwrite existing images via the `microdicom://` URL scheme.

## Attack Vector

The vulnerability is in the custom URL scheme handler, not directly in file parsing. The included DICOM sample contains metadata patterns that could be used in conjunction with URL scheme attacks.

## Files

- `trigger.dcm` - DICOM file with URL scheme payloads in metadata
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
dicom-fuzzer samples --scan samples/cve_reproductions/cve_2024_33606/

# Generate the sample
python -m samples.cve_reproductions.generator --cve CVE-2024-33606
```

## Mitigation

Update to version 2024.2 or later.

## References

- https://nvd.nist.gov/vuln/detail/CVE-2024-33606
- https://www.cisa.gov/news-events/ics-medical-advisories/icsma-24-163-01
