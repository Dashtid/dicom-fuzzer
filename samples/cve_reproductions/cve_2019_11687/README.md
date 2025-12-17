# CVE-2019-11687 - DICOM Standard

## Overview

| Field    | Value                             |
| -------- | --------------------------------- |
| CVE ID   | CVE-2019-11687                    |
| Product  | DICOM Standard                    |
| Type     | Design flaw - preamble executable |
| CVSS     | N/A                               |
| Year     | 2019                              |
| Affected | All DICOM implementations         |
| Fixed    | Mitigation: preamble validation   |

## Description

DICOM preamble can contain executable headers

## Files

- `trigger.dcm` - DICOM file that triggers the vulnerability
- `README.md` - This file

## Testing

```bash
# Test with dicom-fuzzer
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/cve_2019_11687/ \
    --viewer "path/to/vulnerable/viewer"
```

## Mitigation

Update to version Mitigation: preamble validation or later.

## References

- https://nvd.nist.gov/vuln/detail/CVE-2019-11687
- https://github.com/d00rt/pedicom
