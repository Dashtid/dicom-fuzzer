# Security Policy

## Supported Versions

| Version | Supported     |
| ------- | ------------- |
| 1.7.x   | Yes (Current) |
| 1.6.x   | Yes           |
| < 1.6   | No            |

## Reporting a Vulnerability

**DO NOT** create public GitHub issues for security vulnerabilities.

**DO** use [GitHub's private vulnerability reporting](https://github.com/Dashtid/dicom-fuzzer/security/advisories/new).

Include: description, reproduction steps, affected versions, impact, PoC if available.

| Severity | Response | Fix Timeline |
| -------- | -------- | ------------ |
| CRITICAL | 24 hours | 7 days       |
| HIGH     | 48 hours | 14 days      |
| MEDIUM   | 7 days   | 30 days      |
| LOW      | 14 days  | 60 days      |

## Authorized Use

DICOM Fuzzer is for **authorized security testing only**.

1. Only test systems you own or have explicit permission to test
2. Comply with applicable laws (CFAA, GDPR, HIPAA)
3. Report discovered vulnerabilities responsibly
4. Use for defensive security, not malicious purposes

## Protected Health Information (PHI)

DICOM files often contain PHI. Follow these requirements:

1. **Never use production data** - Use anonymized or synthetic DICOM files
2. **Secure storage** - Store fuzzed files in access-controlled locations
3. **Proper disposal** - Securely delete fuzzed files after testing
4. **Isolated networks** - Use isolated test networks, not production medical networks

## Malicious Sample Library

The fuzzer generates intentionally malicious DICOM samples. See [CVE Reference](docs/CVE_REFERENCE.md) for details.

| Category               | Risk   | Description                          |
| ---------------------- | ------ | ------------------------------------ |
| preamble_attacks/      | HIGH   | PE/ELF polyglots (CVE-2019-11687)    |
| dicom_fuzzer/cve/      | HIGH   | Known CVE reproductions              |
| parser_stress/         | MEDIUM | DoS via deep nesting, truncation     |
| compliance_violations/ | LOW    | Malformed samples for parser testing |

### CVE Samples

| CVE            | Product    | Type                   | CVSS |
| -------------- | ---------- | ---------------------- | ---- |
| CVE-2025-5943  | MicroDicom | OOB write              | 8.8  |
| CVE-2025-53618 | GDCM       | JPEG codec OOB read    | 7.5  |
| CVE-2025-53619 | GDCM       | JPEG info disclosure   | 7.5  |
| CVE-2025-11266 | GDCM       | PixelData OOB write    | 6.6  |
| CVE-2025-1001  | RadiAnt    | TLS cert bypass (MitM) | 5.7  |
| CVE-2024-33606 | MicroDicom | URL scheme auth bypass | 8.8  |
| CVE-2024-28877 | MicroDicom | Stack buffer overflow  | 8.7  |
| CVE-2024-22100 | MicroDicom | Heap buffer overflow   | 7.8  |
| CVE-2022-2121  | DCMTK      | Null pointer deref     | 6.5  |
| CVE-2022-2120  | DCMTK      | Path traversal (SCU)   | 7.5  |
| CVE-2022-2119  | DCMTK      | Path traversal (SCP)   | 7.5  |
| CVE-2019-11687 | DICOM Std  | Preamble executable    | N/A  |

### Safety Guidelines

1. **Isolate testing** - Use VMs, containers, or air-gapped systems
2. **Monitor resources** - Stress tests can cause resource exhaustion
3. **Never execute polyglots** - PE/ELF polyglots are valid executables
4. **Clean up after testing** - Remove generated samples when done

### Detection Tools

```bash
# Scan files for threats
dicom-fuzzer samples --scan ./files --recursive --json

# Sanitize suspicious files
dicom-fuzzer samples --sanitize suspicious.dcm
```

## Security Advisories

Published at [GitHub Security Advisories](https://github.com/Dashtid/DICOM-Fuzzer/security/advisories).

## Contact

- **Security issues**: [GitHub Private Vulnerability Reporting](https://github.com/Dashtid/dicom-fuzzer/security/advisories/new)
- **General issues**: [GitHub Issues](https://github.com/Dashtid/DICOM-Fuzzer/issues)
