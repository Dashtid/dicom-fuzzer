# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.8.x   | Yes       |
| < 1.8   | No        |

## Reporting a Vulnerability

**Do not** create public GitHub issues for security vulnerabilities.

Report via [GitHub Private Vulnerability Reporting](https://github.com/Dashtid/dicom-fuzzer/security/advisories/new).

Include: description, reproduction steps, affected versions, impact assessment.

## Authorized Use

This tool is for **authorized security testing only**.

- Only test systems you own or have written authorization to test
- Comply with all applicable laws and regulations
- Report discovered vulnerabilities responsibly
- Never use against production medical systems or real patient data

## DICOM and Patient Data

DICOM files may contain Protected Health Information (PHI).

- Use only anonymized or synthetic DICOM seed files
- Run tests on isolated networks, never production infrastructure
- Securely delete all generated artifacts after testing

## Contact

- **Security issues**: [GitHub Private Vulnerability Reporting](https://github.com/Dashtid/dicom-fuzzer/security/advisories/new)
- **General issues**: [GitHub Issues](https://github.com/Dashtid/dicom-fuzzer/issues)
