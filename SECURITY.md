# Security Policy

## Supported Versions

| Version | Supported     |
| ------- | ------------- |
| 1.9.x   | Yes (Current) |
| 1.8.x   | Yes           |
| < 1.8   | No            |

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

## Generated Artifacts

The fuzzer generates intentionally malicious DICOM samples under `artifacts/fuzzed/`.
Attack patterns are embedded across four modules:

| Module                | Risk   | Description                                        |
| --------------------- | ------ | -------------------------------------------------- |
| `attacks/format/`     | HIGH   | Malformed headers, pixel data, preamble polyglots  |
| `attacks/multiframe/` | HIGH   | Frame count mismatches, encapsulated pixel attacks |
| `attacks/series/`     | HIGH   | Cross-series mutations targeting CVE patterns      |
| `attacks/network/`    | MEDIUM | TLS/DIMSE protocol fuzzing (experimental)          |

### Safety Guidelines

1. **Isolate testing** - Use VMs, containers, or air-gapped systems
2. **Monitor resources** - Stress tests can cause resource exhaustion
3. **Never execute polyglots** - PE/ELF polyglots are valid executables
4. **Clean up after testing** - Remove generated samples when done

## Security Advisories

Published at [GitHub Security Advisories](https://github.com/Dashtid/DICOM-Fuzzer/security/advisories).

## Contact

- **Security issues**: [GitHub Private Vulnerability Reporting](https://github.com/Dashtid/dicom-fuzzer/security/advisories/new)
- **General issues**: [GitHub Issues](https://github.com/Dashtid/DICOM-Fuzzer/issues)
