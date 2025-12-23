# Security Policy

## Table of Contents

- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Security Considerations for Users](#security-considerations-for-users)
- [Security Features](#security-features)
- [Known Security Limitations](#known-security-limitations)
- [Secure Development Practices](#secure-development-practices)
- [Security Advisories](#security-advisories)
- [Compliance and Regulations](#compliance-and-regulations)
- [Security Best Practices](#security-best-practices)
- [Contact and Support](#contact-and-support)
- [Acknowledgments](#acknowledgments)

## Supported Versions

Security updates are provided for the following versions:

| Version | Supported     | End of Support |
| ------- | ------------- | -------------- |
| 1.4.x   | Yes (Current) | TBD            |
| 1.3.x   | Yes           | 2026-06-30     |
| 1.2.x   | No            | 2025-12-31     |
| < 1.2   | No            | 2025-06-30     |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in DICOM Fuzzer, please report it responsibly.

### Reporting Process

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. **DO** use [GitHub's private vulnerability reporting](https://github.com/Dashtid/dicom-fuzzer/security/advisories/new)
3. Include the following information in your report:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected versions
   - Potential impact
   - Proof-of-concept (if available)
   - Suggested remediation (if known)

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days with assessment and timeline
- **Resolution Timeline**: Varies by severity (see below)
- **Public Disclosure**: Coordinated with reporter after fix is released

### Severity Levels and Response Times

| Severity     | Response Time | Fix Timeline | Examples                                     |
| ------------ | ------------- | ------------ | -------------------------------------------- |
| **CRITICAL** | 24 hours      | 7 days       | Remote code execution, authentication bypass |
| **HIGH**     | 48 hours      | 14 days      | Privilege escalation, SQL injection          |
| **MEDIUM**   | 7 days        | 30 days      | Information disclosure, DoS                  |
| **LOW**      | 14 days       | 60 days      | Minor security improvements                  |

## Security Considerations for Users

### General Security

DICOM Fuzzer is a **security testing tool** designed for authorized penetration testing and security research. Users must:

1. **Authorization Required**: Only test systems you own or have explicit permission to test
2. **Legal Compliance**: Comply with all applicable laws and regulations (CFAA, GDPR, HIPAA, etc.)
3. **Responsible Disclosure**: Report discovered vulnerabilities responsibly
4. **Ethical Use**: Use the tool for defensive security, not malicious purposes

### Protected Health Information (PHI)

DICOM files often contain Protected Health Information (PHI). When using DICOM Fuzzer:

1. **Never Use Production Data**: Do not fuzz production DICOM files containing real patient data
2. **Anonymize Test Data**: Use anonymized or synthetic DICOM files for testing
3. **Secure Storage**: Store fuzzed files in secure, access-controlled locations
4. **Proper Disposal**: Securely delete fuzzed files after testing
5. **Logging**: Be aware that PHI may appear in logs if production data is used (NOT recommended)

### Network Security

When performing network fuzzing:

1. **Isolated Networks**: Use isolated test networks, not production medical networks
2. **Firewall Rules**: Implement proper firewall rules to prevent unintended exposure
3. **Authentication**: Use strong authentication for DICOM network services
4. **Encryption**: Enable TLS for DICOM network communications where supported
5. **Monitoring**: Monitor network traffic for anomalies during fuzzing

### File Security

Fuzzed DICOM files may trigger vulnerabilities:

1. **Sandboxing**: Open fuzzed files in sandboxed environments
2. **Virtualization**: Use virtual machines or containers for testing
3. **Antivirus**: Be aware that antivirus may quarantine fuzzed files (false positives)
4. **Backups**: Maintain backups of test systems before fuzzing
5. **Integrity Checks**: Verify system integrity after fuzzing campaigns

## Security Features

DICOM Fuzzer includes built-in security features:

### Input Validation

- **File Size Limits**: Default 100MB limit (configurable)
- **Path Validation**: Prevents directory traversal attacks
- **DICOM Structure Validation**: Validates DICOM file structure

### Attack Detection

- **Null Byte Injection**: Detects null bytes in string fields
- **Buffer Overflow Detection**: Identifies oversized values (>10KB)
- **DoS Pattern Detection**:
  - Excessive element count (>10,000)
  - Deeply nested sequences (>10 levels)
  - Excessive private tags (>100)
  - Large private data (>1MB)

### Data Protection

- **PHI Redaction**: Automatic PHI redaction in logs (PatientName, PatientID, etc.)
- **Sensitive Data Masking**: Masks sensitive information in output
- **Security Event Logging**: Tracks security-relevant events

### Safe Defaults

- **Security-Conscious Configuration**: Secure defaults out of the box
- **Strict Validation Modes**: Optional strict validation for enhanced security
- **Isolated Testing Environments**: Encourages sandboxed testing

## Malicious Sample Library

The `tools/generators/` directory contains intentionally malicious DICOM files for security testing. **Handle with care.**

### Sample Categories

| Category                 | Risk Level | Description                                                            |
| ------------------------ | ---------- | ---------------------------------------------------------------------- |
| `preamble_attacks/`      | **HIGH**   | Executable polyglots (PE/DICOM, ELF/DICOM) that exploit CVE-2019-11687 |
| `cve_reproductions/`     | **HIGH**   | Samples reproducing known CVEs in DICOM software                       |
| `parser_stress/`         | **MEDIUM** | Deep nesting, truncation, and edge cases for DoS testing               |
| `compliance_violations/` | **LOW**    | Malformed but non-exploitative samples for parser testing              |

### CVE Samples Included

| CVE            | Product    | Vulnerability Type                   | CVSS |
| -------------- | ---------- | ------------------------------------ | ---- |
| CVE-2019-11687 | DICOM Std  | PE/DICOM polyglot execution          | N/A  |
| CVE-2022-2119  | DCMTK      | Path traversal (SCP)                 | 7.5  |
| CVE-2022-2120  | DCMTK      | Path traversal (SCU)                 | 7.5  |
| CVE-2022-2121  | DCMTK      | Null pointer dereference             | 6.5  |
| CVE-2024-22100 | MicroDicom | Heap-based buffer overflow           | 7.8  |
| CVE-2024-28877 | MicroDicom | Stack-based buffer overflow          | 8.7  |
| CVE-2024-33606 | MicroDicom | Improper auth in URL scheme handler  | 8.8  |
| CVE-2025-1001  | RadiAnt    | Certificate validation bypass (MitM) | 5.7  |
| CVE-2025-5943  | MicroDicom | Out-of-bounds write                  | 8.8  |
| CVE-2025-11266 | GDCM       | Out-of-bounds write (PixelData)      | 6.6  |
| CVE-2025-53618 | GDCM       | Out-of-bounds read (JPEG codec)      | 7.5  |
| CVE-2025-53619 | GDCM       | Information disclosure (JPEG codec)  | 7.5  |

### Safety Guidelines

When working with malicious samples:

1. **Isolate testing** - Use VMs, containers, or air-gapped systems
2. **Disable AV exclusions carefully** - Antivirus may quarantine polyglots (expected behavior)
3. **Monitor resources** - Parser stress tests can cause resource exhaustion
4. **Never execute polyglots** - PE/ELF polyglots are valid executables
5. **Clean up after testing** - Remove generated samples when done

### Detection and Sanitization Tools

```bash
# Generate all malicious samples
dicom-fuzzer samples --malicious -o ./test_samples

# Scan files for security threats
dicom-fuzzer samples --scan ./suspicious_files --recursive --json

# Sanitize a potentially malicious file
dicom-fuzzer samples --sanitize suspicious.dcm
```

### YARA Rules

The `tools/generators/detection/` directory includes YARA rules for detecting:

- PE/DICOM polyglots
- ELF/DICOM polyglots
- Suspicious preamble content
- Known malicious patterns

## Known Security Limitations

### Current Limitations

1. **Log Sanitization**: PHI redaction is best-effort; avoid using production data
2. **Memory Safety**: Python memory management may leak data in memory
3. **Crash Analysis**: Crash dumps may contain sensitive information
4. **Network Fuzzing**: May cause denial-of-service on target systems

### Mitigation Strategies

1. **Use Synthetic Data**: Generate synthetic DICOM files for testing
2. **Secure Logging**: Store logs in access-controlled directories
3. **Memory Wiping**: Consider memory wiping for highly sensitive environments
4. **Rate Limiting**: Implement rate limiting for network fuzzing

## Secure Development Practices

DICOM Fuzzer follows secure development practices:

### Code Quality

- **Linting**: Ruff linter with security rules enabled
- **Type Checking**: mypy for static type checking
- **Security Scanning**: Bandit for security vulnerability detection
- **Dependency Scanning**: Regular dependency vulnerability checks

### Testing

- **Security Tests**: Dedicated security test suite
- **Attack Vector Validation**: Tests for common attack patterns
- **PHI Redaction Tests**: Verifies PHI redaction functionality
- **Fuzzing Tests**: Fuzz-tests critical components

### Code Review

- **Pull Request Reviews**: All changes reviewed before merge
- **Security Review**: Security-focused review for sensitive components
- **Automated Checks**: CI/CD pipeline enforces code quality

## Security Advisories

Security advisories are published at:

- GitHub Security Advisories: https://github.com/Dashtid/DICOM-Fuzzer/security/advisories
- CHANGELOG.md: Security fixes documented in changelog

### Advisory Format

```markdown
## Security Advisory [YEAR-NUMBER]

**Severity**: CRITICAL/HIGH/MEDIUM/LOW
**CVE ID**: CVE-YEAR-XXXXX (if assigned)
**Affected Versions**: x.x.x - y.y.y
**Fixed Version**: z.z.z

### Description

[Description of vulnerability]

### Impact

[Impact assessment]

### Remediation

[Steps to remediate]

### Credit

[Reporter credit, if desired]
```

## Compliance and Regulations

### Healthcare IT Compliance

Users in healthcare must consider:

1. **HIPAA (USA)**: Ensure compliance with HIPAA Security Rule
   - Use synthetic or anonymized data
   - Implement access controls
   - Maintain audit logs

2. **GDPR (EU)**: Comply with data protection regulations
   - Minimize data collection
   - Implement data retention policies
   - Respect data subject rights

3. **FDA Guidance (Medical Devices)**: For medical device testing
   - Follow FDA cybersecurity guidance
   - Document security testing procedures
   - Report discovered vulnerabilities to manufacturers

4. **EU MDR (Medical Device Regulation)**: For EU market
   - Include security testing in risk management
   - Document cybersecurity controls
   - Maintain technical documentation

### Industry Standards

- **NIST Cybersecurity Framework**: Align testing with NIST CSF
- **IEC 62443 (Industrial Security)**: Apply industrial security principles
- **ISO 27001 (Information Security)**: Integrate with ISMS processes

## Security Best Practices

### For Security Researchers

1. **Responsible Disclosure**: Report vulnerabilities privately first
2. **Proof of Concept**: Provide detailed PoC without weaponization
3. **Vendor Coordination**: Allow vendors time to patch before public disclosure
4. **Documentation**: Document findings thoroughly and professionally

### For System Administrators

1. **Patch Management**: Apply security updates promptly
2. **Network Segmentation**: Isolate medical imaging networks
3. **Access Control**: Implement least privilege access
4. **Monitoring**: Deploy security monitoring and alerting
5. **Incident Response**: Maintain incident response procedures

### For Developers

1. **Secure Coding**: Follow secure coding guidelines
2. **Input Validation**: Validate all external inputs
3. **Dependency Management**: Keep dependencies updated
4. **Security Testing**: Include security tests in development
5. **Code Review**: Conduct security-focused code reviews

## Contact and Support

### Security Contact

- **Primary**: [GitHub Private Vulnerability Reporting](https://github.com/Dashtid/dicom-fuzzer/security/advisories/new)
- **Response Time**: Within 48 hours for initial response

### General Support

- **GitHub Issues**: https://github.com/Dashtid/DICOM-Fuzzer/issues (non-security issues)
- **Documentation**: https://github.com/Dashtid/DICOM-Fuzzer/tree/main/docs
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)

## Acknowledgments

We thank the security research community for responsible disclosure of vulnerabilities.

### Hall of Fame

Security researchers who have responsibly disclosed vulnerabilities will be acknowledged here (with permission):

- [Researcher Name] - [Vulnerability Type] - [Date]

---

**Last Updated**: December 17, 2025
**Next Review**: March 17, 2026

For questions about this security policy, use [GitHub Discussions](https://github.com/Dashtid/dicom-fuzzer/discussions).
