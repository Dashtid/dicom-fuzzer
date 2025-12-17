# Legal Disclaimer and Ethical Use Policy

## Intended Use

The malicious DICOM samples in this repository are provided **exclusively** for:

1. **Authorized security testing** of systems you own or have explicit permission to test
2. **Defensive security research** to improve detection and prevention capabilities
3. **Educational purposes** to understand DICOM security risks
4. **Capture The Flag (CTF)** competitions and security training exercises
5. **Compliance testing** of medical imaging infrastructure

## Prohibited Uses

You **MUST NOT** use these samples to:

- Attack systems without explicit written authorization
- Compromise patient data or healthcare operations
- Create actual malware or weaponized exploits
- Distribute samples with malicious intent
- Violate any applicable laws or regulations (HIPAA, GDPR, etc.)
- Harm healthcare infrastructure or patient safety

## Payload Safety

All executable payloads in this repository are **benign by design**:

- **Windows payloads**: Display a MessageBox or launch Calculator
- **Linux payloads**: Execute `/bin/true` or `exit 0`
- **No actual malware** is included or referenced

The samples demonstrate vulnerability concepts without causing harm.

## Liability

THE SAMPLES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED. THE AUTHORS AND CONTRIBUTORS:

- Are not responsible for misuse of these samples
- Do not guarantee accuracy or completeness
- Are not liable for any damages arising from use
- Do not endorse illegal or unethical activities

## Responsible Disclosure

If you discover new vulnerabilities using these tools:

1. **Do not** publicly disclose without coordinating with the vendor
2. Follow responsible disclosure practices
3. Report to vendor security teams first
4. Allow reasonable time for patches before publication
5. Consider reporting to CISA for medical device vulnerabilities

## Healthcare-Specific Considerations

Medical imaging systems are critical infrastructure. When testing:

- **Never** test on production systems with real patient data
- Use isolated test environments
- Coordinate with IT security and clinical engineering
- Follow your organization's security policies
- Be aware of regulatory requirements (HIPAA, FDA, etc.)

## Acknowledgments

These samples are based on published security research:

- Markel Picado Ortiz (d00rt) - PE/DICOM polyglot research
- Cylera Labs - Original PE/DICOM vulnerability disclosure
- Praetorian - ELFDICOM research
- Claroty Team82 - DCMTK vulnerability research
- CISA ICS-CERT - Medical device security advisories

## Contact

For questions about appropriate use, please open an issue on the repository.

---

**By using these samples, you agree to these terms and accept full responsibility for your actions.**
