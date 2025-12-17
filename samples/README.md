# Malicious DICOM Sample Library

A comprehensive collection of security-focused DICOM test samples for vulnerability research, penetration testing, and defensive tool development.

> **WARNING**: These samples are designed to trigger vulnerabilities in DICOM parsers and viewers. Handle with care and use only in isolated test environments.

## Purpose

This library serves multiple purposes:

1. **Security Research** - Test DICOM implementations for known vulnerabilities
2. **Penetration Testing** - Validate medical imaging infrastructure security
3. **Defensive Development** - Build and test detection/prevention tools
4. **Education** - Learn about DICOM security risks and attack vectors

## Directory Structure

```
samples/
├── preamble_attacks/        # PE/DICOM and ELF/DICOM polyglots (CVE-2019-11687)
├── cve_reproductions/       # Samples that trigger specific CVEs
├── parser_stress/           # Edge cases that crash or hang parsers
├── compliance_violations/   # DICOM standard violations
└── detection/               # YARA rules, scanners, and sanitization tools
```

## Sample Categories

### Preamble Attacks (`preamble_attacks/`)

Exploits the DICOM standard's allowance of 128 arbitrary bytes before the "DICM" magic marker. These bytes can contain executable headers, creating polyglot files that are both valid DICOM images AND executable programs.

**CVE**: CVE-2019-11687
**Risk**: Malware hiding in medical images, HIPAA-protected malware
**Platforms**: Windows (PE), Linux (ELF), macOS (Mach-O)

### CVE Reproductions (`cve_reproductions/`)

Samples designed to trigger specific, documented vulnerabilities:

| CVE            | Product        | Type                 | CVSS | Year |
| -------------- | -------------- | -------------------- | ---- | ---- |
| CVE-2019-11687 | DICOM Standard | Preamble executable  | N/A  | 2019 |
| CVE-2022-2119  | DCMTK          | Path traversal (SCP) | 7.5  | 2022 |
| CVE-2022-2120  | DCMTK          | Path traversal (SCU) | 7.5  | 2022 |
| CVE-2022-2121  | DCMTK          | Null pointer deref   | 6.5  | 2022 |
| CVE-2025-5943  | MicroDicom     | Out-of-bounds write  | 8.8  | 2025 |
| CVE-2025-11266 | GDCM           | PixelData OOB write  | 6.6  | 2025 |
| CVE-2025-53618 | GDCM           | JPEG codec OOB read  | 7.5  | 2025 |

### Parser Stress Tests (`parser_stress/`)

Edge cases designed to test parser robustness:

- **Deep sequence nesting** - Recursive SQ elements
- **Giant value lengths** - 4GB VL fields
- **Truncated pixel data** - Incomplete transfers
- **Undefined length abuse** - Malformed delimiters
- **Invalid transfer syntax** - Encoding mismatches
- **Zero-length elements** - Empty required fields

### Compliance Violations (`compliance_violations/`)

Files that violate the DICOM standard in specific ways:

- **Invalid VR** - Wrong Value Representation types
- **Oversized values** - Exceeding VR length limits
- **Missing required** - Absent mandatory tags
- **Encoding errors** - Character set violations

## Usage

### Testing a DICOM Viewer

```bash
# Test with preamble polyglots
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/preamble_attacks/ \
    --viewer "C:/Path/To/Viewer.exe"

# Test with CVE samples
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/cve_reproductions/ \
    --viewer "C:/Path/To/Viewer.exe"
```

### Scanning for Malicious Samples

```bash
# Scan a directory for polyglot files
python samples/detection/scanner.py /path/to/dicom/files

# Sanitize infected files
python samples/detection/sanitizer.py infected.dcm --output clean.dcm
```

### Using YARA Rules

```bash
yara samples/detection/yara_rules/dicom_polyglot.yar /path/to/scan
```

## Detection Guidance

### Indicators of Compromise (IOCs)

**PE/DICOM Polyglots:**

- Bytes 0-1: `MZ` (0x4D5A) - DOS header magic
- Byte 60-63: Points to PE header location
- Bytes 128-131: `DICM` - DICOM magic

**ELF/DICOM Polyglots:**

- Bytes 0-3: `\x7fELF` - ELF magic
- Bytes 128-131: `DICM` - DICOM magic

### Defensive Measures

1. **Preamble validation** - Check first 128 bytes for executable signatures
2. **Whitelist approach** - Only allow known-good preamble patterns (null bytes, TIFF)
3. **Sanitization** - Zero out preamble on import
4. **Network segmentation** - Isolate PACS from general network
5. **File type verification** - Don't rely solely on extension

## Generating New Samples

```python
from samples.preamble_attacks.generator import PreambleAttackGenerator

# Generate a PE/DICOM polyglot
generator = PreambleAttackGenerator()
generator.create_pe_dicom(
    dicom_template="path/to/template.dcm",
    output_path="output/pe_dicom.dcm",
    payload_type="messagebox"  # benign payload
)

# Generate an ELF/DICOM polyglot
generator.create_elf_dicom(
    dicom_template="path/to/template.dcm",
    output_path="output/elf_dicom.dcm",
    payload_type="exit"  # benign payload
)
```

## References

- [CVE-2019-11687 - DICOM Preamble Vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2019-11687)
- [PE/DICOM Research - Cylera Labs](https://researchcylera.wpcomstaging.com/2019/04/16/pe-dicom-medical-malware/)
- [ELFDICOM - Praetorian](https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/)
- [CISA DICOM Security Alert](https://www.cisa.gov/news-events/ics-alerts/ics-alert-19-162-01)
- [DICOM Security FAQ](https://www.dicomstandard.org/docs/librariesprovider2/dicomdocuments/wp-cotent/uploads/2019/05/faq-dicom-128-byte-preamble-posted1-1.pdf)

## License

These samples are provided for security research and educational purposes only. See [DISCLAIMER.md](DISCLAIMER.md) for terms of use.
