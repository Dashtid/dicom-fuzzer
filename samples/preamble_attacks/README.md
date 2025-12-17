# Preamble Attack Samples (CVE-2019-11687)

## Overview

The DICOM standard allows 128 arbitrary bytes at the beginning of a file (the "preamble") before the `DICM` magic marker. This design decision, intended for backward compatibility, creates a critical security vulnerability: the preamble can contain executable headers, creating **polyglot files** that are simultaneously valid DICOM images AND executable programs.

## The Vulnerability

### DICOM File Structure

```
Offset    Content
------    -------
0-127     Preamble (128 bytes - ARBITRARY CONTENT ALLOWED)
128-131   "DICM" magic marker
132+      DICOM metadata and pixel data
```

### Exploitation

Since a PE (Windows) or ELF (Linux) header can fit within 128 bytes, attackers can create files that:

1. Open normally in DICOM viewers (showing medical images)
2. Execute as programs when run directly (delivering malware)

```
┌─────────────────────────────────────────┐
│  Bytes 0-127: PE/ELF Header             │  ← Executable
├─────────────────────────────────────────┤
│  Bytes 128-131: "DICM"                  │  ← DICOM marker
├─────────────────────────────────────────┤
│  DICOM Metadata & Pixel Data            │  ← Medical image
└─────────────────────────────────────────┘
```

## Attack Scenarios

### 1. Malware Distribution

- Attacker embeds malware in DICOM images
- Images distributed via PACS, email, or removable media
- Victim opens `.dcm` file - sees normal image
- Attacker renames to `.exe` - executes malware

### 2. HIPAA-Protected Malware

- Malware hidden in PHI (Protected Health Information)
- Standard incident response (delete malware) would destroy patient data
- Creates regulatory and clinical dilemma

### 3. Persistence

- Malware infects existing DICOM images on disk
- Images still function normally in viewers
- Malware survives typical file-based detection

## Samples in This Directory

| File                   | Platform | Payload    | Description                     |
| ---------------------- | -------- | ---------- | ------------------------------- |
| `pe_dicom_benign.dcm`  | Windows  | MessageBox | Shows dialog when executed      |
| `elf_dicom_benign.dcm` | Linux    | exit(0)    | Exits cleanly when executed     |
| `generator.py`         | N/A      | N/A        | Tool to create custom polyglots |
| `detection.yara`       | N/A      | N/A        | YARA rules for detection        |

## Testing the Samples

### Windows (PE/DICOM)

```powershell
# View as DICOM (should display image)
& "C:\Path\To\DicomViewer.exe" pe_dicom_benign.dcm

# Execute as PE (should show MessageBox)
Copy-Item pe_dicom_benign.dcm pe_dicom_benign.exe
.\pe_dicom_benign.exe
```

### Linux (ELF/DICOM)

```bash
# View as DICOM
dcmdump elf_dicom_benign.dcm

# Execute as ELF
cp elf_dicom_benign.dcm elf_dicom_benign
chmod +x elf_dicom_benign
./elf_dicom_benign
echo $?  # Should be 0
```

## Detection

### Manual Inspection

```python
with open("suspicious.dcm", "rb") as f:
    preamble = f.read(128)
    magic = f.read(4)

    # Check for PE header
    if preamble[:2] == b"MZ":
        print("WARNING: PE header detected in preamble!")

    # Check for ELF header
    if preamble[:4] == b"\x7fELF":
        print("WARNING: ELF header detected in preamble!")

    # Verify DICOM magic
    if magic == b"DICM":
        print("Valid DICOM magic marker present")
```

### YARA Detection

```yara
rule DICOM_PE_Polyglot {
    meta:
        description = "Detects PE executable hidden in DICOM preamble"
        cve = "CVE-2019-11687"

    strings:
        $mz = { 4D 5A }           // MZ header
        $dicm = { 44 49 43 4D }   // DICM magic

    condition:
        $mz at 0 and $dicm at 128
}
```

## Mitigation

### 1. Preamble Validation (Recommended)

```python
SAFE_PREAMBLES = [
    b"\x00" * 128,           # Null bytes (most common)
    b"II\x2a\x00" + b"\x00" * 124,  # TIFF little-endian
    b"MM\x00\x2a" + b"\x00" * 124,  # TIFF big-endian
]

def validate_preamble(dicom_path):
    with open(dicom_path, "rb") as f:
        preamble = f.read(128)

    # Check for executable signatures
    if preamble[:2] == b"MZ":  # PE
        return False, "PE header detected"
    if preamble[:4] == b"\x7fELF":  # ELF
        return False, "ELF header detected"
    if preamble[:4] == b"\xfe\xed\xfa\xce":  # Mach-O
        return False, "Mach-O header detected"

    return True, "Preamble appears safe"
```

### 2. Preamble Sanitization

```python
def sanitize_preamble(input_path, output_path):
    """Replace preamble with null bytes, preserving DICOM data."""
    with open(input_path, "rb") as f:
        f.seek(128)  # Skip preamble
        dicom_data = f.read()

    with open(output_path, "wb") as f:
        f.write(b"\x00" * 128)  # Safe null preamble
        f.write(dicom_data)
```

### 3. Network-Level Controls

- Block DICOM files with executable preambles at network boundary
- Implement deep packet inspection for DICOM traffic
- Quarantine suspicious files for analysis

## References

- [CVE-2019-11687](https://nvd.nist.gov/vuln/detail/CVE-2019-11687)
- [PE/DICOM: Hiding Malware in Medical Images (Cylera Labs)](https://researchcylera.wpcomstaging.com/2019/04/16/pe-dicom-medical-malware/)
- [d00rt/pedicom GitHub](https://github.com/d00rt/pedicom)
- [CISA ICS-ALERT-19-162-01](https://www.cisa.gov/news-events/ics-alerts/ics-alert-19-162-01)
- [DICOM FAQ: 128-byte Preamble](https://www.dicomstandard.org/docs/librariesprovider2/dicomdocuments/wp-cotent/uploads/2019/05/faq-dicom-128-byte-preamble-posted1-1.pdf)
- [ELFDICOM (Praetorian)](https://www.praetorian.com/blog/elfdicom-poc-malware-polyglot-exploiting-linux-based-medical-devices/)

## Credits

Original research by Markel Picado Ortiz (d00rt) at Cylera Labs.
