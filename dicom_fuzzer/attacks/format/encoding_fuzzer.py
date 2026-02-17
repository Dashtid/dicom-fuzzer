"""Encoding Fuzzer - Character Set and Text Encoding Mutations.

Category: generic

Attacks:
- Invalid SpecificCharacterSet values
- Character set vs actual data encoding mismatch
- Invalid UTF-8 sequences and overlong encodings
- ISO 2022 escape sequence injection
- BOM injection across text fields
- Null byte and control character injection
- Mixed encoding within single dataset
- UTF-16 surrogate pair injection
"""

from __future__ import annotations

import random

from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Invalid/problematic character set values
INVALID_CHARSETS = [
    "INVALID_CHARSET",
    "UTF-16",  # Not supported in DICOM
    "UTF-32",
    "ISO_IR 999",
    "\\ISO_IR 100",  # Backslash prefix
    "ISO_IR 100\\ISO_IR 100",  # Duplicate
    "",  # Empty with multi-byte data
    "\x00",  # Null
    "A" * 100,  # Overlong
]

# Tags commonly containing text
TEXT_TAGS = [
    Tag(0x0010, 0x0010),  # PatientName
    Tag(0x0010, 0x0020),  # PatientID
    Tag(0x0008, 0x1030),  # StudyDescription
    Tag(0x0008, 0x103E),  # SeriesDescription
    Tag(0x0008, 0x0080),  # InstitutionName
    Tag(0x0008, 0x0090),  # ReferringPhysicianName
    Tag(0x0020, 0x4000),  # ImageComments
    Tag(0x0032, 0x1060),  # RequestedProcedureDescription
]


class EncodingFuzzer(FormatFuzzerBase):
    """Fuzzes character encoding and text fields.

    Targets internationalization handling which is often a source
    of security vulnerabilities in medical software.
    """

    def __init__(self) -> None:
        """Initialize the encoding fuzzer."""
        super().__init__()
        self.mutation_strategies = [
            self._invalid_charset_value,
            self._charset_data_mismatch,
            self._invalid_utf8_sequences,
            self._escape_sequence_injection,
            self._bom_injection,
            self._null_byte_injection,
            self._control_character_injection,
            self._overlong_utf8,
            self._mixed_encoding_attack,
            self._surrogate_pair_attack,
        ]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "encoding"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply encoding-related mutations to the dataset.

        Args:
            dataset: The DICOM dataset to mutate

        Returns:
            Mutated dataset with encoding corruptions

        """
        num_strategies = random.randint(1, 3)
        selected = random.sample(self.mutation_strategies, num_strategies)

        for strategy in selected:
            try:
                dataset = strategy(dataset)
            except Exception as e:
                logger.debug("Encoding mutation failed: %s", e)

        return dataset

    def _invalid_charset_value(self, dataset: Dataset) -> Dataset:
        """Set invalid SpecificCharacterSet values.

        Tests how parsers handle unknown or malformed charset declarations.
        """
        attack = random.choice(
            [
                "unknown_charset",
                "malformed_charset",
                "empty_charset_with_unicode",
                "conflicting_charsets",
            ]
        )

        try:
            if attack == "unknown_charset":
                dataset.SpecificCharacterSet = random.choice(INVALID_CHARSETS)

            elif attack == "malformed_charset":
                # Charset with control characters
                dataset.SpecificCharacterSet = "ISO_IR\x00100"

            elif attack == "empty_charset_with_unicode":
                # No charset declared but has Unicode data
                dataset.SpecificCharacterSet = ""
                if Tag(0x0010, 0x0010) in dataset:
                    dataset.PatientName = "日本語患者"

            elif attack == "conflicting_charsets":
                # Multiple charsets that conflict
                dataset.SpecificCharacterSet = ["ISO_IR 100", "ISO_IR 192", "GB18030"]

        except Exception as e:
            logger.debug("Invalid charset attack failed: %s", e)

        return dataset

    def _charset_data_mismatch(self, dataset: Dataset) -> Dataset:
        """Create mismatch between declared charset and actual data.

        Declares one encoding but uses data from another, testing
        whether parsers validate consistency.
        """
        try:
            attack = random.choice(
                [
                    "latin1_declared_utf8_data",
                    "utf8_declared_latin1_data",
                    "ascii_declared_multibyte",
                ]
            )

            if attack == "latin1_declared_utf8_data":
                dataset.SpecificCharacterSet = "ISO_IR 100"  # Latin-1
                # But set UTF-8 encoded data
                dataset.PatientName = "Müller"  # UTF-8 umlaut
                dataset.InstitutionName = "北京医院"  # Chinese UTF-8

            elif attack == "utf8_declared_latin1_data":
                dataset.SpecificCharacterSet = "ISO_IR 192"  # UTF-8
                # Set Latin-1 bytes that are invalid UTF-8
                dataset.add_new(
                    Tag(0x0010, 0x0010),
                    "PN",
                    b"M\xfcller",  # ü in Latin-1, invalid UTF-8
                )

            elif attack == "ascii_declared_multibyte":
                dataset.SpecificCharacterSet = "ISO_IR 6"  # ASCII only
                dataset.PatientName = "Здравствуйте"  # Cyrillic

        except Exception as e:
            logger.debug("Charset mismatch attack failed: %s", e)

        return dataset

    def _invalid_utf8_sequences(self, dataset: Dataset) -> Dataset:
        """Inject invalid UTF-8 byte sequences.

        Invalid UTF-8 can cause:
        - Crashes in string processing
        - Buffer overflows in conversion routines
        - Security bypasses through encoding confusion
        """
        dataset.SpecificCharacterSet = "ISO_IR 192"  # UTF-8

        invalid_sequences = [
            b"\x80",  # Continuation byte without start
            b"\xc0\xaf",  # Overlong encoding of '/'
            b"\xe0\x80\xaf",  # Overlong encoding
            b"\xf0\x80\x80\xaf",  # Overlong encoding
            b"\xfe",  # Invalid start byte
            b"\xff",  # Invalid start byte
            b"\xc0\xc0",  # Two start bytes
            b"\xe0\x80",  # Truncated 3-byte sequence
            b"\xf0\x80\x80",  # Truncated 4-byte sequence
            b"\xed\xa0\x80",  # UTF-16 surrogate (invalid in UTF-8)
            b"\xed\xbf\xbf",  # UTF-16 surrogate
            b"\xf4\x90\x80\x80",  # Above U+10FFFF
        ]

        try:
            invalid_seq = random.choice(invalid_sequences)
            # Embed in otherwise valid text
            value = b"Patient" + invalid_seq + b"Name"
            dataset.add_new(Tag(0x0010, 0x0010), "PN", value)
        except Exception as e:
            logger.debug("Invalid UTF-8 injection failed: %s", e)

        return dataset

    def _escape_sequence_injection(self, dataset: Dataset) -> Dataset:
        """Inject ISO 2022 escape sequences.

        ISO 2022 uses escape sequences to switch character sets.
        Malformed sequences can confuse parsers or enable attacks.
        """
        dataset.SpecificCharacterSet = "ISO 2022 IR 87"  # Japanese

        escape_sequences = [
            b"\x1b$B",  # Switch to JIS X 0208
            b"\x1b(B",  # Switch back to ASCII
            b"\x1b$@",  # Old JIS
            b"\x1b$(D",  # JIS X 0212
            b"\x1b\x1b\x1b",  # Multiple escapes
            b"\x1b$",  # Truncated escape
            b"\x1b(X",  # Invalid designation
            b"\x1b$B\x1b$B",  # Redundant switching
        ]

        try:
            escape = random.choice(escape_sequences)
            value = b"Test" + escape + b"Value" + b"\x1b(B"
            dataset.add_new(Tag(0x0010, 0x0010), "PN", value)
        except Exception as e:
            logger.debug("Escape sequence injection failed: %s", e)

        return dataset

    def _bom_injection(self, dataset: Dataset) -> Dataset:
        """Inject Byte Order Marks (BOMs) into text fields.

        BOMs are not expected in DICOM text fields but may be
        present in data from external sources.
        """
        boms = [
            b"\xef\xbb\xbf",  # UTF-8 BOM
            b"\xff\xfe",  # UTF-16 LE BOM
            b"\xfe\xff",  # UTF-16 BE BOM
            b"\xff\xfe\x00\x00",  # UTF-32 LE BOM
            b"\x00\x00\xfe\xff",  # UTF-32 BE BOM
        ]

        try:
            bom = random.choice(boms)
            attack = random.choice(
                [
                    "bom_at_start",
                    "bom_in_middle",
                    "multiple_boms",
                ]
            )

            if attack == "bom_at_start":
                value = bom + b"PatientName"
            elif attack == "bom_in_middle":
                value = b"Patient" + bom + b"Name"
            else:  # multiple_boms
                value = bom + b"Patient" + bom + b"Name" + bom

            dataset.add_new(Tag(0x0010, 0x0010), "PN", value)
        except Exception as e:
            logger.debug("BOM injection failed: %s", e)

        return dataset

    def _null_byte_injection(self, dataset: Dataset) -> Dataset:
        """Inject null bytes into text fields.

        Null bytes can:
        - Truncate strings in C-based parsers
        - Cause security bypasses
        - Trigger undefined behavior
        """
        try:
            attack = random.choice(
                [
                    "null_in_middle",
                    "null_at_end",
                    "multiple_nulls",
                    "null_padding",
                ]
            )

            if attack == "null_in_middle":
                value = "Patient\x00Name"
            elif attack == "null_at_end":
                value = "PatientName\x00"
            elif attack == "multiple_nulls":
                value = "Pat\x00ient\x00Na\x00me"
            else:  # null_padding
                value = "PatientName" + "\x00" * 100

            # Apply to multiple text fields
            for tag in random.sample(TEXT_TAGS, min(3, len(TEXT_TAGS))):
                try:
                    dataset.add_new(tag, "LO", value)
                except Exception as e:
                    logger.debug("Null byte injection rejected for tag %s: %s", tag, e)

        except Exception as e:
            logger.debug("Null byte injection failed: %s", e)

        return dataset

    def _control_character_injection(self, dataset: Dataset) -> Dataset:
        """Inject ASCII control characters into text fields.

        Control characters (0x00-0x1F) can cause:
        - Display issues
        - Log injection
        - Command injection in some contexts
        """
        control_chars = [
            "\x01",  # SOH
            "\x02",  # STX
            "\x03",  # ETX
            "\x04",  # EOT
            "\x07",  # BEL (beep)
            "\x08",  # BS (backspace)
            "\x09",  # TAB
            "\x0a",  # LF (newline)
            "\x0b",  # VT
            "\x0c",  # FF (form feed)
            "\x0d",  # CR (carriage return)
            "\x1b",  # ESC
            "\x7f",  # DEL
        ]

        try:
            attack = random.choice(
                [
                    "single_control",
                    "multiple_controls",
                    "control_sequence",
                ]
            )

            if attack == "single_control":
                char = random.choice(control_chars)
                value = f"Patient{char}Name"

            elif attack == "multiple_controls":
                chars = random.sample(control_chars, 5)
                value = "Patient" + "".join(chars) + "Name"

            else:  # control_sequence
                # ANSI escape sequence (terminal control)
                value = "Patient\x1b[31mRED\x1b[0mName"

            dataset.PatientName = value

        except Exception as e:
            logger.debug("Control character injection failed: %s", e)

        return dataset

    def _overlong_utf8(self, dataset: Dataset) -> Dataset:
        """Inject overlong UTF-8 encodings.

        Overlong encodings represent characters with more bytes than
        necessary. They're invalid UTF-8 and have been used for
        security bypasses (e.g., CVE-2000-0884).
        """
        dataset.SpecificCharacterSet = "ISO_IR 192"

        # Overlong encodings of common characters
        overlong_encodings = [
            (b"\xc0\x80", "NUL via 2-byte"),  # NUL as 2-byte
            (b"\xe0\x80\x80", "NUL via 3-byte"),  # NUL as 3-byte
            (b"\xf0\x80\x80\x80", "NUL via 4-byte"),  # NUL as 4-byte
            (b"\xc0\xaf", "/ via 2-byte"),  # '/' as 2-byte
            (b"\xe0\x80\xaf", "/ via 3-byte"),  # '/' as 3-byte
            (b"\xc1\x9c", "\\ via 2-byte"),  # '\\' as 2-byte
            (b"\xe0\x81\x9c", "\\ via 3-byte"),  # '\\' as 3-byte
            (b"\xc0\xae", ". via 2-byte"),  # '.' as 2-byte
        ]

        try:
            encoding, desc = random.choice(overlong_encodings)
            value = b"Patient" + encoding + b"Name"
            dataset.add_new(Tag(0x0010, 0x0010), "PN", value)
            logger.debug("Injected overlong UTF-8: %s", desc)
        except Exception as e:
            logger.debug("Overlong UTF-8 injection failed: %s", e)

        return dataset

    def _mixed_encoding_attack(self, dataset: Dataset) -> Dataset:
        """Mix multiple character encodings in the same dataset.

        Different fields using different encodings without proper
        charset declarations can cause confusion.
        """
        try:
            # Declare one charset but use mixed data
            dataset.SpecificCharacterSet = "ISO_IR 192"  # UTF-8

            # UTF-8 data
            dataset.PatientName = "日本太郎"

            # Latin-1 data (bytes that look like Latin-1)
            dataset.add_new(Tag(0x0008, 0x0080), "LO", b"H\xf4pital Fran\xe7ais")

            # ASCII with high-bit set
            dataset.add_new(Tag(0x0008, 0x1030), "LO", b"Study\x80\x81\x82Description")

            # GB18030 data
            dataset.add_new(Tag(0x0032, 0x1060), "LO", "中文描述".encode("gb18030"))

        except Exception as e:
            logger.debug("Mixed encoding attack failed: %s", e)

        return dataset

    def _surrogate_pair_attack(self, dataset: Dataset) -> Dataset:
        """Inject UTF-16 surrogate pairs into UTF-8 context.

        UTF-16 surrogates (U+D800-U+DFFF) are invalid in UTF-8 and
        can cause issues in parsers that don't validate properly.
        """
        dataset.SpecificCharacterSet = "ISO_IR 192"

        # UTF-8 encoding of surrogate code points (invalid)
        surrogates = [
            b"\xed\xa0\x80",  # U+D800 (high surrogate start)
            b"\xed\xaf\xbf",  # U+DBFF (high surrogate end)
            b"\xed\xb0\x80",  # U+DC00 (low surrogate start)
            b"\xed\xbf\xbf",  # U+DFFF (low surrogate end)
        ]

        try:
            attack = random.choice(
                [
                    "lone_high_surrogate",
                    "lone_low_surrogate",
                    "reversed_pair",
                    "double_high",
                ]
            )

            if attack == "lone_high_surrogate":
                value = b"Patient" + surrogates[0] + b"Name"
            elif attack == "lone_low_surrogate":
                value = b"Patient" + surrogates[2] + b"Name"
            elif attack == "reversed_pair":
                value = b"Patient" + surrogates[2] + surrogates[0] + b"Name"
            else:  # double_high
                value = b"Patient" + surrogates[0] + surrogates[1] + b"Name"

            dataset.add_new(Tag(0x0010, 0x0010), "PN", value)
        except Exception as e:
            logger.debug("Surrogate pair attack failed: %s", e)

        return dataset
