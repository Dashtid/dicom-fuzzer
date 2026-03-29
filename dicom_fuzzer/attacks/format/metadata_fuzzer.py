"""Metadata Fuzzer - Patient, Study, Series, and Institution Metadata Mutations.

Category: generic

Attacks:
- Required UID tag removal (SOPClassUID, StudyInstanceUID, etc.)
- VR length boundary violations (CS/SH/LO fields at maxlen + 1)
- DICOM delimiter byte injection into text fields
- Patient identifier injection (SQL, XSS, path traversal in PatientID/Name)
- Patient demographics boundary values (age, weight, size, sex)
- Study metadata corruption (dates, times, IDs, accession numbers)
- Series metadata injection (descriptions, body part, modality)
- Institution and personnel name injection
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from pydicom.dataset import Dataset
from pydicom.tag import Tag

from dicom_fuzzer.utils.anonymizer import anonymize_patient_info
from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase
from .dicom_dictionaries import (
    INJECTION_PAYLOADS,
)
from .dicom_dictionaries import (
    INVALID_DATES as _INVALID_DATES,
)
from .dicom_dictionaries import (
    INVALID_PN_VALUES as _PN_ATTACKS,
)
from .dicom_dictionaries import (
    INVALID_TIMES as _INVALID_TIMES,
)

logger = get_logger(__name__)


class MetadataFuzzer(FormatFuzzerBase):
    """Fuzzer for DICOM metadata across the entire metadata hierarchy.

    Targets patient, study, series, and institution metadata fields
    with injection payloads, boundary values, and format violations.
    """

    def __init__(self) -> None:
        """Initialize with fake patient data for realistic mutations."""
        super().__init__()
        self.fake_names = ["Smith^John", "Doe^Jane", "Johnson^Mike"]

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "metadata"

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply metadata mutations, always including at least one structural attack.

        Structural methods (required tag removal, VR length violations, delimiter
        injection) fire on every call. Content methods (string injection payloads)
        fire with 1-in-3 probability to maintain coverage breadth without dominating
        the mutation budget.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset

        """
        structural = [
            self._required_tag_removal,  # [STRUCTURAL] missing required UID halts routing
            self._vr_length_boundary_attack,  # [STRUCTURAL] VR maxlen+1 buffer boundary
            self._delimiter_byte_injection,  # [STRUCTURAL] DICOM delimiter bytes in text field
        ]
        content = [
            self._patient_identifier_attack,  # [CONTENT] SQL/XSS/path traversal in text fields
            self._patient_demographics_attack,  # [CONTENT] invalid codes / floats, parser reads fine
            self._study_metadata_attack,  # [CONTENT] date/string fields, no parse effect
            self._series_metadata_attack,  # [CONTENT] description strings, no parse effect
            self._institution_personnel_attack,  # [CONTENT] name/address fields, no parse effect
        ]

        selected = random.sample(structural, k=1)
        if random.random() < 0.33:
            selected.append(random.choice(content))
        self.last_variant = ",".join(a.__name__ for a in selected)

        for attack in selected:
            try:
                attack(dataset)
            except Exception as e:
                logger.debug("Mutation %s failed: %s", attack.__name__, e)

        return dataset

    def mutate_patient_info(self, dataset: Dataset) -> Dataset:
        """Replace patient identifiers with fake but believable values.

        Delegates to :func:`dicom_fuzzer.utils.anonymizer.anonymize_patient_info`.
        Kept on the class for backward compatibility with existing callers.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset (same object)

        """
        return anonymize_patient_info(dataset)

    # --- Structural Attacks ---

    def _required_tag_removal(self, dataset: Dataset) -> None:
        """Remove one required Type 1 DICOM identifier tag.

        SOPClassUID, SOPInstanceUID, StudyInstanceUID, and SeriesInstanceUID
        are required for routing and identification. Parsers that do not guard
        against missing UIDs may crash or misroute the file.
        """
        candidates = [
            "SOPClassUID",
            "SOPInstanceUID",
            "StudyInstanceUID",
            "SeriesInstanceUID",
        ]
        tag = random.choice(candidates)
        try:
            if hasattr(dataset, tag):
                delattr(dataset, tag)
        except Exception as e:
            logger.debug("Required tag removal failed for %s: %s", tag, e)

    def _vr_length_boundary_attack(self, dataset: Dataset) -> None:
        """Set a VR-typed field to one byte over its declared maximum length.

        CS (Code String) max = 16 chars. SH (Short String) max = 16 chars.
        LO (Long String) max = 64 chars. Setting values at maxlen + 1 exercises
        boundary checks and fixed-size buffer allocations in target parsers.
        """
        attacks = [
            # (attribute, value at maxlen + 1)
            ("Modality", "A" * 17),  # CS max=16
            ("PatientSex", "M" * 17),  # CS max=16
            ("StudyID", "S" * 17),  # SH max=16
            ("AccessionNumber", "A" * 17),  # SH max=16
            ("StationName", "S" * 17),  # SH max=16
            ("InstitutionName", "I" * 65),  # LO max=64
            ("PatientID", "P" * 65),  # LO max=64
            ("SeriesDescription", "D" * 65),  # LO max=64
        ]
        attr, value = random.choice(attacks)
        try:
            setattr(dataset, attr, value)
        except Exception as e:
            logger.debug("VR length boundary attack failed for %s: %s", attr, e)

    def _delimiter_byte_injection(self, dataset: Dataset) -> None:
        """Inject DICOM structural delimiter bytes into a text field.

        DICOM Item (FFFE,E000) and Sequence Delimiter (FFFE,E0DD) bytes embedded
        in a text value confuse parsers that scan for these patterns in the byte
        stream before validating the enclosing VR type.
        """
        delimiter_payloads = [
            b"\xfe\xff\x00\xe0",  # Item tag (FFFE,E000)
            b"\xfe\xff\xdd\xe0",  # Sequence Delimiter (FFFE,E0DD)
            b"\xfe\xff\x0d\xe0",  # Item Delimitation Item (FFFE,E00D)
            b"Text\xfe\xff\x00\xe0More",  # Item delimiter embedded in text
            b"\xfe\xff\x00\xe0" * 4,  # Repeated item delimiters
            b"\xfe\xff\xdd\xe0\x00\x00\x00\x00",  # Seq delim + zero length
        ]
        targets = [
            # LO VR only: pydicom keeps bytes as-is for LO, which preserves
            # the raw delimiter pattern. PN converts bytes to string on storage,
            # stripping the binary payload before it reaches a parser.
            (Tag(0x0008, 0x0080), "LO"),  # InstitutionName
            (Tag(0x0008, 0x1030), "LO"),  # StudyDescription
            (Tag(0x0008, 0x103E), "LO"),  # SeriesDescription
        ]
        payload = random.choice(delimiter_payloads)
        tag, vr = random.choice(targets)
        try:
            dataset.add_new(tag, vr, payload)
        except Exception as e:
            logger.debug("Delimiter byte injection failed: %s", e)

    # --- Content Attack Categories ---

    def _patient_identifier_attack(self, dataset: Dataset) -> None:
        """Attack patient identifier fields with malformed values.

        Targets PatientID, PatientName, and PatientBirthDate with
        injection payloads, boundary values, and format violations.
        """
        attacks = random.sample(
            ["patient_id", "patient_name", "birth_date"],
            k=random.randint(1, 3),
        )

        if "patient_id" in attacks:
            dataset.PatientID = random.choice(
                [
                    "",  # Empty ID
                    "A" * 65,  # Over 64-char LO limit
                    "ID WITH SPACES",
                    "ID\x00HIDDEN",  # Null byte
                    "PAT-" + "9" * 100,  # Extreme length
                    *INJECTION_PAYLOADS[:5],
                    "0" * 64,  # Max length numeric
                    "ID\tTAB\tSEPARATED",  # Tab characters
                    "PATIENT\\ID\\BACKSLASH",  # Backslashes
                ]
            )

        if "patient_name" in attacks:
            dataset.PatientName = self._random_pn_attack()

        if "birth_date" in attacks:
            dataset.PatientBirthDate = random.choice(_INVALID_DATES)

    def _patient_demographics_attack(self, dataset: Dataset) -> None:
        """Attack patient demographic fields not covered by other fuzzers.

        Targets PatientSex, PatientAge, PatientWeight, and PatientSize
        with invalid codes, boundary values, and type confusion.
        """
        attacks = random.sample(
            ["sex", "age", "weight", "size"],
            k=random.randint(1, 4),
        )

        if "sex" in attacks:
            dataset.PatientSex = random.choice(
                [
                    "",  # Empty
                    "m",  # Lowercase (should be M/F/O)
                    "MF",  # Multiple values
                    "X",  # Invalid code
                    "\x00",  # Null byte
                    "Male",  # Full word instead of code
                    "  M  ",  # Padded
                    "F" * 20,  # Overlong
                ]
            )

        if "age" in attacks:
            dataset.PatientAge = random.choice(
                [
                    "",  # Empty
                    "999X",  # Invalid unit (should be D/W/M/Y)
                    "12345Y",  # Too many digits (should be 3)
                    "12Y",  # Too few digits
                    "ABCY",  # Non-numeric
                    "-01Y",  # Negative
                    "000D",  # Zero age
                    "200Y",  # Impossibly old
                    "999Y",  # Max digits
                    "001",  # Missing unit
                    "Y",  # Missing digits
                    "0100M",  # 5 chars
                ]
            )

        if "weight" in attacks:
            dataset.PatientWeight = random.choice(
                [
                    0,  # Zero weight
                    -1,  # Negative
                    0.0001,  # Near zero
                    999999.99,  # Extremely heavy
                    float("inf"),  # Infinity
                    float("nan"),  # NaN (breaks == comparisons)
                    1e308,  # Near max float
                    1e-308,  # Near min float
                ]
            )

        if "size" in attacks:
            dataset.PatientSize = random.choice(
                [
                    0,  # Zero
                    -1.0,  # Negative
                    0.001,  # Near zero
                    100.0,  # 100 meters
                    float("inf"),  # Infinity
                    float("nan"),  # NaN (breaks == comparisons)
                    1e308,  # Near max float
                ]
            )

    def _study_metadata_attack(self, dataset: Dataset) -> None:
        """Attack study-level metadata fields.

        Targets StudyDate, StudyTime, StudyID, AccessionNumber,
        and ReferringPhysicianName.
        """
        attacks = random.sample(
            ["study_date", "study_time", "study_id", "accession", "referring"],
            k=random.randint(1, 4),
        )

        if "study_date" in attacks:
            dataset.StudyDate = random.choice(_INVALID_DATES)

        if "study_time" in attacks:
            dataset.StudyTime = random.choice(_INVALID_TIMES)

        if "study_id" in attacks:
            dataset.StudyID = random.choice(
                [
                    "",  # Empty
                    "S" * 17,  # Over 16-char SH limit
                    "STUDY\x00ID",  # Null byte
                    *INJECTION_PAYLOADS[:3],
                    "12345678901234567",  # 17 chars
                    "STUDY WITH SPACES AND MORE TEXT",  # Long with spaces
                ]
            )

        if "accession" in attacks:
            dataset.AccessionNumber = random.choice(
                [
                    "",  # Empty
                    "A" * 17,  # Over 16-char SH limit
                    "ACC\x00NUM",  # Null byte
                    *INJECTION_PAYLOADS[:3],
                    "0" * 16,  # Max length numeric
                    "ACC-2025-" + "9" * 50,  # Overlong realistic format
                ]
            )

        if "referring" in attacks:
            dataset.ReferringPhysicianName = self._random_pn_attack()

    def _series_metadata_attack(self, dataset: Dataset) -> None:
        """Attack series-level metadata fields.

        Targets SeriesDate, SeriesDescription, and BodyPartExamined.
        """
        attacks = random.sample(
            ["series_date", "description", "body_part"],
            k=random.randint(1, 3),
        )

        if "series_date" in attacks:
            dataset.SeriesDate = random.choice(_INVALID_DATES)

        if "description" in attacks:
            dataset.SeriesDescription = random.choice(
                [
                    "",  # Empty
                    "A" * 65,  # Over 64-char LO limit
                    "CT HEAD W/O CONTRAST\x00HIDDEN",  # Null byte in realistic desc
                    "CHEST\nXRAY\nPA\nLATERAL",  # Newlines
                    "DESCRIPTION" * 100,  # Very long
                    "\x1b[31mRED SERIES\x1b[0m",  # ANSI escape codes
                    *INJECTION_PAYLOADS[:3],  # SQL, path traversal, XSS
                ]
            )

        if "body_part" in attacks:
            dataset.BodyPartExamined = random.choice(
                [
                    "",  # Empty
                    "BODY" * 10,  # Overlong CS
                    "head",  # Lowercase (should be uppercase)
                    "NOT A BODY PART",  # Invalid code
                    "CHEST\x00",  # Null terminated
                    "A" * 17,  # Over 16-char CS limit
                    "HEAD;CHEST",  # Semicolon separator
                    "ABDOMEN\nCHEST",  # Newline
                ]
            )

    def _institution_personnel_attack(self, dataset: Dataset) -> None:
        """Attack institution and personnel metadata fields.

        Targets InstitutionName, InstitutionAddress, StationName,
        OperatorsName, and PerformingPhysicianName.
        """
        attacks = random.sample(
            ["institution", "address", "station", "operator", "physician"],
            k=random.randint(1, 4),
        )

        if "institution" in attacks:
            dataset.InstitutionName = random.choice(
                [
                    "",  # Empty
                    "A" * 65,  # Over 64-char LO limit
                    "HOSPITAL\x00HIDDEN",  # Null byte
                    "General Hospital\nSecond Line",  # Newline
                    "Medical Center" * 50,  # Very long
                    "\xe4\xb8\x8a\xe6\xb5\xb7\xe5\x8c\xbb\xe9\x99\xa2",  # Chinese hospital
                    *INJECTION_PAYLOADS[:2],  # SQL, path traversal
                ]
            )

        if "address" in attacks:
            dataset.InstitutionAddress = random.choice(
                [
                    "",  # Empty
                    "A" * 1025,  # Over 1024-char ST limit
                    "123 Main St\x00Hidden Address",  # Null byte
                    "456 Oak Ave\r\nInjected-Header: evil",  # HTTP header injection
                    "ADDRESS" * 200,  # Very long
                    *INJECTION_PAYLOADS[:2],  # SQL, path traversal
                ]
            )

        if "station" in attacks:
            dataset.StationName = random.choice(
                [
                    "",  # Empty
                    "S" * 17,  # Over 16-char SH limit
                    "STATION\x00",  # Null terminated
                    "CT_SCANNER_1'; --",  # SQL in station name
                    "WORKSTATION\nNEWLINE",  # Newline
                    "\x00" * 16,  # All nulls
                ]
            )

        if "operator" in attacks:
            dataset.OperatorsName = self._random_pn_attack()

        if "physician" in attacks:
            dataset.PerformingPhysicianName = self._random_pn_attack()

    # --- Helpers ---

    def _random_date(self) -> str:
        """Generate random but valid DICOM date (YYYYMMDD).

        Returns dates in the range 1950-2010 for realistic patient DOB.
        """
        start_date = datetime(1950, 1, 1)
        end_date = datetime(2010, 12, 31)
        random_date = start_date + timedelta(
            days=random.randint(0, (end_date - start_date).days)
        )
        return random_date.strftime("%Y%m%d")

    def _random_pn_attack(self) -> str:
        """Generate a malformed Person Name (PN) value.

        DICOM PN format uses carets to separate component groups
        and equals signs between value representations.
        """
        attack_type = random.choice(
            [
                "malformed",
                "injection",
                "boundary",
            ]
        )

        if attack_type == "malformed":
            return random.choice(_PN_ATTACKS)
        elif attack_type == "injection":
            payload = random.choice(INJECTION_PAYLOADS)
            prefix = random.choice(["Dr.", "Smith^", "Patient^", ""])
            return f"{prefix}{payload}"
        else:  # boundary
            return random.choice(
                [
                    "A" * 64 + "^" + "B" * 64,  # Max component lengths
                    "^" * 100,  # Many carets
                    "\x00" * 20,  # Null bytes
                    " " * 64,  # All spaces
                    "A^B^C^D^E" * 10,  # Repeated structure
                ]
            )
