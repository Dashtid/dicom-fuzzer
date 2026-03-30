"""DICOM PHI tag definitions for dataset sanitization.

Tag lists derived from DICOM PS3.15 Annex E (Basic Application Level
Confidentiality Profile) and HIPAA Safe Harbor de-identification rules.
"""

from __future__ import annotations

# Tags to delete outright (addresses, phone numbers, physician names, etc.)
PHI_DELETE_KEYWORDS: frozenset[str] = frozenset(
    {
        # Patient metadata
        "OtherPatientIDs",
        "OtherPatientNames",
        "PatientAge",
        "PatientSize",
        "PatientWeight",
        "PatientAddress",
        "PatientTelephoneNumbers",
        "EthnicGroup",
        "AdditionalPatientHistory",
        "PatientComments",
        # Institutional identifiers
        "InstitutionName",
        "InstitutionAddress",
        "InstitutionalDepartmentName",
        "ReferringPhysicianName",
        "ReferringPhysicianAddress",
        "ReferringPhysicianTelephoneNumbers",
        "PhysiciansOfRecord",
        "PhysiciansOfRecordIdentificationSequence",
        "PerformingPhysicianName",
        "NameOfPhysiciansReadingStudy",
        "OperatorsName",
        "StationName",
        # Accession
        "AccessionNumber",
    }
)

# Date keywords to shift by a consistent random offset.
PHI_DATE_KEYWORDS: frozenset[str] = frozenset(
    {
        "StudyDate",
        "SeriesDate",
        "AcquisitionDate",
        "ContentDate",
    }
)

# UID keywords to regenerate (breaks linkage to original data).
PHI_UID_KEYWORDS: frozenset[str] = frozenset(
    {
        "SOPInstanceUID",
        "StudyInstanceUID",
        "SeriesInstanceUID",
    }
)
