# DICOM Compliance Violation Samples

DICOM files that violate specific provisions of the DICOM standard. These samples test how implementations handle non-conformant data.

## Purpose

Test parser behavior when encountering:

- Invalid Value Representations (VR)
- Values exceeding VR length limits
- Missing required elements
- Character encoding violations

## Categories

### Invalid VR (`invalid_vr/`)

Files with incorrect Value Representation assignments.

| File                     | Violation           | Expected VR         | Actual VR         |
| ------------------------ | ------------------- | ------------------- | ----------------- |
| `integer_as_string.dcm`  | Type mismatch       | IS (Integer String) | Binary int        |
| `string_as_sequence.dcm` | Structure mismatch  | LO (Long String)    | SQ (Sequence)     |
| `date_malformed.dcm`     | Format violation    | DA (Date)           | Invalid format    |
| `uid_invalid_chars.dcm`  | Character violation | UI (UID)            | Non-numeric chars |

### Oversized Values (`oversized_values/`)

Files with values exceeding VR length limits.

| File               | VR  | Max Length | Actual Length |
| ------------------ | --- | ---------: | ------------- |
| `ui_oversized.dcm` | UI  |         64 | 128           |
| `lo_oversized.dcm` | LO  |         64 | 256           |
| `sh_oversized.dcm` | SH  |         16 | 64            |
| `ae_oversized.dcm` | AE  |         16 | 128           |

### Missing Required (`missing_required/`)

Files missing mandatory DICOM elements.

| File                    | Missing Element              | IOD |
| ----------------------- | ---------------------------- | --- |
| `no_sop_class.dcm`      | SOPClassUID (0008,0016)      | All |
| `no_sop_instance.dcm`   | SOPInstanceUID (0008,0018)   | All |
| `no_patient_id.dcm`     | PatientID (0010,0020)        | All |
| `no_study_instance.dcm` | StudyInstanceUID (0020,000D) | All |

### Encoding Errors (`encoding_errors/`)

Files with character encoding violations.

| File                 | Violation                               |
| -------------------- | --------------------------------------- |
| `invalid_utf8.dcm`   | Invalid UTF-8 byte sequences            |
| `wrong_charset.dcm`  | Data doesn't match declared charset     |
| `mixed_encoding.dcm` | Different encodings within same element |
| `null_in_string.dcm` | Null bytes in string VRs                |

## Usage

```bash
# Test compliance samples
python -m dicom_fuzzer.cli.fuzz_viewer \
    --input samples/compliance_violations/ \
    --viewer "path/to/viewer.exe" \
    --recursive

# Validate with dcmtk
dcmchk samples/compliance_violations/invalid_vr/integer_as_string.dcm
```

## Standard References

- [DICOM Part 5 - Data Structures](https://dicom.nema.org/medical/dicom/current/output/html/part05.html)
- [DICOM Part 6 - Data Dictionary](https://dicom.nema.org/medical/dicom/current/output/html/part06.html)
- [Value Representation Table](https://dicom.nema.org/medical/dicom/current/output/html/part05.html#table_6.2-1)

## VR Length Limits Reference

| VR  | Max Length | Description        |
| --- | ---------- | ------------------ |
| AE  | 16         | Application Entity |
| AS  | 4          | Age String         |
| CS  | 16         | Code String        |
| DA  | 8          | Date               |
| DS  | 16         | Decimal String     |
| DT  | 26         | Date Time          |
| IS  | 12         | Integer String     |
| LO  | 64         | Long String        |
| LT  | 10240      | Long Text          |
| PN  | 64×5       | Person Name        |
| SH  | 16         | Short String       |
| ST  | 1024       | Short Text         |
| TM  | 14         | Time               |
| UI  | 64         | Unique Identifier  |
| UT  | 2³²-2      | Unlimited Text     |
