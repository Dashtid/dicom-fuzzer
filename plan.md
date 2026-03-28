# Implementation Plan: Centralize attack payloads in dicom_dictionaries

## Summary

Audit all format fuzzers for inline attack payload lists that duplicate entries
already centralized in `dicom_dictionaries.py`. The goal is: one source of truth
for injection vectors so an FDA auditor can enumerate all attack strings in one
module, and so payloads don't drift between files.

## Findings (post-audit)

Most fuzzers already import from `dicom_dictionaries`:

- `metadata_fuzzer`, `private_tag_fuzzer`, `header_fuzzer` — all import
  `INJECTION_PAYLOADS`, `BUFFER_OVERFLOW_STRINGS`, etc. No local duplicates.
- `conformance_fuzzer` — imports `SOP_CLASS_BY_MODALITY`, `TRANSFER_SYNTAX_BY_NAME`.
  The `mismatches` list at line 214 uses dict lookups from the imported constants — correct.
- `encoding_fuzzer` — imports `INVALID_CHARSETS` correctly.

Remaining duplicate: `encapsulated_pdf_fuzzer.py` had a module-level
`_INJECTION_PAYLOADS` list (9 entries) that was a subset of `INJECTION_PAYLOADS`
in `dicom_dictionaries.py`. One entry (`"\n" * 500` newline flood) was missing
from the central list.

Inline `"A" * N` values in modality fuzzers (nm, pet, rtss, rt_dose, seg) are
domain-specific enumeration-overflow tests. They're contextually chosen sizes (e.g.
5000 chars for a CS/LO tag) and are NOT generic buffer overflow payloads. They
belong local to their fuzzer.

## Changes Made

### `dicom_dictionaries.py`

- Added `"\n" * 500` to `INJECTION_PAYLOADS` (newline flood; covers log injection,
  header splitting, metadata field overflow)

### `encapsulated_pdf_fuzzer.py`

- Imported `INJECTION_PAYLOADS` from `.dicom_dictionaries`
- Removed module-level `_INJECTION_PAYLOADS` list (was duplicating central list)
- Updated 2 call sites: `random.choice(_INJECTION_PAYLOADS)` →
  `random.choice(INJECTION_PAYLOADS)`

## Verification

- `pytest tests/test_attacks/format/test_encapsulated_pdf_fuzzer.py -x -q`
- `pytest tests/test_attacks/format/ -x -q`
