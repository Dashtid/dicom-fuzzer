# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

---

## Scope policy (2026-04-13)

Format fuzzers are only worth adding when a matching seed exists in
`dicom-seeds/`. Current seed corpus modalities: CT, DX, MR, NM, PET,
RT-Dose, RT-Struct, SEG, encapsulated-PDF (9 modalities). Fuzzers for
SOP classes outside this set produce no crashes against the actual
target (Hermes.exe with these seeds) because `can_mutate()` returns
False for every campaign input.

Going forward:

1. Format work should focus on **CVE gap coverage within the 9 seed
   modalities**, not new modality fuzzers.
2. New modality fuzzers (US, MG, XA, MRS, PM, SC, PR, VL, SR,
   Waveform, etc.) require seed corpus expansion first.
3. Non-format work (network/DIMSE deepening, campaign tooling, crash
   triage automation, coverage-guided fuzzing) is the higher-leverage
   track.

---

## P0: Remove out-of-scope strategies (follow-up to PR #244)

After PR #244 merges, delete the 9 strategies whose SOP classes have
no matching seed in `dicom-seeds/`:

- WaveformFuzzer (strategy 34)
- StructuredReportFuzzer (35)
- UltrasoundFuzzer (36)
- MammographyFuzzer (37)
- XRayAngiographyFuzzer (38)
- SpectroscopyFuzzer (39)
- ParametricMapFuzzer (40)
- SecondaryCaptureFuzzer (41)
- PresentationStateFuzzer (42)

For each: delete fuzzer file, delete test file, remove from
`attacks/format/__init__.py` (import + **all**), remove from
`core/mutation/mutator.py` (import + registration list), update
`tests/test_core/engine/test_generator.py` (count and expected_format).
Target final count: 33 strategies (24 in-scope format + 10 multiframe -
1 for whatever ends up dropped). Update CVE_AUDIT.md if any of these
covered specific CVEs. Update memory: "Codebase Structure" total count.

---

## P1: CVE gap audit refocus on seed-corpus modalities

Re-read `docs/CVE_AUDIT.md` and filter the ~140 CVEs / 13 gap list to
only those affecting CT, MR, PET, NM, DX, RT-Dose, RT-Struct, SEG, or
encapsulated-PDF SOP classes. Identify which gaps are still uncovered
within this scope. Output: a short addendum to CVE_AUDIT.md listing
"in-scope gaps" with target fuzzer + attack.

---

## Format fuzzing -- P2: CVE gap coverage (larger scope)

---

## Series/Study fuzzing -- P2

### ~~Temporal (4D) series attacks~~ DONE

### ~~Registration geometry attacks~~ DONE

Multiple series with same FrameOfReferenceUID but conflicting
ImagePositionPatient. FoR UID orphaning.

---

## Network protocol fuzzing -- Prototype to Production

### ~~P0: PDU binary format (PS3.8 Section 7)~~ DONE

### ~~P0: State machine wiring~~ DONE

### ~~P0: DIMSE command generation~~ DONE

### ~~P1: Real TLS testing~~ DONE

### ~~P1: Query/Retrieve fuzzing~~ DONE

---

## Campaign & validation

### Build local high-quality DICOM seed corpus

Assemble a diverse, realistic seed corpus in the local-only
`dicom-seeds/` directory (fully gitignored). See project wiki
for quality bar per modality and sourcing process.

**Effort:** Ongoing.

### Full campaign run

Overnight run with 9 seeds + 30s timeout. Analyze crash-by-strategy.

### Second-pass structural audit

After campaign data: remove/redesign zero-crash strategies.

---

## Low priority / deferred

- Structural/content code comments
- CrashAnalyzer rename
- Test flakiness investigation
- Strategy effectiveness charts
- End-of-campaign auto-triage
- Authentication negotiation fuzzing

---

## Long-term vision

### Full DICOM SOP Class coverage

186 Storage SOP Classes. Current 42 strategies. Target ~44-48.

### Coverage-guided fuzzing

DynamoRIO/Frida instrumentation, coverage feedback, seed selection.

---

## Completed (reference only)

| Item                                                                               | PR(s)                          |
| ---------------------------------------------------------------------------------- | ------------------------------ |
| Audit mutations for crash potential (structural/content split)                     | #188, #198                     |
| Formalize variant terminology + replay --decompose                                 | #195, #184, #197               |
| Re-encode pixel data (PixelReencodingFuzzer)                                       | #204                           |
| Attack mode / scope filtering (--target-type)                                      | #205                           |
| Move mutate_patient_info to utils/anonymizer.py                                    | #201                           |
| Centralize attack payloads in dicom_dictionaries                                   | #194                           |
| Seed corpus diversification (SEG, RTSS, PDF)                                       | #206                           |
| Unify reporting CSS/HTML systems                                                   | #200                           |
| Make reports minimalistic and professional                                         | #200 (CSS cleaned up)          |
| Consolidate crash data types (CrashRecord)                                         | #203                           |
| Add can_mutate() guards to multiframe strategies                                   | #202                           |
| Register multiframe strategies in DicomMutator dispatch                            | (all 10 registered)            |
| Track binary mutations in MutationRecord                                           | #197                           |
| Seed fuzzer engine + log RNG seed                                                  | #184, #185                     |
| crash_by_strategy telemetry                                                        | #191                           |
| Structural mutation reweighting                                                    | #188                           |
| Merge/disambiguate corpus_minimization vs corpus_minimizer                         | (corpus_minimizer.py deleted)  |
| CrashRecord.reproduction_command always None                                       | (conditionally populated)      |
| Pre-mutation safety checks (--safety-mode)                                         | #209                           |
| Seed file sanitization (dicom-fuzzer sanitize)                                     | #210                           |
| Seed corpus diversification (MR, DX, NM, PT, RTDOSE, RTSTRUCT)                     | (seed corpus populated)        |
| Surface multiframe attack type via last_variant                                    | #217                           |
| Mutation taxonomy (boundary/malformed/injection)                                   | Dropped (not effective)        |
| Crash discovery saturation curve                                                   | Dropped (insufficient data)    |
| EmptyValueFuzzer (9 present-but-empty .NET crash attacks)                          | #229                           |
| StructureFuzzer binary VR corruption (4 attacks)                                   | #230                           |
| CompressedPixelFuzzer binary encapsulation (6 attacks)                             | #231                           |
| Overlay attacks + private SQ at EOF + odd-length pixel data                        | #232                           |
| Bump cryptography >= 46.0.7 (Dependabot #43)                                       | #233                           |
| CVE-to-strategy coverage audit (~140 CVEs, 13 gaps, 2 rounds)                      | #234, #235                     |
| Fully untrack dicom-seeds directory                                                | #236                           |
| P1 CVE quick wins: G1, G4, G6, G8, G9, G12, G13 (7 gaps)                           | (7 attacks across 3 fuzzers)   |
| P1 CVE medium: G2 JPEG-LS, G7 VOI LUT, G10 duplicate meta                          | (3 attacks across 3 fuzzers)   |
| MR modality expansion (6 attack types in CalibrationFuzzer)                        | (fuzz_mr_parameters)           |
| DX/CR modality expansion (5 attack types in CalibrationFuzzer)                     | (fuzz_dx_parameters)           |
| Multiframe functional group crash attacks (2 new attacks)                          | (empty frame content + NaN)    |
| Concurrent field mismatches (PixelFuzzer)                                          | (\_concurrent_field_mismatch)  |
| Registration geometry attacks (4 sub-attacks in StudyMutator)                      | (REGISTRATION_GEOMETRY)        |
| G11: Preamble polyglot (PE/ELF/JSON/ff/random, PreambleFuzzer)                     | (preamble strategy)            |
| G5: DICOMDIR path traversal + deep nesting (DicomdirFuzzer)                        | (dicomdir strategy)            |
| G3: Decompression bomb 128MB/512MB/1GB/corrupted (DeflateBombFuzzer)               | (deflate_bomb strategy)        |
| Temporal (4D) attacks: InstanceCreationTime, delta violations, cardiac TriggerTime | (3 sub-attacks in strategy 12) |
| P0: State machine wiring: StatefulFuzzer.fuzz(), execute_event() PDU building      | (build_pdu_for_event + types)  |
| P0: DIMSE PDU packing: DIMSEMessage.to_p_data_tf_pdu() + C-STORE from pydicom      | (26 new tests)                 |
| WaveformFuzzer: 14 ECG/waveform channel-count/OOB attacks (strategy 34)            | (31 new tests)                 |
| StructuredReportFuzzer: 12 SR ContentSequence tree attacks (strategy 35)           | (26 new tests)                 |
| UltrasoundFuzzer: 12 US frame/Doppler/region geometry attacks (strategy 36)        | (31 new tests)                 |
| MammographyFuzzer: 12 MG/DBT geometry and calibration attacks (strategy 37)        | (29 new tests)                 |
| XRayAngiographyFuzzer: 12 XA/XRF CINE, dose, geometry attacks (strategy 38)        | (30 new tests)                 |
| SpectroscopyFuzzer: 12 MR Spectroscopy data/frequency attacks (strategy 39)        | (27 new tests)                 |
| ParametricMapFuzzer: 12 quantitative MRI RWV mapping attacks (strategy 40)         | (26 new tests)                 |
| SecondaryCaptureFuzzer: 12 SC pixel geometry/color space attacks (strategy 41)     | (32 new tests)                 |
| PresentationStateFuzzer: 12 GSPS/CSPS VOI LUT and annotation attacks (strategy 42) | (38 new tests)                 |
