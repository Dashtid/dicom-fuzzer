# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

## Scope policy (2026-04-13)

Format fuzzers are only worth adding when a matching seed exists in
`dicom-seeds/`. Current seed corpus modalities: CT, DX, MR, NM, PET,
RT-Dose, RT-Struct, SEG, encapsulated-PDF (9 modalities). Fuzzers for
SOP classes outside this set produce no crashes against the actual
target (Hermes.exe with these seeds) because `can_mutate()` returns
False for every campaign input.

Going forward:

1. Format work focuses on **CVE gap coverage within the 9 seed modalities**.
2. New modality fuzzers (US, MG, XA, MRS, PM, SC, PR, VL, SR, Waveform,
   etc.) require seed corpus expansion first.
3. Non-format work (campaign tooling, crash triage automation,
   coverage-guided fuzzing, network/DIMSE deepening) is the
   higher-leverage track.

---

## Campaign & validation -- P1

### Build local high-quality DICOM seed corpus

Ongoing. Seed corpus already covers 9 modalities (CT, DX, MR, NM,
PET, RT-Dose, RT-Struct, SEG, encapsulated-PDF) in
`dicom-seeds/`. Expansion to US/MG/XA/SR/Waveform unlocks
reinstating the modality fuzzers removed in PR #246.

### Full campaign run

Overnight run with current 9 seeds + 30s timeout against
Hermes.exe. Analyze `crash_by_strategy` telemetry to identify
zero-crash strategies for second-pass audit.

### Crash triage automation

Currently 1 confirmed crash (stack overflow CWE-674 via
self-referencing ReferencedImageSequence). Build:

- Auto-cluster crashes by stack-frame signature
- Auto-minimize via mutation-record replay
- Generate per-crash markdown report from `CrashRecord`

### Second-pass structural audit

After campaign data exists: remove or redesign zero-crash
strategies. Requires statistically meaningful campaign first.

---

## Low priority / deferred

- Structural/content code comments
- CrashAnalyzer rename
- Test flakiness investigation (`test_complete_generation_workflow`)
- Strategy effectiveness charts
- End-of-campaign auto-triage
- Authentication negotiation fuzzing (network module extension)

---

## Long-term vision

### Full DICOM SOP Class coverage

186 Storage SOP Classes. Current 33 strategies (23 in-scope format
plus 10 multiframe). Out-of-scope modality fuzzers were removed;
expand seed corpus first before adding more.

### Coverage-guided fuzzing

DynamoRIO/Frida instrumentation against Hermes.exe. Coverage
feedback drives seed selection and mutation reweighting. Highest
expected payoff but largest scope (~1-2 weeks).

---

## Completed (reference only)

Earlier completed items collapsed; recent work below.

| Item                                                           | PR(s)                         |
| -------------------------------------------------------------- | ----------------------------- |
| EmptyValueFuzzer (9 .NET crash attacks)                        | #229                          |
| StructureFuzzer binary VR corruption                           | #230                          |
| CompressedPixelFuzzer binary encapsulation                     | #231                          |
| Overlay attacks + private SQ at EOF + odd-length pixel data    | #232                          |
| Bump cryptography >= 46.0.7                                    | #233                          |
| CVE-to-strategy coverage audit (~140 CVEs, 13 gaps, 2 rounds)  | #234, #235                    |
| Fully untrack dicom-seeds directory                            | #236                          |
| P1 CVE quick wins: G1, G4, G6, G8, G9, G12, G13                | (across 3 fuzzers)            |
| P1 CVE medium: G2 JPEG-LS, G7 VOI LUT, G10 duplicate meta      | (across 3 fuzzers)            |
| G11: Preamble polyglot (PreambleFuzzer)                        | (preamble strategy)           |
| G5: DICOMDIR path traversal + nesting (DicomdirFuzzer)         | (dicomdir strategy)           |
| G3: Deflate bomb (DeflateBombFuzzer)                           | (deflate_bomb strategy)       |
| MR modality expansion in CalibrationFuzzer                     | (fuzz_mr_parameters)          |
| DX/CR modality expansion in CalibrationFuzzer                  | (fuzz_dx_parameters)          |
| Multiframe functional group crash attacks                      | (empty frame + NaN)           |
| Concurrent field mismatches in PixelFuzzer                     | (\_concurrent_field_mismatch) |
| Temporal (4D) series attacks                                   | (series strategy 12)          |
| Registration geometry attacks (StudyMutator)                   | (REGISTRATION_GEOMETRY)       |
| P0 PDU binary format (PS3.8 Section 7)                         | (7 PDU type builders)         |
| P0 State machine wiring (StatefulFuzzer.fuzz + execute_event)  | (build_pdu_for_event)         |
| P0 DIMSE PDU packing (to_p_data_tf_pdu, C-STORE from pydicom)  | (26 new tests)                |
| P1 Real TLS testing                                            | (TLSSecurityTester)           |
| P1 Query/Retrieve fuzzing                                      | (DIMSEFuzzer C-FIND/MOVE)     |
| Removed 9 out-of-scope modality fuzzers                        | #246                          |
| CVE audit refocus addendum (all 13 gaps closed, ~95% coverage) | #247                          |
| 4 niche fo-dicom binary attacks (#1009, #763, #1386, #1982)    | #252                          |
