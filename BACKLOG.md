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

## Module maturity (2026-04-22)

| Module     | Maturity | Strategies         | Tests | Binary attacks            |
| ---------- | -------- | ------------------ | ----- | ------------------------- |
| Format     | mature   | 23                 | ~1260 | 13 (Structure) + 4 others |
| Multiframe | growing  | 10                 | ~180  | 0                         |
| Series     | growing  | 18 (12+6)          | ~335  | 0                         |
| Network    | mature   | DIMSE+TLS+Stateful | ~595  | PDU-level                 |

Key gap: Multiframe and Series have no binary-level attacks.

---

## Format fuzzing -- P3: architectural depth

- **Generic `mutate_bytes` length-field sweep.** Today only
  StructureFuzzer has a length-field binary attack. Extract it as
  a base-class helper so every format fuzzer can opt into length
  corruption.
- **Nested-SQ recursion bomb in SequenceFuzzer.** Configurable
  depth (default 10k). Current nesting is ad-hoc and shallow.
- **Cross-reference attacks.** AT/AE/UI forward references that
  point at nonexistent tags, at themselves, or form cycles.

## Multiframe fuzzing -- P2: close the binary-attack gap

- **Multiframe-aware BOT corruption.** Add `mutate_bytes` to
  EncapsulatedPixelStrategy that knows NumberOfFrames and can
  create N-mismatched offsets (CompressedPixelFuzzer's BOT attack
  is single-frame unaware).
- **Extended Offset Table (EOT) fuzzing.** DICOM 2022 tag
  (7FE0,0001) is untouched. New strategy class.
- **Shared/per-frame ambiguity.** Replicate a value in both
  SharedFunctionalGroupsSequence and PerFrameFunctionalGroupsSequence
  to test viewer precedence logic.

## Series/study fuzzing -- P2: close obvious gaps

- **Circular ReferencedSeriesSequence** (A->B->A) to test
  depth-first traversal safety.
- **Singular geometry matrices** (zero-determinant Transform
  via ImagePositionPatient + ImageOrientationPatient) to crash
  reconstruction matrix-inversion paths.
- **Same SOPInstanceUID across series** to test archiver
  instance-dedup logic.
- **Fault isolation for ParallelSeriesMutator** (per-worker
  try/except; pool survives single worker crash).

## Network fuzzing -- P3: complete the state machine

- **Wire `timing_attacks.py` + `resource_attacks.py` into
  `StatefulFuzzer.generate_fuzz_sequences()`.** Modules exist but
  no campaign calls into them.
- **TLS cert chain fuzzing.** Expired certs, self-signed chains,
  wrong-CN, CRL/OCSP revocation scenarios.
- **User-identity negotiation fuzzing** (PS3.7 User-Identity
  Sub-Item: username/password, Kerberos, SAML, JWT).

---

## Open-source target adoption -- P1

Current target is `Hermes.exe` (proprietary). Crash reports stay
local; no upstream contribution path. Recommended primary
open-source target: **Orthanc 1.12.10** (C++, Windows installer,
DIMSE+REST+DICOMweb covers all four attack modes, active CVE
surface). **DCMTK** as secondary (format-heavy batch via
`dcmdump`/`storescp`; Linux-only is fine for CI).

Why Orthanc specifically:

- Accepts format/multiframe files via HTTP upload or C-STORE
- Full DIMSE server (exercises network module)
- Study-level REST + DICOMweb (exercises series module)
- Machine Spirits disclosed CVE-2026-5437..5445 against 1.12.10
  in 2026 (heap BOF, decompression bomb, meta-header OOB read);
  all fixed in 1.12.11. Proves the parser is fuzzable and
  maintainers ship fixes.
- Active maintainer (Sebastien Jodogne, UCLouvain); public
  issue tracker and responsive security handling.

Concrete work:

- **Pin Orthanc 1.12.10 locally** as regression baseline. Our
  fuzzer should reproduce CVE-2026-5437..5445 -- strong
  end-to-end validation of the fuzzer.
- **Add `--target-mode` option** with `hermes`, `orthanc-file`,
  `orthanc-dimse` variants.
- **Separate artifact roots** (`artifacts/campaigns/orthanc/`)
  so Hermes data stays isolated.
- **Coordinated disclosure flow** if a new crash is found against
  patched versions.

Alternatives considered and rejected as primary: GDCM (library,
no server), fo-dicom (.NET, what Hermes already hits implicitly),
dcm4chee-arc-light (Java, heavy deploy), OHIF/Weasis/Slicer
(hard to automate crash detection, less active CVE surface).

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
