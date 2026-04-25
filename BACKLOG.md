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

## Open PRs needing triage (2026-04-23)

Three PRs opened 2026-04-22 sit `BEHIND` main. Work is sound but
needs rebase + re-verify before merging.

| #    | Title                                                  | Action needed                                          |
| ---- | ------------------------------------------------------ | ------------------------------------------------------ |
| #272 | Multiframe binary attacks on EncapsulatedPixelStrategy | Rebase; closes the "0 binary attacks" gap below        |
| #273 | CLI round-robin starvation fix                         | Rebase; bug is still live on main (campaign_runner.py) |
| #276 | fo-dicom file harness target                           | Rebase; listed as concrete work below                  |

---

## Module maturity (2026-04-23)

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
local; no upstream contribution path. Primary open-source target:
**fo-dicom**. Secondary: **pydicom**.

### Why fo-dicom as primary

- GitHub-native ([fo-dicom/fo-dicom](https://github.com/fo-dicom/fo-dicom)),
  normal PR review flow, active releases (5.2.6 in March 2026).
- Full DICOM surface: parser (Format + Multiframe), `DicomServer` +
  `DicomClient` with DIMSE + TLS (Network), directory loading (Series).
  A ~50-line C# harness wrapping `DicomServer<DicomCStoreProvider>`
  turns it into the network module's target.
- High relevance to Hermes (both .NET). Crashes found in fo-dicom
  often reproduce in Hermes and vice versa.
- ~40 known fo-dicom crash issues already map to parser/encoder
  bugs. No formal CVEs, but real bugs in real medical imaging
  software.

### Why pydicom as secondary

- Free second target: our pipeline already parses files through
  pydicom after mutation. Any parse-time crash surfaces naturally.
  Zero setup.
- GitHub-native ([pydicom/pydicom](https://github.com/pydicom/pydicom)),
  pure Python. Trivial fix-and-PR loop.

### Dropped from consideration

- **Orthanc** -- canonical repo is Mercurial, contributions via
  forum patch-post. Ergonomics too heavy for a solo project.
- **DCMTK** -- git-based but not GitHub; Redmine tracker. Stronger
  C/C++ CVE surface, but contribution flow is slower than GitHub PR.
- **GDCM** -- GitHub mirror accepts PRs, but library-only (no server,
  no DIMSE). Narrower attack surface than fo-dicom.
- **dcm4chee-arc-light** -- Java, heavy deploy (WildFly + DB).
- **OHIF/Weasis/3D Slicer** -- hard to automate crash detection,
  less active CVE surface.

### What going fo-dicom-only costs us

- Memory-corruption class crashes (OOB, UAF, heap overflow) are
  rare: .NET GC bounds-checks everything. Crashes are DoS, not
  RCE candidates.
- CVE-assignment velocity is lower than C/C++ parsers. fo-dicom
  findings usually land as GitHub issues + PRs, not CVEs.
- Downstream blast radius is narrower (mostly .NET ecosystem).

Accepted trade-off: 3-5x higher velocity on the full loop
(crash -> repro -> issue -> PR -> merged) beats the theoretical
RCE ceiling we'd never reach with a slower toolchain.

### Concrete work

- **fo-dicom network harness.** Small .NET app
  (`examples/fodicom-network-harness/`) wrapping
  `DicomServer<DicomCStoreProvider>` + TLS. Our network fuzzer
  points at it.
- **fo-dicom file harness.** Small .NET app that runs
  `DicomFile.Open(path)` + `Dataset.Get<T>(...)` traversals in a
  loop over a corpus directory. Crashes surface as process exit
  codes.
- **Separate artifact roots** (`artifacts/campaigns/fodicom/`,
  `artifacts/campaigns/pydicom/`) so Hermes data stays isolated.
- **Issue-report template** for fo-dicom repro bundles: crashing
  input + stack trace + minimal reproducer program.

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
| Codecov wired up + badge on README                             | #279                          |
| CI coverage measured across all 10 test splits (not just g1)   | #281                          |
| Coverage-tail closers (cli/base, samples, study_campaign)      | #283, #284, #285              |
| Coverage-tail closers (parallel_mutator, resource_manager)     | #286                          |
| fo-dicom network harness (DIMSE SCP + TLS) under examples/     | #277                          |
| pydicom smoke harness (corpus analyzer) under examples/        | #275                          |
| examples/ directory (targets + tooling consolidation)          | #278                          |
