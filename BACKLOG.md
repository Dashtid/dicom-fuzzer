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

## Module maturity (2026-04-25)

| Module     | Maturity | Strategies         | Tests | Binary attacks            |
| ---------- | -------- | ------------------ | ----- | ------------------------- |
| Format     | mature   | 23                 | ~1260 | 13 (Structure) + 4 others |
| Multiframe | growing  | 10                 | ~180  | 6 (EncapsulatedPixel)     |
| Series     | growing  | 18 (12+6)          | ~335  | 0                         |
| Network    | mature   | DIMSE+TLS+Stateful | ~595  | PDU-level                 |

Key gap: Series has no binary-level attacks.

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
zero-crash strategies for second-pass audit. For fo-dicom-harness
campaigns also pass `--crash-exit-codes 1,11` so untyped library
escapes are recorded as findings instead of dropping to ERROR.

### Hash-pin remaining tool installs (Pinned-Deps 9 -> 10)

OpenSSF Scorecard's Pinned-Deps check is at 9/10 because two
unpinned tool installs remain in workflows:

- `mutation-testing.yml`: `uv pip install mutmut toml` (twice).
  Adding `mutmut`, `toml` to a `[project.optional-dependencies]`
  group and switching to `uv sync --extra mutation` would route
  them through `uv.lock` (hash-pinned). Slight CI overhead per run.
- `sbom-scan.yml`: `pip install sbom-sentinel`. Either move to
  `uv.lock` via an extra (couples the project to its own SBOM tool
  as a dev dep -- circular feel), or generate a hash-pinned
  requirements file in `.github/requirements/sbom-sentinel.txt`
  and use `pip install --require-hashes -r ...`.

Score impact is +0.05 to the Scorecard aggregate -- not visible on
the badge. Worth doing when convenient, not worth contorting the
build for.

### fo-dicom harness regression tests in CI

Harness binary today has zero CI coverage: no test runs the compiled
`.exe` against known-rc fixtures. Add a test (Linux-runnable via
`dotnet run`) that asserts: a known-clean DICOM returns 0; a malformed
file missing required tags returns 12; a deliberately-malformed parse
target returns 10. Catches future regressions to the typed/untyped split.

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
- **CI runner OOM in `test_default_arguments`** (resource_manager).
  `tests/test_core/session/test_resource_manager.py::TestResourceLimitedConvenience::test_default_arguments`
  calls `resource_limited(min_disk_space_mb=1)` which uses default
  `max_memory_mb=1024` and applies `setrlimit(RLIMIT_AS, 1GB)` to the
  test process itself. Pytest with coverage instrumentation already
  exceeds 1GB virtual address space, so the next allocation triggers
  exit 137/152 (OOM kill). Bounced through nearly every matrix split
  during the 2026-04-25 PR landing batch (#272, #284, #287). Fix:
  pass an explicit `max_memory_mb` value high enough that the test
  process won't trip it (e.g. 8192), or run the limit-setting in a
  subprocess so the parent isn't affected. Same root cause may also
  affect `test_yields_resource_manager` which uses 2048 MB.
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

## Known unpatched advisories

### pip CVE-2026-3219 (medium, no patch)

Dependabot alert for pip <= 26.0.1 (interpretation conflict --
concatenated tar+ZIP files handled as ZIP). Pulled in transitively
by `pip-api` -> `pip-audit` (the `[security]` extra). Not consumed
by any production code path. No fix version published yet (as of
2026-04-27). Re-evaluate when pip > 26.0.1 ships; until then,
acceptable risk because the vulnerable code is only reached during
`pip-audit` runs.

---

## Completed (reference only)

Earlier completed items collapsed; recent work below.

| Item                                                              | PR(s)                         |
| ----------------------------------------------------------------- | ----------------------------- |
| EmptyValueFuzzer (9 .NET crash attacks)                           | #229                          |
| StructureFuzzer binary VR corruption                              | #230                          |
| CompressedPixelFuzzer binary encapsulation                        | #231                          |
| Overlay attacks + private SQ at EOF + odd-length pixel data       | #232                          |
| Bump cryptography >= 46.0.7                                       | #233                          |
| CVE-to-strategy coverage audit (~140 CVEs, 13 gaps, 2 rounds)     | #234, #235                    |
| Fully untrack dicom-seeds directory                               | #236                          |
| P1 CVE quick wins: G1, G4, G6, G8, G9, G12, G13                   | (across 3 fuzzers)            |
| P1 CVE medium: G2 JPEG-LS, G7 VOI LUT, G10 duplicate meta         | (across 3 fuzzers)            |
| G11: Preamble polyglot (PreambleFuzzer)                           | (preamble strategy)           |
| G5: DICOMDIR path traversal + nesting (DicomdirFuzzer)            | (dicomdir strategy)           |
| G3: Deflate bomb (DeflateBombFuzzer)                              | (deflate_bomb strategy)       |
| MR modality expansion in CalibrationFuzzer                        | (fuzz_mr_parameters)          |
| DX/CR modality expansion in CalibrationFuzzer                     | (fuzz_dx_parameters)          |
| Multiframe functional group crash attacks                         | (empty frame + NaN)           |
| Concurrent field mismatches in PixelFuzzer                        | (\_concurrent_field_mismatch) |
| Temporal (4D) series attacks                                      | (series strategy 12)          |
| Registration geometry attacks (StudyMutator)                      | (REGISTRATION_GEOMETRY)       |
| P0 PDU binary format (PS3.8 Section 7)                            | (7 PDU type builders)         |
| P0 State machine wiring (StatefulFuzzer.fuzz + execute_event)     | (build_pdu_for_event)         |
| P0 DIMSE PDU packing (to_p_data_tf_pdu, C-STORE from pydicom)     | (26 new tests)                |
| P1 Real TLS testing                                               | (TLSSecurityTester)           |
| P1 Query/Retrieve fuzzing                                         | (DIMSEFuzzer C-FIND/MOVE)     |
| Removed 9 out-of-scope modality fuzzers                           | #246                          |
| CVE audit refocus addendum (all 13 gaps closed, ~95% coverage)    | #247                          |
| 4 niche fo-dicom binary attacks (#1009, #763, #1386, #1982)       | #252                          |
| Codecov wired up + badge on README                                | #279                          |
| CI coverage measured across all 10 test splits (not just g1)      | #281                          |
| Coverage-tail closers (cli/base, samples, study_campaign)         | #283, #284, #285              |
| Coverage-tail closers (parallel_mutator, resource_manager)        | #286                          |
| fo-dicom network harness (DIMSE SCP + TLS) under examples/        | #277                          |
| pydicom smoke harness (corpus analyzer) under examples/           | #275                          |
| examples/ directory (targets + tooling consolidation)             | #278                          |
| fo-dicom file harness (-t EXE target under examples/)             | #276                          |
| Multiframe binary attacks via `mutate_bytes` (BOT/EOT, 6)         | #272                          |
| Round-robin starvation fix (CLI mini-batching)                    | #273                          |
| Backlog hygiene + stale-PR triage section                         | #287                          |
| fo-dicom harness pixel-data decoder + rc=12 typed-rejection split | #298, #303                    |
| Configurable per-target crash exit codes in TargetRunner          | (current)                     |
| Codec-bearing seeds (JPEG-LS, JPEG2000, JPEG Baseline, RLE)       | (current)                     |
