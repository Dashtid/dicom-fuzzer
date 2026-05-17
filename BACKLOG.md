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

(empty -- previous P3 item closed by the length-field utils extraction;
add new format-architecture work here when it surfaces.)

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

### Full campaign run -- DONE (2026-05-14)

8h overnight run (`-c 45`, 720 tests, 7h 33m wall) completed. Headline
numbers: 649 successful, 71 crashes (auto-triaged to **2 clusters**),
1 memory limit hit.

**Cluster 1 (70 crashes, sig `844c8d389ce1`):** STACK_OVERFLOW
(0xC00000FD). Same underlying CWE-674 we already had, but the
single-seed-strategy memory note was wrong -- the bug is reachable
via **22 different mutation strategies**, not just `dicomdir`. Top
contributors: `sequence` (16), `compressed_pixel` (6),
`pixel_data_truncation` (5), `dicomdir` (4), `preamble` (4),
`pixel_reencoding` (4), `attribute_tag` (4), `dictionary` (3), ...
The dispatcher in Hermes recurses on a wide class of structurally
malformed inputs, not specifically on directory records.

**Cluster 2 (1 crash, sig `f3475e3cfa6d`):** MemoryLimitExceeded,
peak 4851 MB, strategy `dictionary`. Single occurrence in 720 tests.
**Candidate new finding** -- if reproducible with a small seed input,
this is CWE-770 unbounded allocation. See follow-up item below.

`--detect-dialogs` was used and worked; no license-dialog stalls
observed across 720 launches.

### Investigate the 8h-campaign memory-amplification candidate -- P1

The 2026-05-14 campaign produced one `MemoryLimitExceeded` (4851 MB
peak) from a `dictionary`-strategy mutation. Whether this is a real
CWE-770 finding or a freak amplification from a large input is
unknown -- we can't extract the exact input because the campaign
hit the `preserved_sample_path` collision bug (now fixed) and the
preserved .dcm was overwritten 70 times by the stack-overflow
crashes that finalized later.

Repro plan:

- Re-run with `--seed 12345 --strategy dictionary` (need to wire
  this through if not already exposed) against the same 16-seed
  corpus, OR re-run the full campaign now that preserved-sample
  paths are unique per crash.
- If reproduced, minimize the input and check whether the seed
  size is small enough that the 4.85GB peak is a true amplification
  (>100x) rather than legitimate large-data processing.

### Atheris fuzz coverage -- DONE (closed 2026-05-05)

Two harnesses run weekly + on PRs touching parsing paths:
`fuzz_parser.py` (DicomParser) and `fuzz_mutator.py` (DicomMutator).
Corpus persists across runs via actions/cache. ~1M executions on
fuzz_parser produced zero crashes; coverage plateaued at ~1010 edges,
which is the surface limit of a one-module harness rather than a
runtime limit. `fuzz_corpus.py` was considered and rejected as
marginal -- the corpus loader's surface is already covered by
`fuzz_parser`'s upstream side. Only revisit if a regression appears
in the weekly cron summary or someone invests in a wider Python
parser surface.

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

### Workflow token-permission scoping (Scorecard Token-Permissions)

Scorecard's Token-Permissions check flags four workflows that run with
the default (write-all) `GITHUB_TOKEN` scope instead of an explicit,
least-privilege `permissions:` block:

- `auto-tag.yml` (job- and workflow-level) -- needs `contents: write`
  for tag creation, nothing else.
- `release.yml` (`:106`) -- needs `contents: write` for the release
  upload; scope the rest to `contents: read`.
- `dependabot-auto-merge.yml` (`:13`) -- needs `pull-requests: write`
  - `contents: write` for the merge; nothing else.
- `sbom-scan.yml` (`:33`) -- needs `contents: read` (and
  `security-events: write` only if it uploads SARIF).

Add a top-level `permissions: { contents: read }` to each, then
re-grant the minimum at the job that needs it. Surfaced as 5 "high"
CodeQL/Scorecard alerts during the 2026-05-12 dependency-drift sweep.
Same caveat as Pinned-Deps: aggregate-score only, not on the badge.

### Bare `except: pass` in binary_mutators.py:183 (CodeQL py/empty-except)

One `except Exception: pass` with no comment in
`dicom_fuzzer/utils/binary_mutators.py:183` -- CodeQL `py/empty-except`
(note severity). Either narrow the caught type, add a `# intentional:`
rationale comment, or log at debug. Trivial; bundle with the next
touch of that file.

### pip GHSA-58qw-9mgm-455v -- no upstream fix yet

`GHSA-58qw-9mgm-455v` (medium, pip `<= 26.0.1`) has no patched
release as of 2026-05-12 -- it lingers as an open Dependabot alert on
`uv.lock` until upstream ships one. Nothing actionable; revisit when a
pip release advertises the fix. (The companion pip CVE
`GHSA-jp4c-xjxw-mgf9` was cleared by the 26.0 -> 26.1 bump in #321.)

### fo-dicom harness regression tests in CI

Harness binary today has zero CI coverage: no test runs the compiled
`.exe` against known-rc fixtures. Add a test (Linux-runnable via
`dotnet run`) that asserts: a known-clean DICOM returns 0; a malformed
file missing required tags returns 12; a deliberately-malformed parse
target returns 10. Catches future regressions to the typed/untyped split.

### Crash triage automation

Currently 1 confirmed crash (stack overflow CWE-674 via
self-referencing ReferencedImageSequence). Build:

- Auto-cluster crashes by stack-frame signature -- Phase 5 (in this
  PR) lands the full pipeline: `--dump-dir` sets
  `DOTNET_DbgEnableMiniDump` on Hermes so the runtime writes a .dmp
  on every Corrupted State Exception; pythonnet + bundled ClrMD
  symbolicate; Socorro-style hashing buckets matching crashes into
  one signature; cluster reports embed the top frames + primary/
  minor hashes. No external installs, no `tools/` folder.
- Auto-minimize via mutation-record replay
- Generate per-crash markdown report from `CrashRecord` -- done in
  Phase 4 / cluster reports.

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

| Item                                                                                                                 | PR(s)                         |
| -------------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| EmptyValueFuzzer (9 .NET crash attacks)                                                                              | #229                          |
| StructureFuzzer binary VR corruption                                                                                 | #230                          |
| CompressedPixelFuzzer binary encapsulation                                                                           | #231                          |
| Overlay attacks + private SQ at EOF + odd-length pixel data                                                          | #232                          |
| Bump cryptography >= 46.0.7                                                                                          | #233                          |
| CVE-to-strategy coverage audit (~140 CVEs, 13 gaps, 2 rounds)                                                        | #234, #235                    |
| Fully untrack dicom-seeds directory                                                                                  | #236                          |
| P1 CVE quick wins: G1, G4, G6, G8, G9, G12, G13                                                                      | (across 3 fuzzers)            |
| P1 CVE medium: G2 JPEG-LS, G7 VOI LUT, G10 duplicate meta                                                            | (across 3 fuzzers)            |
| G11: Preamble polyglot (PreambleFuzzer)                                                                              | (preamble strategy)           |
| G5: DICOMDIR path traversal + nesting (DicomdirFuzzer)                                                               | (dicomdir strategy)           |
| G3: Deflate bomb (DeflateBombFuzzer)                                                                                 | (deflate_bomb strategy)       |
| MR modality expansion in CalibrationFuzzer                                                                           | (fuzz_mr_parameters)          |
| DX/CR modality expansion in CalibrationFuzzer                                                                        | (fuzz_dx_parameters)          |
| Multiframe functional group crash attacks                                                                            | (empty frame + NaN)           |
| Concurrent field mismatches in PixelFuzzer                                                                           | (\_concurrent_field_mismatch) |
| Temporal (4D) series attacks                                                                                         | (series strategy 12)          |
| Registration geometry attacks (StudyMutator)                                                                         | (REGISTRATION_GEOMETRY)       |
| P0 PDU binary format (PS3.8 Section 7)                                                                               | (7 PDU type builders)         |
| P0 State machine wiring (StatefulFuzzer.fuzz + execute_event)                                                        | (build_pdu_for_event)         |
| P0 DIMSE PDU packing (to_p_data_tf_pdu, C-STORE from pydicom)                                                        | (26 new tests)                |
| P1 Real TLS testing                                                                                                  | (TLSSecurityTester)           |
| P1 Query/Retrieve fuzzing                                                                                            | (DIMSEFuzzer C-FIND/MOVE)     |
| Removed 9 out-of-scope modality fuzzers                                                                              | #246                          |
| CVE audit refocus addendum (all 13 gaps closed, ~95% coverage)                                                       | #247                          |
| 4 niche fo-dicom binary attacks (#1009, #763, #1386, #1982)                                                          | #252                          |
| Codecov wired up + badge on README                                                                                   | #279                          |
| CI coverage measured across all 10 test splits (not just g1)                                                         | #281                          |
| Coverage-tail closers (cli/base, samples, study_campaign)                                                            | #283, #284, #285              |
| Coverage-tail closers (parallel_mutator, resource_manager)                                                           | #286                          |
| fo-dicom network harness (DIMSE SCP + TLS) under examples/                                                           | #277                          |
| pydicom smoke harness (corpus analyzer) under examples/                                                              | #275                          |
| examples/ directory (targets + tooling consolidation)                                                                | #278                          |
| fo-dicom file harness (-t EXE target under examples/)                                                                | #276                          |
| Multiframe binary attacks via `mutate_bytes` (BOT/EOT, 6)                                                            | #272                          |
| Round-robin starvation fix (CLI mini-batching)                                                                       | #273                          |
| Backlog hygiene + stale-PR triage section                                                                            | #287                          |
| fo-dicom harness pixel-data decoder + rc=12 typed-rejection split                                                    | #298, #303                    |
| Configurable per-target crash exit codes in TargetRunner                                                             | (current)                     |
| Codec-bearing seeds (JPEG-LS, JPEG2000, JPEG Baseline, RLE)                                                          | (current)                     |
| Nested-SQ recursion bomb in SequenceFuzzer.mutate_bytes                                                              | (current)                     |
| AT VR pointer-semantics attacks (AttributeTagFuzzer, 3 strategies)                                                   | (current)                     |
| Length-field corruption helper extracted; HeaderFuzzer + MetadataFuzzer + PrivateTagFuzzer adopt it via mutate_bytes | (current)                     |
