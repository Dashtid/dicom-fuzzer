# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

## Scope policy (2026-06-06 update)

**Target scope:** fo-dicom (primary upstream) and pydicom (secondary
upstream) are the **only** open-source targets we pursue actively.
Other DICOM stacks (Orthanc, DCMTK, dcm4che, GDCM) are not in scope
even when bugs would be welcome upstream -- contribution ergonomics
or low GitHub-PR signal rules them out. See `## Open-source target
adoption -- P1` for the rationale.

**Hermes scope filter:** Hermes parse-crash findings are out of
scope. Vendor's deployment is single-process so parse crashes are
trivially recoverable; only CWE-770-class amplification findings get
escalated to the vendor. This is encoded as a project memory rule
(`feedback_hermes_scope.md`) so future Claude sessions apply it
without being re-prompted. Format/network strategies still target
Hermes implicitly via the seed corpus, but Hermes is no longer the
disclosure target.

**Format strategy policy:** Format fuzzers are only worth adding
when (a) a matching seed exists in `dicom-seeds/` AND (b) the
mutation maps to a known fo-dicom OR pydicom bug class (or a
plausible parser-internal failure mode). Current seed corpus
modalities: CT, DX, MR, NM, PET, RT-Dose, RT-Struct, SEG,
encapsulated-PDF (9 modalities). Gap-audit-driven additions are
prioritised over speculative ones.

Going forward:

1. Format work focuses on **gap-audit-verified attack patterns**
   that fo-dicom and pydicom would actually crash on.
2. New modality fuzzers (US, MG, XA, MRS, PM, SC, PR, VL, SR,
   Waveform, etc.) require seed corpus expansion AND a target-side
   bug pattern first.
3. Non-format work (campaign tooling, crash triage automation,
   coverage-guided fuzzing, network/DIMSE deepening) is the
   higher-leverage track when no audit-verified gap is queued.

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

## Upstream-PR pipeline -- P1 (2026-06-06)

The harnesses, strategies, and network module exist. What's missing
is a deterministic pipeline from "we have a fuzzer" to "merged
upstream PR". This section IS that pipeline. Success metric: **3-5
merged upstream PRs across fo-dicom + pydicom over the next
4 weeks**.

Each phase is sized for one focused session. Phases 4-7 run on
wall-clock timers (campaign + triage) and overlap heavily.

### Phase 1 -- Gap audit -- DONE (2026-06-06)

Workflow-driven fan-out audit across 5 axes (PS3.5, PS3.7/3.8,
fo-dicom issues, pydicom issues, public CVEs). 41 agents, 13min,
66 raw gaps -> 28 verified after adversarial refutation.

Full report (not in git): `artifacts/audit/gap_audit_2026-06-06.md`.

**Top 10 verified gaps (input to Phase 2):**

| #   | Title                                           | Module  | Effort | Yield |
| --- | ----------------------------------------------- | ------- | ------ | ----- |
| 1   | file-meta-group-length-binary-rewrite           | format  | S      | high  |
| 2   | big-endian-tsuid-le-bytes-binary                | format  | S      | high  |
| 3   | sq-undefined-truncated-at-eof                   | format  | S      | high  |
| 4   | definite-length-sq-lies                         | format  | S      | high  |
| 5   | seq-delim-non-zero-length                       | format  | S      | high  |
| 6   | item-delim-non-zero-length                      | format  | S      | high  |
| 7   | max-length-subitem-0x51-edge-values             | network | S      | high  |
| 8   | multiple-and-empty-transfer-syntaxes-per-pc     | network | S      | high  |
| 9   | duplicate-and-overflow-presentation-context-ids | network | S      | high  |
| 10  | dimse-command-set-illegal-data-set-type         | network | M      | high  |

Two thematic clusters:

- **Format binary length-field attacks** (#1-6): post-serialization
  rewrites pydicom cannot express because it recomputes lengths on
  `dcmwrite`. All target distinct parser code paths.
- **Network A-ASSOCIATE sub-item attacks** (#7-9) + DIMSE command-set
  rewrites (#10): the User Information sub-item family is almost
  entirely uncovered (only 0x58 User Identity has a fuzzer); PC list
  shape is hardcoded.

18 additional verified gaps are queued as backlog candidates after
the top-10 lands. See the audit report for the full list.

### Phase 2 -- Gap selection (~30min, P1)

Read the audit report. Pick top 3-5 strategies to implement,
biased toward (a) fo-dicom-evidenced bugs, (b) novel attack
patterns not in any current strategy, (c) S-effort first to keep
PR cadence high.

### Phase 3 -- Strategy implementation (~3-5 PRs, P1)

One PR per selected strategy. Standard add-strategy loop:

- New `<name>_fuzzer.py` in `dicom_fuzzer/attacks/format/` (or
  appropriate subpackage)
- `BaseFuzzer` subclass: `strategy_name`, `can_mutate`, `mutate`
- Tests in `tests/test_attacks/format/test_<name>_fuzzer.py`
- Register in `dicom_fuzzer/attacks/format/__init__.py` +
  `dicom_fuzzer/core/mutation/mutator.py::_register_default_strategies`
- Update strategy count in `tests/test_core/engine/test_generator.py`
- CHANGELOG entry under `### Added`

### Phase 4 -- fo-dicom file harness campaign (~1 day wall, P1)

Run a sustained campaign with the full strategy set (post-Phase 3)
against `examples/fodicom-file-harness/` (PR #276). This **folds
in the post-PR-346 validation** -- the campaign exercises the
rewrite-off default + `tsuid_mismatch` strategy and the file
harness gives us a non-Hermes crash channel. Cluster crashes by
stack signature. Filter for novel findings (not the CWE-674
recursion bomb we already know about).

Suggested command (`-c N` semantics: per-seed-file with `-r`):

```
dicom-fuzzer "C:\code-two\dicom-fuzzer\dicom-seeds" -r -c 45 \
  -o ./artifacts/campaigns/fodicom-file \
  -t "examples\fodicom-file-harness\bin\Release\net8.0\fodicom-file-harness.exe" \
  --timeout 30 --seed 12345
```

### Phase 5 -- fo-dicom network harness campaign (DONE 2026-06-07)

Plain DIMSE + TLS sweeps against the bundled harness on
fo-dicom 5.2.6 surfaced TWO novel code-quality findings, both with
root cause traced to upstream source. Both reported upstream
2026-06-07 as issue + PR pairs:

- **Finding A** -- `DicomServer.cs:327` `ContinueWith` never reads
  `t.Exception`, so every malformed-PDU disconnect leaks an unobserved
  Task. Default .NET 8 swallows it; `<ThrowUnobservedTaskExceptions>`
  hosts crash. Upstream: issue [fo-dicom#2148](https://github.com/fo-dicom/fo-dicom/issues/2148)
  - PR [fo-dicom#2149](https://github.com/fo-dicom/fo-dicom/pull/2149)
    (OPEN). Artifact: `artifacts/findings/fodicom_unobserved_pdu_20260607/`.
- **Finding B** -- `PDU.cs:185` `Pdu[type={Type:X2}, ...]` interpolates
  `RawPduType` enum with `X2` format spec, rejected by .NET 8's
  stricter `Enum.TryFormat`. Masks the intended `DicomNetworkException`
  from `CheckOffset` as a generic `FormatException`. One-line fix.
  Upstream: issue [fo-dicom#2146](https://github.com/fo-dicom/fo-dicom/issues/2146)
  - PR [fo-dicom#2147](https://github.com/fo-dicom/fo-dicom/pull/2147)
    (OPEN). Artifact: `artifacts/findings/fodicom_format_exception_pdu_20260607/`.

Neither is security-class (no DoS, no GHSA needed) -- mergeable as
code-quality PRs. Memory: `memory/fodicom_phase5_findings.md`.

Harness side-improvement (2026-06-07): `CStoreProvider.cs:OnConnectionClosed`
now uses `ExceptionDispatchInfo.Capture(e).Throw()` instead of `throw e`,
preserving the original stack through the bubble-up shim. Without this,
Finding B's actual fo-dicom call site was invisible.

### Phase 6 -- Per-finding upstream PR loop (ongoing, P1)

**First PR landed 2026-06-07** -- pydicom issue #2330 + PR #2331,
both OPEN at pydicom/pydicom. Adds `config.settings.max_sequence_depth`
(default 100) + a `_depth` counter threaded through the SQ-reader path
that raises `InvalidDicomError` instead of `RecursionError` on
adversarial input. See `memory/pydicom_disclosure_state.md`.

Loop for future findings:

1. Reproduce with minimal DICOM (delta-debug the seed +
   mutation chain).
2. Read upstream source to identify the failing parse / decode /
   negotiate path.
3. File GitHub issue at the target repo with: minimal repro
   file, stack trace, root-cause summary.
4. File fix PR (defensive bound check, explicit length validation,
   sane defaults, etc.). Match upstream's existing code style.
5. Track in `memory/<target>_disclosure_state.md`.

### Phase 7 -- pydicom natural-yield triage (parallel to 4-6, P1)

pydicom is already in our parse pipeline -- every fuzzed file is
loaded by pydicom before being passed to the target. Parse
exceptions are already captured in campaign artifacts. Phase 7
work:

1. Triage existing parse-exception logs from campaigns: which are
   _unintended_ pydicom bugs vs _intended_ well-formed rejections?
2. For unintended: minimal repro, file issue + PR at
   `pydicom/pydicom`.
3. Track in `artifacts/upstream/pydicom_prs.md`.

This is "free" velocity -- no extra harness, just better triage of
data we already have.

---

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

### Investigate the 8h-campaign memory-amplification candidate -- DONE (2026-05-21)

Reproduced, isolated, and disclosed. The `MemoryLimitExceeded`
case from the 8h campaign was a real CWE-770 finding with an
amplification ratio of ~4.4 million-to-one (6 KB input -> >25 GB
peak RAM). Minimum trigger is **two tags** on an otherwise valid
encapsulated DICOM file:

- `(0002,0010)` Transfer Syntax UID set to `1.2.840.10008.1.2.1`
  (Explicit VR Little Endian -- declares uncompressed)
- `(0028,0010)` Rows set to `0`

Pixel-data bytes left as encapsulated JPEG 2000 fragments. Each
mutation alone is harmless (~380 MB peak); the pair selects
Hermes's uncompressed pixel-data reader (mutation 1) and poisons
its sizing math (mutation 2). Verified deterministic across n=5
independent runs.

Disclosure package + repro file:
`artifacts/findings/cwe770_memory_amplification/disclosure/` (gitignored).
Disclosed to Hermes PM 2026-05-21 as courtesy notification (no fixed
timer, no CVE intent). **Fixed by vendor (2026-05-29 per user); no
CVE, no advisory, silent fix.**

### Validate post-PR-346 fuzzer -- FOLDED into Phase 4

This item is now subsumed by **Phase 4 (fo-dicom file harness
campaign)** of the Upstream-PR pipeline above. The post-PR-346
fuzzer (rewrite-off default + `tsuid_mismatch` strategy) is what
Phase 4 runs by default, against fo-dicom rather than Hermes,
since Hermes parse-crash findings are now out of scope. A Hermes
validation run is unnecessary -- the only signal that mattered
there (CWE-770 amplification) has been fixed by the vendor.

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
  on every Corrupted State Exception; pythonnet + vendored ClrMD
  DLL (committed under `_vendor/clrmd/`) symbolicate; Socorro-style
  hashing buckets matching crashes into one signature; cluster
  reports embed the top frames + primary / minor hashes. Truly
  zero-step: `uv tool install dicom-fuzzer` ships everything.
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
| CWE-770 amplification candidate isolated to 2-tag minimum trigger; courtesy disclosure to Hermes PM                  | (2026-05-21)                  |
| Drop default TSUID rewrite + add explicit tsuid_mismatch strategy (audit showed implicit rewrite inflated signal)    | #346                          |
| Ignore /scripts/ (formalise existing convention; one-off ad-hoc scripts dir)                                         | #347                          |
