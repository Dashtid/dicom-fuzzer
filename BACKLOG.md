# Backlog

Ideas pruned from the codebase that may be worth implementing later.
Items are roughly ordered by priority within each section.

---

## Active items

### MR modality-specific fuzzing

**Context:** SOP Class `1.2.840.10008.5.1.4.1.1.4`

MR is structurally similar to CT (pixel data, calibration), so existing
fuzzers have good baseline coverage. The gap is MR-specific acquisition
sequences and parameters.

**Attack surface:**

- **MR-specific sequences** (Enhanced MR IOD):
  `MREchoSequence`, `MRTimingAndRelatedParametersSequence`,
  `MRFOVGeometrySequence`, `MRModifierSequence`
- **Acquisition parameters**: `EchoTime` (0018,0081),
  `RepetitionTime` (0018,0080), `FlipAngle` (0018,1314),
  `InversionTime` (0018,0082), `MagneticFieldStrength` (0018,0087)
- **DiffusionBValue** / **DiffusionGradientDirection**: DWI/DTI processing

**Implementation:** Expand `DictionaryFuzzer.TAG_TO_DICTIONARY` with
MR-specific tags or add MR parameters to `CalibrationFuzzer`. Requires
MR seed files. Low-medium effort.

### Empirically validate mutation reweighting with per-strategy crash telemetry

**Context:** `dicom_fuzzer/core/session/fuzzing_session.py`,
`dicom_fuzzer/core/reporting/`, `dicom_fuzzer/attacks/format/`

Structural/content reweighting was applied (PR #188) and crash-by-strategy
telemetry added (PR #191). What remains: run campaigns against a real
target viewer and measure whether the reweighting increases crash rate.

**Experiment design (2026-03-30):**

Run A (baseline, pre-reweighting commit `f50c7d2`) vs Run B (HEAD) with
identical `--seed` and seed corpus. Same strategy selection sequence,
only intra-strategy method dispatch differs.

- **Seed corpus:** `C:\code-one\cybersecurity\dicom-seeds` (9 modalities)
- **Target:** MicroDicom (free, known CVE-2025-5943) with `--gui-mode`
- **Runs:** 500-1000 files/seed, `--seed 12345`, `--timeout 15`
- **Telemetry:** `session_<id>.json` has `crash_by_strategy`,
  `fuzzed_files[].mutations[].variant`, and all statistics
- **No code changes needed** -- existing infrastructure captures everything

**Success criteria:**

1. B has higher overall crash rate than A
2. Crash `variant` fields show structural methods dominating
3. No strategy regression (productive strategies in A still productive in B)

**Priority:** High -- closes the feedback loop on the reweighting work.
Blocked on: target viewer installation + ~10-45 hours of campaign runtime.

### Second-pass structural audit: DictionaryFuzzer and minor-offender fuzzers

**Context:** `dicom_fuzzer/attacks/format/dictionary_fuzzer.py`,
`sequence_fuzzer.py`, `reference_fuzzer.py`, `calibration_fuzzer.py`

The first-pass reweighting (PR #188) addressed the six highest-impact
fuzzers. A second pass is needed for:

- **DictionaryFuzzer** -- entire strategy is content (replaces values
  with plausible-but-wrong dictionary entries). Zero crash potential.
  Redesign as structural or remove from default pool.
- **SequenceFuzzer** -- `_mixed_encoding_sequence` and
  `_circular_reference_attack` are content/low-value
- **ReferenceFuzzer** -- `_orphan_reference`, `_reference_type_mismatch`,
  `_mismatched_study_reference` are low-value
- **CalibrationFuzzer** -- `fuzz_slice_thickness` is content

**Priority:** Medium. Complete after empirical validation confirms the
first-pass reweighting improved crash rates.

### Build unique-crash-over-time curve (crash discovery saturation)

**Context:** `dicom_fuzzer/core/crash/crash_analyzer.py`,
`dicom_fuzzer/core/analytics/`

After a fuzzing campaign, the operator needs to prove diminishing
returns -- that the unique crash discovery rate has plateaued. The
plateau proof is more convincing than raw case counts for FDA
submissions.

**What needs to be built:**

1. `crash_timeline` in `CrashAnalyzer` -- append `(datetime, count)`
   when `is_unique_crash()` returns True
2. `TrendAnalysis` dataclass in `campaign_analytics.py`
3. `plot_crash_trend()` in `visualization.py`
4. Wire at campaign end

Medium effort. All net-new code.

### Surface MultiFrameMutationRecord details in campaign reports

All 10 multiframe strategies are now registered in `DicomMutator` and
fire during standard campaigns. However, `_mutate_impl()` returns
per-frame detail records that the public `mutate()` wrapper discards.

**Work items:**

- Extend `MutationRecord` with optional `frame_mutations: list[MultiFrameMutationRecord]`
- Surface frame-level details in session JSON and HTML reports
- The `MultiFrameMutationRecord` class already exists with `to_dict()`

Medium effort. Now actionable since multiframe dispatch is live.

---

## Low priority / deferred

### Enforce structural/content classification as code comments

Add `# [STRUCTURAL]` or `# [CONTENT]` tags on method lines in each
fuzzer's `mutate()` dispatch list. Pure documentation, do as part of
future fuzzer modifications.

### Review CrashAnalyzer's role for black-box fuzzing

`CrashAnalyzer` handles Python exceptions, not process-level crashes.
Consider renaming to `ExceptionAnalyzer` and evaluating whether internal
exceptions should flow through the same triage pipeline as process
crashes. Naming/architecture discussion, no functional impact.

### Investigate test_files_are_valid_dicom flakiness under load

**Location:** `tests/test_core/engine/test_generator.py::TestFileSaving::test_files_are_valid_dicom`

Fails intermittently under parallelism or high load. Passes consistently
in isolation. Documented in PR #193. Low priority unless failure rate
increases.

### Wire strategy effectiveness into CampaignAnalyzer and FuzzingVisualizer

`CampaignAnalyzer.analyze_strategy_effectiveness()` and
`FuzzingVisualizer.plot_strategy_effectiveness()` exist but are never
called from the campaign pipeline. The simple text-table + JSON path
(PR #191) already answers the FDA question. Full analytics pipeline
wiring is future work.

### Series attacks: investigate before wiring into campaign pipeline

The series attack module operates on file lists, not single datasets.
Used by `study-campaign` command but not wired into the main
single-file fuzzing pipeline. Requires design work before integration.

### End-of-campaign auto-triage

`dicom-fuzzer triage` CLI exists. Follow-on: call it automatically at
campaign end. Needs decision on hook point (CampaignRunner session-close
vs. CLI layer).

---

## Long-term vision

### Full DICOM SOP Class coverage

186 active Storage SOP Class UIDs across ~17 domains. Current: 19
format fuzzers + 10 multiframe strategies = 29 total. Full coverage
would require ~40-44 total fuzzers. Roughly 10-14 weeks of focused
work; diminishing returns past ~30 fuzzers.

### Add coverage-guided fuzzing

The project is a pure black-box mutation fuzzer. No feedback loop, no
seed selection, no coverage tracking. Adding coverage-guided fuzzing
requires instrumenting the target (DynamoRIO/Frida/SanCov), feeding
coverage back, and implementing seed selection. Major architectural
change.

---

## Completed (reference only)

| Item                                                           | PR(s)                                                                                                                                                                                        |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Audit mutations for crash potential (structural/content split) | #188, #198                                                                                                                                                                                   |
| Formalize variant terminology + replay --decompose             | #195, #184, #197                                                                                                                                                                             |
| Re-encode pixel data (PixelReencodingFuzzer)                   | #204                                                                                                                                                                                         |
| Attack mode / scope filtering (--target-type)                  | #205                                                                                                                                                                                         |
| Move mutate_patient_info to utils/anonymizer.py                | #201                                                                                                                                                                                         |
| Centralize attack payloads in dicom_dictionaries               | #194                                                                                                                                                                                         |
| Seed corpus diversification (SEG, RTSS, PDF)                   | #206                                                                                                                                                                                         |
| Unify reporting CSS/HTML systems                               | #200                                                                                                                                                                                         |
| Make reports minimalistic and professional                     | #200 (CSS cleaned up)                                                                                                                                                                        |
| Consolidate crash data types (CrashRecord)                     | #203                                                                                                                                                                                         |
| Add can_mutate() guards to multiframe strategies               | #202                                                                                                                                                                                         |
| Register multiframe strategies in DicomMutator dispatch        | (all 10 registered)                                                                                                                                                                          |
| Track binary mutations in MutationRecord                       | #197                                                                                                                                                                                         |
| Seed fuzzer engine + log RNG seed                              | #184, #185                                                                                                                                                                                   |
| crash_by_strategy telemetry                                    | #191                                                                                                                                                                                         |
| Structural mutation reweighting                                | #188                                                                                                                                                                                         |
| Merge/disambiguate corpus_minimization vs corpus_minimizer     | (corpus_minimizer.py deleted)                                                                                                                                                                |
| CrashRecord.reproduction_command always None                   | (conditionally populated now)                                                                                                                                                                |
| Pre-mutation safety checks (--safety-mode)                     | #209                                                                                                                                                                                         |
| Seed file sanitization (dicom-fuzzer sanitize)                 | #210                                                                                                                                                                                         |
| Seed corpus diversification (MR, DX, NM, PT, RTDOSE, RTSTRUCT) | (seed corpus populated)                                                                                                                                                                      |
| Mutation taxonomy (boundary/malformed/injection)               | Dropped -- research showed static family-first selection is neutral-to-harmful vs uniform random (MOPT, DARWIN). Not required by FDA/IEC 81001-5-1. Method names already communicate intent. |
