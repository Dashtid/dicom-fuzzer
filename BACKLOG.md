# Backlog

Ideas pruned from the codebase that may be worth implementing later.
Items are roughly ordered by priority within each section.

---

## Active items

### Pre-mutation safety checks

**Removed from:** `dicom_fuzzer/core/mutation/mutator.py`

The mutator had stub infrastructure for pre-mutation safety checks:

- `_is_safe_to_mutate()` method (always returned True)
- `preserve_critical_elements` config key
- `safety_checks` config key

The idea: before applying a mutation, check whether the target tag is
"critical" (e.g. SOPClassUID needed for file identification) and skip
mutations that would make the file completely unreadable. This would
let you tune between "maximally aggressive" and "realistic corruption"
fuzzing modes.

Worth implementing if we find that too many fuzzed files are rejected
at the file-open stage before reaching deeper parser code paths.

### Seed file sanitization

**Context:** `dicom_fuzzer/core/engine/` and `dicom_fuzzer/core/corpus/`

Seed DICOM files may contain real patient data (PHI/PII). The fuzzer
should have built-in sanitization that strips or replaces identifiable
metadata before using seed files in a campaign.

Patient anonymization was extracted to `dicom_fuzzer/utils/anonymizer.py`
(PR #201). What remains: a standalone CLI subcommand
(`dicom-fuzzer sanitize <seed-dir>`) that uses `anonymize_patient_info()`
to strip PHI from seed files before they enter the corpus.

### Seed corpus diversification (medium/low priority remaining)

**Context:** `dicom_fuzzer/core/corpus/` and engine pipeline

High-priority synthetic seeds (SEG, RTSS, Encapsulated PDF) are done
(PR #206). Remaining:

2. **Medium**: MR, DX, US seeds -- incrementally better coverage of
   modality-specific tags with existing fuzzers.
3. **Low**: SR (Structured Report), Presentation State seeds -- niche
   SOP Classes, lower priority unless the target viewer handles them.

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
telemetry added (PR #191). What remains: run campaigns and measure whether
the reweighting actually increases crash rate per CPU-hour.

**Work items:**

1. Run a baseline campaign (e.g., 10,000 files) and review per-strategy
   crash distribution from `session_<id>.json`
2. If content-heavy strategies (MetadataFuzzer, EncodingFuzzer) produce
   zero crashes, consider removing their content pools entirely
3. If high-potential structural methods also produce zero crashes,
   reclassify and downweight

**Priority:** High -- closes the feedback loop on the reweighting work.

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

### Establish a consistent mutation taxonomy across all fuzzers

**Location:** `dicom_fuzzer/attacks/format/` (all fuzzers)

**Prerequisite:** Centralize payloads is done (PR #194). Taxonomy can
now be applied to the centralized payloads.

**Status:** `metadata_fuzzer.py`'s `_random_pn_attack()` already
implements the three-family pattern. Remaining: apply it to the 12
fuzzers that still mix families.

**Proposed three-family taxonomy:**

- **Boundary**: Empty strings, max-length violations, zero/negative
  numerics, NaN, infinity, impossible dates
- **Malformed**: Null bytes, wrong character set, missing separators,
  invalid encoding sequences
- **Injection**: SQL, XSS, path traversal, Log4Shell, ANSI escapes

**Heavy mixing (all three families entangled):** structure_fuzzer,
header_fuzzer, encoding_fuzzer, sequence_fuzzer, private_tag_fuzzer,
rt_dose_fuzzer, rtss_fuzzer, seg_fuzzer, nm_fuzzer, pet_fuzzer,
encapsulated_pdf_fuzzer, calibration_fuzzer

**Already focused (no change needed):** pixel_fuzzer,
compressed_pixel_fuzzer, reference_fuzzer, uid_attacks, dictionary_fuzzer,
metadata_fuzzer

Large effort overall but can be done incrementally per-fuzzer.

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

| Item                                                           | PR(s)                         |
| -------------------------------------------------------------- | ----------------------------- |
| Audit mutations for crash potential (structural/content split) | #188, #198                    |
| Formalize variant terminology + replay --decompose             | #195, #184, #197              |
| Re-encode pixel data (PixelReencodingFuzzer)                   | #204                          |
| Attack mode / scope filtering (--target-type)                  | #205                          |
| Move mutate_patient_info to utils/anonymizer.py                | #201                          |
| Centralize attack payloads in dicom_dictionaries               | #194                          |
| Seed corpus diversification (SEG, RTSS, PDF)                   | #206                          |
| Unify reporting CSS/HTML systems                               | #200                          |
| Make reports minimalistic and professional                     | #200 (CSS cleaned up)         |
| Consolidate crash data types (CrashRecord)                     | #203                          |
| Add can_mutate() guards to multiframe strategies               | #202                          |
| Register multiframe strategies in DicomMutator dispatch        | (all 10 registered)           |
| Track binary mutations in MutationRecord                       | #197                          |
| Seed fuzzer engine + log RNG seed                              | #184, #185                    |
| crash_by_strategy telemetry                                    | #191                          |
| Structural mutation reweighting                                | #188                          |
| Merge/disambiguate corpus_minimization vs corpus_minimizer     | (corpus_minimizer.py deleted) |
| CrashRecord.reproduction_command always None                   | (conditionally populated now) |
