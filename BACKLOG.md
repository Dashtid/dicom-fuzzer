# Backlog

Ideas pruned from the codebase that may be worth implementing later.

## All fuzzers: Audit mutations for crash potential vs. noise

**Location:** `dicom_fuzzer/attacks/format/` (all fuzzers)

Not all mutations are equal. There is a meaningful distinction between mutations that
produce _noise_ (corrupt data a parser handles gracefully) and mutations that produce
_parser-breaking inputs_ (force allocation failures, integer overflows, state machine
violations, or unguarded code paths).

The only confirmed crash so far came from intense sequence nesting — a structural attack,
not a content one. This pattern warrants a systematic review of every fuzzer.

**Investigation goal:** For each fuzzer, classify every mutation method as either:

- **Structural** — attacks parser logic, size calculations, state machines, or allocation
  (high crash potential)
- **Content** — corrupts data values the parser has already successfully read and allocated
  for (low crash potential; parsers are hardened against this)

Mutations in the content category should be deprioritized, weighted lower in the sampling
pool, or replaced with structural equivalents where possible.

**Work items:**

- Enumerate all mutation methods across every fuzzer in `attacks/format/`
- Classify each as structural vs. content using the above definition
- For each content mutation, assess whether a structural equivalent exists or could be designed
- Produce a prioritized list of high-value mutations and low-value ones to cut or downweight

## pixel_fuzzer.py: Deprioritize content mutations, strengthen structural ones

**Location:** `dicom_fuzzer/attacks/format/pixel_fuzzer.py`

The byte-level pixel content mutations (`_pixel_data_byte_flip`, `_pixel_data_fill_pattern`,
`_pixel_data_random_garbage`) have low crash probability because modern image codecs are built
to degrade gracefully on corrupt pixel bytes — they render garbage or raise a handled decode
error rather than crashing.

The high-value mutations are the ones that attack _allocation math_ and _cross-field
consistency_ — where the parser trusts DICOM metadata to calculate buffer sizes without
validation:

- `_dimension_mismatch` with `extreme_dimensions` (e.g. `Rows=4294967295`) forces a
  multi-terabyte allocation calculation — crash surface is at the allocation site, not decode.
- `_bit_depth_attack` with `extreme_bits` similarly corrupts the bytes-per-pixel multiplier.
- Multi-field contradictions (e.g. `SamplesPerPixel=3`, `PhotometricInterpretation=MONOCHROME2`,
  `BitsAllocated=128`, `Rows=65535` applied simultaneously) are stronger than single-field
  attacks because they force impossible code paths the parser never validates.

**Work items:**

- Consider removing or deprioritizing `_pixel_data_byte_flip` and `_pixel_data_fill_pattern`
  from the mutation pool, or weighting them much lower.
- Add a combined "extreme contradiction" mutation that sets multiple conflicting fields
  simultaneously rather than picking one at a time.
- `extreme_dimensions` and `extreme_bits` should be the primary crash vectors; `rows_larger`
  (10x multiplier) is weaker than just setting `Rows=65535`.

## pixel_fuzzer.py: Missing tag attacks

**Location:** `dicom_fuzzer/attacks/format/pixel_fuzzer.py`

Several pixel-related tags that can cause crashes or rendering failures are not covered:

- **PixelRepresentation** (0028,0103): 0=unsigned, 1=signed two's complement. Setting
  this to 1 on a file with 0=unsigned data (or vice versa) causes display inversion or
  sign-extension misreads. Set to invalid values (2, 255) to test parser robustness.
- **NumberOfFrames** mismatch: Declare N frames but supply pixel data for only 1 (or
  declare 1 but supply data for N). Multi-frame viewers are especially susceptible.
- **SmallestImagePixelValue / LargestImagePixelValue**: Set range wider than actual data,
  narrower than actual, or inverted (Smallest > Largest). Affects auto-windowing logic.
- **RescaleSlope / RescaleIntercept**: Set slope to 0, NaN, Inf, or very large values.
  Affects CT/modality LUT transforms. NaN/Inf specifically crash floating-point display
  pipelines.
- **WindowCenter / WindowWidth**: Set Width to 0 or negative (divide-by-zero in
  windowing formula). Set Center and Width combinations that result in empty display range.

## Formalize variant terminology and add crash replay capability

**Location:** `dicom_fuzzer/attacks/format/` (all fuzzers), `dicom_fuzzer/core/engine/generator.py`, `dicom_fuzzer/core/mutation/mutator.py`, `dicom_fuzzer/core/session/fuzzing_session.py`

**Investigation findings (2026-03-16):**

The engine already produces two per-session artifacts:

- `mutation_map.json` (output dir): maps filename → strategy name only
- `session_<id>.json` (`artifacts/reports/json/`): full `MutationRecord` per file with
  strategy name, mutation type, target DICOM tag, original value, mutated value

What is NOT tracked:

- The **variant** (the inner `random.choice` result inside each mutation method, e.g.
  `"bits_stored_greater"`) — chosen and discarded with no log entry
- **Binary-level mutations** from `mutate_bytes()` — applied after serialization,
  completely untracked
- **RNG state** — `DicomMutator` / `DICOMGenerator` never call `random.seed()` and
  record no seed. Series/Study mutators have an optional `seed` param but don't log it.
  No `--seed` CLI flag exists.

This is why a viewer crash is hard to reproduce: you can identify the strategy and
mutation type from `session_<id>.json`, but not the variant, and you cannot rerun the
RNG sequence deterministically.

**Work items in dependency order:**

1. **Add variant to MutationRecord** (`fuzzing_session.py`): Add `variant: str | None`
   field to the `MutationRecord` dataclass in `fuzzing_session.py:31` (note: there are
   two classes named `MutationRecord` — `mutator.py:34` has 6 fields and is for internal
   tracking, `fuzzing_session.py:31` has 8 fields and writes to session JSON; the variant
   belongs in the latter). Each mutation method should return (or pass back) the variant
   string it chose. `generator.py` captures it into the record. This alone solves the
   immediate debugging pain — session JSON already lands on disk per run.

2. **Add `replay --decompose` CLI subcommand** (depends on item 1): No replay command
   exists today — this is net-new. Add `dicom-fuzzer replay --decompose <fuzzed_file.dcm>`.
   Given a crashed fuzzed file, it reads its `MutationRecord` entries from
   `session_<id>.json`, then re-applies each mutation in isolation against the original
   clean input — producing N output files, one per mutation/variant combination. Naming:
   `<original>_mut0_<strategy>_<type>_<variant>.dcm`. Load each in the viewer to find
   the crash-causing mutation without manual bisection. This is standard delta-debugging.
   Note: without item 1, decompose can only isolate to mutation-type level, not variant.
   Also: `CrashRecord` already has a `reproduction_command: str | None` field (currently
   always `None`) — populate this during decompose so crashes are self-documenting.

3. **Seed the format fuzzer engine + log the seed**: Add `seed: int | None` param to
   `DICOMGenerator.__init__()` and `DicomMutator`. Call `random.seed(seed)` at init.
   Write the seed into `session_<id>.json` and `mutation_map.json`. Add `--seed INT`
   CLI flag. With seed + variant logged, a crash is fully reproducible: pass `--seed`
   and the engine recreates the exact RNG sequence.

4. **Track binary mutations**: `mutate_bytes()` currently returns modified bytes with no
   record. Add a `binary_mutations: list[str]` field to `MutationRecord` or a separate
   record, populated by strategies that override `mutate_bytes()`.

Also worth auditing: whether the 1-2 mutation types per file (`k=random.randint(1, 2)`)
is consistent across all fuzzers. The count is intentional for throughput during
overnight batch runs (not a bug), but the policy is undocumented and may vary per fuzzer.

## Export CrashTriageEngine and add CLI triage subcommand

**Location:** `dicom_fuzzer/core/crash/crash_triage.py`, `dicom_fuzzer/core/crash/__init__.py`

**Investigation findings (2026-03-17):**

`CrashTriageEngine` (480 lines: exploitability rating, priority scoring, actionable
recommendations) is NOT orphaned — it IS used in production. `enhanced_reporter.py` and
`enrichers.py` import it directly from `crash_triage.py`. It works.

The real issues:

1. **Not in the package API**: `crash/__init__.py` does not export `CrashTriageEngine` or
   `CrashTriage`. Callers bypass the package interface, creating a hidden dependency.
2. **No CLI entry point**: triage is only reachable via the reporting layer, not directly.
3. **Minimization stub**: the engine recommends "minimize test case" but no minimization
   code backs this recommendation.

**Work items:**

- Export `CrashTriageEngine` and `CrashTriage` from `crash/__init__.py`
- Add a `dicom-fuzzer triage` CLI subcommand that accepts a crash report JSON and prints
  exploitability rating, priority score, and recommendations
- Optionally fold into the `replay` subcommand (from "Formalize variant terminology")
  as `replay --triage`
- Implement or stub the minimization path so the recommendation is actionable

Low-medium effort. The core logic exists and works — this is plumbing and CLI wiring only.

## Re-encode pixel data to match mutated TransferSyntaxUID

**Context:** `dicom_fuzzer/attacks/format/compressed_pixel_fuzzer.py`,
`dicom_fuzzer/attacks/format/conformance_fuzzer.py`,
`dicom_fuzzer/attacks/format/dictionary_fuzzer.py`

When fuzzers swap the `TransferSyntaxUID` tag (e.g., Implicit VR LE to
JPEG Baseline), the actual pixel data is NOT re-encoded. The output file
claims a compressed transfer syntax but contains raw uncompressed pixels.
This is intentional for mismatch testing, but it does not exercise the
viewer's actual JPEG/JPEG2000/RLE decoders with valid compressed streams.

### What's needed

A new strategy (or extension to `CompressedPixelFuzzer`) that:

1. Takes the seed's real pixel data (from `dataset.PixelData`)
2. Compresses it using the target transfer syntax:
   - JPEG Baseline/Extended: via `Pillow` or `pylibjpeg`
   - JPEG 2000: via `openjpeg` / `pylibjpeg-openjpeg`
   - RLE Lossless: via pydicom's built-in RLE encoder
3. Sets `TransferSyntaxUID` to match the actual encoding
4. Then applies the existing corruption strategies (marker corruption,
   dimension mismatch, truncation, etc.) to the real compressed output

This produces files with structurally valid compressed bitstreams that
have been fuzzed -- exercising the decoder's error recovery paths rather
than just the "wrong syntax" rejection path.

### Complexity

- Must handle varying `BitsAllocated` (8/12/16), `SamplesPerPixel`
  (1 for grayscale, 3 for RGB), and `PhotometricInterpretation`
  (MONOCHROME1/2, RGB, YBR_FULL) combinations correctly
- JPEG Baseline only supports 8-bit; JPEG Extended supports 12-bit;
  JPEG 2000 and RLE support 16-bit -- need encoding path per syntax
- Pillow cannot encode 16-bit JPEG; need `pylibjpeg` or raw encoding
- Multi-frame images need per-frame compression + encapsulation

### Effort estimate

Medium. ~150-200 lines of code. The tricky part is handling the
BitsAllocated/PhotometricInterpretation matrix correctly. The existing
`CompressedPixelFuzzer` already builds synthetic compressed frames, so
the encapsulation and corruption infrastructure is in place.

### Priority

Medium-low. The existing synthetic bitstreams already test the important
attack surface (malformed markers, dimension mismatches, truncation).
Real re-encoding matters more for testing decoder happy-path robustness,
which is valuable but secondary to structural fuzzing.

## Pre-mutation safety checks

**Removed from:** `dicom_fuzzer/core/mutation/mutator.py`
**Removed in commit:** (fill in after commit)

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

## Seed file sanitization

**Context:** `dicom_fuzzer/core/engine/` and `dicom_fuzzer/core/corpus/`

Seed DICOM files may contain real patient data (PHI/PII). The fuzzer
should have built-in sanitization that strips or replaces identifiable
metadata before using seed files in a campaign. This would prevent
accidental inclusion of real patient data in fuzzed output, crash
reports, or logs.

Could be a pre-processing step in the engine or a standalone CLI
subcommand (`dicom-fuzzer sanitize <seed-dir>`).

## Attack mode / scope filtering

**Context:** `dicom_fuzzer/attacks/format/metadata_fuzzer.py` and others

Many attack payloads target specific application architectures:

- SQL injection payloads are irrelevant for standalone desktop viewers
- XSS payloads are irrelevant for non-web applications
- JNDI/Log4Shell payloads target Java logging frameworks

A CLI option like `--target-type viewer|web|pacs` (or similar) could
filter attack payloads to match the actual target architecture. This
would make fuzzing runs more focused and reports more relevant for
FDA submissions where you need to explain every finding.

The injection payloads are still worth keeping even for desktop viewers
(they can trigger buffer overflows, format string bugs, or logging
issues), but having the option to scope them would be valuable.

## Move mutate_patient_info out of MetadataFuzzer

**Context:** `dicom_fuzzer/attacks/format/metadata_fuzzer.py`

`MetadataFuzzer.mutate_patient_info()` generates realistic fake patient
data (anonymization). It is not a fuzzing attack -- it replaces fields
with valid-looking data from `fake_names` and `fake_ids` lists.

It has 25 call sites (all in test files, zero production callers), so moving it is
low-risk. A natural home would be a dedicated anonymization utility (e.g.
`dicom_fuzzer/utils/anonymizer.py`) or a data generation helper. Worth doing when
building a proper anonymization module.

## Centralize attack payloads in dicom_dictionaries

**Context:** `dicom_fuzzer/attacks/format/` (8+ files affected)

Generic attack payloads (SQL injection, XSS, command injection, format
strings, path traversal, buffer overflow strings, integer overflow values)
are duplicated across multiple fuzzer files instead of being sourced from
the central `dicom_dictionaries.py` module.

### Scope of duplication

Exact-match duplicates found:

| Payload                         | Duplicated in                                                                                   |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| `"'; DROP TABLE patients; --"`  | `dicom_dictionaries`, `metadata_fuzzer`, `private_tag_fuzzer`                                   |
| `"%s%s%s%s%s%s%s%s%s%s"`        | `metadata_fuzzer`, `private_tag_fuzzer`                                                         |
| `"<script>alert(...)</script>"` | `dicom_dictionaries`, `metadata_fuzzer`, `private_tag_fuzzer`, `sequence_fuzzer`                |
| `"../../etc/passwd"`            | `dicom_dictionaries`, `metadata_fuzzer`, `private_tag_fuzzer`                                   |
| `"; ls -la"`, `"$(whoami)"`     | `dicom_dictionaries`, `metadata_fuzzer`, `private_tag_fuzzer`                                   |
| `2147483647`, `4294967295`      | `dicom_dictionaries`, `header_fuzzer`, `calibration_fuzzer`, `pixel_fuzzer`, `structure_fuzzer` |
| `"A" * N` (various lengths)     | 6+ files                                                                                        |
| Null bytes                      | 8+ files, 15+ locations                                                                         |

Additionally, `encoding_fuzzer.py` has its own `VALID_CHARSETS` /
`INVALID_CHARSETS` lists that overlap with `CHARACTER_SETS` in
`dicom_dictionaries.py`, and `conformance_fuzzer.py` has its own
`TRANSFER_SYNTAXES` dict duplicating the same list.

### What to centralize

**Generic payloads** (not VR-aware, just strings):

- SQL injection, XSS, command injection, format strings, path traversal
- Buffer overflow strings (`"A" * 64`, `"A" * 256`, `"A" * 1024`, etc.)
- Integer overflow values (`2147483647`, `4294967295`, `65535`, `-1`)
- Null byte variants (`"\x00"`, `"text\x00text"`, `"\x00" * N`)
- Empty strings (as a constant, not hardcoded `""` everywhere)

`dicom_dictionaries.py` already has `get_edge_cases()` and
`get_malicious_values()` with most of these -- the problem is that
no fuzzer actually calls them. Each fuzzer hardcodes its own copies.

### What to keep local

**VR-specific mutations** in `header_fuzzer.py`'s `VR_MUTATIONS` dict
map invalid values to specific VR types (DA, TM, PN, IS, DS, etc.).
These are context-aware and belong in the fuzzer that understands VRs.

**Domain-specific constants** like `KNOWN_CREATORS` in
`private_tag_fuzzer.py` or JPEG markers in `compressed_pixel_fuzzer.py`
are unique to their fuzzers and do not overlap.

### Implementation approach

1. Expand `dicom_dictionaries.py` constants to cover all generic payloads
   currently scattered across fuzzers
2. Update each fuzzer to import from `dicom_dictionaries` instead of
   defining inline lists
3. Remove the now-redundant inline definitions
4. Verify no test assertions break (tests may assert specific values)

Touches 8+ files, ~200+ lines. Medium effort, low risk.

### Benefits

- Single place to add new payloads (add once, every fuzzer gets it)
- No drift between "same" payloads that are subtly different across files
- Easier auditing for FDA submissions (one module lists all attack vectors)
- Enables the "attack mode / scope filtering" backlog item (filter by
  category at the source instead of in each fuzzer)

## Seed corpus diversification

**Context:** `dicom_fuzzer/core/corpus/` and engine pipeline

The current corpus uses CT image seeds. The existing generic fuzzers
(HeaderFuzzer, MetadataFuzzer, PixelFuzzer, etc.) work on any image
modality because they target shared DICOM structures. However:

### Why more seed types matter

- **Modality-specific tags**: MR seeds have EchoTime, RepetitionTime,
  MagneticFieldStrength. DX seeds have ExposureInuAs, DistanceSource
  ToDetector. US seeds have MechanicalIndex, ThermalIndex. These tags
  are absent from CT seeds, so VR-scanning fuzzers never discover them.
- **Different pixel formats**: US images are often RGB (SamplesPerPixel=3),
  MR can be multi-frame, DX is typically high-resolution single-frame.
  Each exercises different pixel parsing paths.
- **Specialized SOP Classes**: SEG, RTSS, Encapsulated PDF, Structured
  Reports, Presentation States -- these have entirely different internal
  structures that need matching seed files. Generic fuzzers still apply
  (they have metadata too), but specialized fuzzers need correct seeds
  to be effective.

### Priority

1. **High**: SEG, RTSS, Encapsulated PDF seeds -- these unlock entirely
   new attack surfaces that CT seeds cannot reach.
2. **Medium**: MR, DX, US seeds -- incrementally better coverage of
   modality-specific tags with existing fuzzers.
3. **Low**: SR (Structured Report), Presentation State seeds -- niche
   SOP Classes, lower priority unless the target viewer handles them.

### Routing mechanism

Already supported: `FormatFuzzerBase.can_mutate(dataset)` lets each
fuzzer self-select based on SOPClassUID. The engine offers every seed
to every fuzzer; specialized fuzzers skip seeds they don't understand.
No engine changes needed.

## Expand DictionaryFuzzer TAG_TO_DICTIONARY for CS VR tags

**Context:** `dicom_fuzzer/attacks/format/dictionary_fuzzer.py`

`TAG_TO_DICTIONARY` currently maps 18 tags to value dictionaries.
DICOM PS3.6 defines ~4,000+ tags total. The biggest gap is CS
(Code String) tags -- there are ~300 of them, each with an enumerated
set of valid values (e.g., ImageType: ORIGINAL/DERIVED/PRIMARY/SECONDARY,
BodyPartExamined: HEAD/CHEST/ABDOMEN, Laterality: L/R, etc.).

Currently, CS tags not in `TAG_TO_DICTIONARY` fall through to the
random-dictionary fallback (line 251), which picks a value from an
unrelated dictionary. This produces obviously invalid data (a date
string in a laterality field) rather than plausible-but-wrong data
(R in a field that should be L for this study).

### What to add

Priority CS tags with enumerated values worth mapping:

- `ImageType` (0008,0008): ORIGINAL, DERIVED, PRIMARY, SECONDARY, etc.
- `BodyPartExamined` (0018,0015): HEAD, CHEST, ABDOMEN, PELVIS, etc.
- `Laterality` (0020,0060): L, R
- `PatientPosition` (0018,5100): HFS, HFP, FFS, FFP, etc.
- `ConversionType` (0008,0064): DV, DI, DF, WSD, SD, SI, etc.
- `PresentationIntentType` (0008,0068): FOR PROCESSING, FOR PRESENTATION
- `LossyImageCompression` (0028,2110): 00, 01

Also, DA/TM/PN tags beyond the 2 dates and 2 times currently mapped:

- `ContentDate` (0008,0023), `AcquisitionDate` (0008,0022)
- `ContentTime` (0008,0033), `AcquisitionTime` (0008,0032)
- `ReferringPhysicianName` (0008,0090), `PerformingPhysicianName` (0008,1050)

### Implementation approach

Two options:

1. **Manual expansion**: Add ~20-30 high-value CS tags with curated value
   lists in `dicom_dictionaries.py`. Straightforward, easy to audit for
   FDA submissions.
2. **Runtime VR detection**: Use pydicom's data dictionary at runtime to
   detect CS VR tags and apply generic CS mutations (wrong case, wrong
   length, unknown codes). More coverage, less precision.

Option 1 is recommended as a first step. Option 2 could supplement later.

Medium effort, low risk.

## Unify reporting CSS/HTML systems

**Location:** `dicom_fuzzer/core/reporting/html_templates.py`,
`dicom_fuzzer/core/reporting/series_reporter.py`

Two independent CSS/HTML systems produce reports with different fonts,
colors, container widths, and class names:

- **Main reports** (`html_templates.py` REPORT_CSS): Segoe UI, purple
  gradient body, 1400px container, gradient stat cards, hover animations
- **Series3D reports** (`series_reporter.py` inline CSS): -apple-system,
  white body, 1200px container, flat stat cards, no animations

No shared design tokens. Each system defines its own color palette,
spacing, and typography independently.

**Fix:** Extract a single shared CSS file or constant. Both report
generators should reference the same design system. The series reporter's
120 lines of inline CSS should import from html_templates.py or a shared
module.

## Make reports minimalistic and professional

**Location:** `dicom_fuzzer/core/reporting/html_templates.py` (REPORT_CSS),
`dicom_fuzzer/core/reporting/series_reporter.py` (inline CSS)

Current styling is flashy rather than professional:

- Purple gradient body background (`linear-gradient(135deg, #667eea, #764ba2)`)
- Hover animations on stat cards (`transform: translateY(-5px)`)
- Gradient stat cards with heavy box shadows (`0 20px 60px`)
- Giant 3em stat values
- Gradient table headers
- `[+]` CLI-style text prefixes in HTML headings
- 2em icon text in alert/status boxes

**Fix:** Replace with clean, flat styling: white/light gray backgrounds,
subtle borders instead of shadows, standard-sized text, no animations,
no gradients. Professional enough for FDA submission attachments.

## MR modality-specific fuzzing

**Context:** SOP Class `1.2.840.10008.5.1.4.1.1.4` -- MR-specific
sequences and acquisition parameters not covered.

MR is structurally similar to CT (pixel data, calibration), so existing
fuzzers have good baseline coverage. The gap is MR-specific acquisition
sequences and parameters.

### Attack surface

- **MR-specific sequences** (Enhanced MR IOD):
  `MREchoSequence`, `MRTimingAndRelatedParametersSequence`,
  `MRFOVGeometrySequence`, `MRModifierSequence` -- present in Enhanced
  MR (multi-frame) objects. Not in standard MR Image Storage unless
  explicitly added.
- **Acquisition parameters**: `EchoTime` (0018,0081),
  `RepetitionTime` (0018,0080), `FlipAngle` (0018,1314),
  `InversionTime` (0018,0082), `MagneticFieldStrength` (0018,0087) --
  numeric DS values not in any attack dictionary. Invalid ranges
  (negative echo time, zero field strength) test viewer robustness.
- **DiffusionBValue** / **DiffusionGradientDirection**: Present in
  diffusion-weighted MR. Corruption tests DWI/DTI processing.
- **RescaleSlope/Intercept**: Present in some MR but meaning differs
  from CT (no Hounsfield Units). `CalibrationFuzzer` applies but its
  CT-HU-specific extreme values may not exercise MR-specific paths.

### Priority

Lower than NM/PET/RT Dose because MR's pixel structure is identical
to CT and existing fuzzers cover the core attack surface. The gaps
are incremental rather than fundamental.

### Implementation

Expand `DictionaryFuzzer.TAG_TO_DICTIONARY` with MR-specific tags
and values rather than creating a dedicated fuzzer. Or add MR
parameters to `CalibrationFuzzer` attack methods. Requires MR seed
files.

Low-medium effort. Requires MR seed file in corpus.

## Full DICOM SOP Class coverage (long-term vision)

**Context:** The DICOM standard defines 186 active Storage SOP Class UIDs
across ~17 domains (RT, SR, ophthalmology, waveform, pathology, etc.).
The current 12 generic fuzzers cover structural mutations applicable to
all SOP Classes. The 6 modality-specific stubs (SEG, RTSS, Encapsulated
PDF, NM, PET, RT Dose) target the viewer's accepted SOP Classes.

Full coverage would require ~28-32 modality-specific fuzzers (SOP Classes
within a domain share IOD structure, so it's fuzzer-per-domain not
fuzzer-per-SOP-Class), plus the existing 12 generic fuzzers, for a total
of ~40-44 fuzzers.

### Domains not yet covered

- Enhanced Multi-frame (CT/MR/PET/XA) -- shared/per-frame functional groups
- Structured Reporting / Key Object Selection -- recursive tree content
- Waveform / ECG / Physiology -- channel-multiplexed sample data
- Whole Slide Microscopy / Pathology -- tiled pyramidal, millions of frames
- Mammography / Breast Imaging -- CAD SR templates, tomosynthesis
- Ultrasound / Photoacoustic -- multi-frame cine loops
- Presentation State (12 SOP Classes) -- display pipeline parameters
- RT Plan / RT Record family (beyond RT Dose) -- deeply nested beam sequences
- Ophthalmology (19 SOP Classes) -- OCT, perimetry, measurements
- Surface / Parametric / Mapping -- mesh and point cloud data
- DICOS / DICONDE -- security screening and industrial inspection
- Encapsulated Documents beyond PDF -- CDA, STL, OBJ, MTL (3D printing)

### Biggest bottleneck

Seed corpus acquisition. Each domain needs valid DICOM seed files, and
many modalities (ophthalmology, waveform, DICOS) lack freely available
samples. The TCIA archive covers radiology well but has gaps in niche
modalities.

### Effort estimate

Roughly 10-14 weeks of focused work for one developer to reach
comprehensive coverage, with diminishing returns past ~30 fuzzers.
The 6 existing stubs + 4-6 high-value domain fuzzers would cover
~85-90% of the attack surface for typical PACS/viewer targets.

## Register multiframe strategies in DicomMutator dispatch pool

**Location:** `dicom_fuzzer/attacks/multiframe/`, `dicom_fuzzer/core/mutation/mutator.py`

**Investigation findings (2026-03-17):**

The architecture unification described in the old version of this item is already done.
`MultiFrameFuzzerBase` extends `FormatFuzzerBase` (via `attacks/multiframe/format_base.py`).
All 10 multiframe strategies expose a conformant `mutate(dataset) -> Dataset` interface.
`MultiFrameHandler`, `MutationStrategyBase`, and the disconnected dispatch chain described
previously do not exist in the current codebase.

What remains: none of the 10 strategies are registered in `DicomMutator`'s strategy pool.
They are explicit-only — they never fire in a standard campaign run.

**Work items:**

- Import and register all 10 multiframe strategies in `DicomMutator`
- Verify `can_mutate()` guards fire correctly for non-multiframe seeds (multiframe
  strategies should self-select based on `NumberOfFrames > 1`)
- Run `tests/test_attacks/format/test_format_fuzzer_verification.py` — strategy count
  will increase from 88 to ~98

**Note:** `MultiFrameMutationRecord` per-frame detail records are produced by
`_mutate_impl()` internally but discarded by the public `mutate()` wrapper. They will
not appear in campaign reports after dispatch registration. See deferred item below.

## Deferred: Surface MultiFrameMutationRecord details in campaign reports

**Location:** `dicom_fuzzer/attacks/multiframe/format_base.py`, `dicom_fuzzer/core/reporting/`

**Deferred from:** "Register multiframe strategies in DicomMutator dispatch pool"

`_mutate_impl()` returns `tuple[Dataset, list[MultiFrameMutationRecord]]` with per-frame
detail (strategy, frame_number, tag, original_value, mutated_value, severity). The public
`mutate()` wrapper returns only the `Dataset` and discards the records. Once multiframe
strategies run through `DicomMutator`, these per-frame records are lost — campaign reports
only see the strategy name, not which frames were mutated or what changed.

**Future work:**

- Extend `MutationRecord` (`fuzzing_session.py`) with an optional
  `frame_mutations: list[MultiFrameMutationRecord]` field
- Surface frame-level details in session JSON and HTML reports
- Depends on "Formalize variant terminology" item 1 first (MutationRecord already
  extended before adding `frame_mutations`)

Medium effort. Lower priority than basic dispatch registration.

## Remove orphaned DicomParser methods

**Location:** `dicom_fuzzer/core/dicom/parser.py`

**Investigation findings (2026-03-17):**

The "Consolidate DICOM metadata extraction" item that preceded this was based on a false
premise. `DicomParser.extract_metadata()` (14+ fields, cached, comprehensive) and
`FuzzingSession._extract_metadata()` (7 fields, `stop_before_pixels=True`, lightweight)
serve different purposes and should not be merged. The two-method design is intentional.

What is actionable: four `DicomParser` instance methods have zero production callers,
confirmed by tracing through `engine/generator.py` and all session/reporting code:

- `get_pixel_data()` -- unused, remove
- `get_transfer_syntax()` -- unused, remove
- `is_compressed()` -- keep: useful for seed selection and `can_mutate()` logic
- `temporary_mutation()` -- keep: useful for test isolation patterns

**Work items:**

- Remove `get_pixel_data()` and `get_transfer_syntax()` from `DicomParser`
- Grep for callers before deleting (confirm no test-only usage remains)
- Update `core/dicom/__init__.py` exports if either method is re-exported

Low effort. Low risk.

## Wire strategy hit-rate tracking into session output

**Context:** `dicom_fuzzer/core/engine/generator.py`,
`dicom_fuzzer/core/session/fuzzing_session.py`

After a fuzzing campaign, the operator needs to verify that all strategies fired at
least once. If some got 0 hits (stochastic selection or seed incompatibility), the
campaign has blind spots.

### What exists

`GenerationStats.strategies_used: dict[str, int]` in `generator.py` already counts hits
per strategy during `generate_batch()`. The counting works. The problem: it resets per
batch and is never persisted or emitted anywhere.

### Approach (simple path)

1. **Accumulate across batches** -- add a `cumulative_strategies: dict[str, int]` that
   persists across `generate_batch()` resets in `DICOMGenerator`
2. **Emit at session close** -- write as a `strategy_hit_rates` section in
   `session_<id>.json` (strategy name -> hit count + hit rate %)
3. **Log a text table** -- at campaign end, log `strategy | hits | hit_rate%` with a
   warning for any strategy at 0 hits

This answers the FDA question without requiring the full analytics pipeline.

### Effort

Small. The counting already works. The work is persisting the dict and one JSON/log
write at campaign end.

### Priority

Medium. Directly supports the "all strategies fired" FDA rationale.

### Deferred: Full analytics pipeline

See the deferred item below for wiring accumulated counts into `CampaignAnalyzer` and
`FuzzingVisualizer` for richer visualizations.

## Deferred: Wire strategy effectiveness into CampaignAnalyzer and FuzzingVisualizer

**Location:** `dicom_fuzzer/core/analytics/campaign_analytics.py`,
`dicom_fuzzer/core/analytics/visualization.py`

**Deferred from:** "Wire strategy hit-rate tracking into session output"

Once `cumulative_strategies` is persisted, the full analytics pipeline is available
but not wired:

- `CampaignAnalyzer.analyze_strategy_effectiveness()` computes composite scores but
  expects `list[MutationStatistics]` -- never constructed, never called
- `FuzzingVisualizer.plot_strategy_effectiveness()` renders a bar chart -- never called
- `MutationStatistics` in `statistics.py` has all required fields (`times_used`,
  `effectiveness_score()`, `crashes_found`) -- never populated

**Future work:**

1. Build `MutationStatistics` objects from accumulated strategy counts
2. Call `CampaignAnalyzer.analyze_strategy_effectiveness()` at campaign end
3. Call `FuzzingVisualizer.plot_strategy_effectiveness()` to generate the chart
4. Include chart in the HTML campaign report

Medium effort. Lower priority than the text-table path (which already answers the FDA
question).

## Build unique-crash-over-time curve (crash discovery saturation)

**Context:** `dicom_fuzzer/core/crash/crash_analyzer.py`,
`dicom_fuzzer/core/analytics/campaign_analytics.py`,
`dicom_fuzzer/core/analytics/visualization.py`

**Investigation findings (2026-03-17):**

The previous version of this item claimed `TrendAnalysis` and `plot_crash_trend()`
exist and only need wiring. Neither exists. Both must be built from scratch.

After a fuzzing campaign, the operator needs to prove diminishing returns -- that the
unique crash discovery rate has plateaued. If the curve is still climbing, more runs
are needed.

### What actually exists

- `CrashAnalyzer.crash_hashes: set[str]` -- SHA256 dedup. `is_unique_crash()` works.
  No temporal tracking.
- `CampaignAnalyzer` in `campaign_analytics.py` -- no `TrendAnalysis` class here
- `FuzzingVisualizer` in `visualization.py` -- no `plot_crash_trend()` method here

### What needs to be built

1. **`crash_timeline` in `CrashAnalyzer`** -- add
   `crash_timeline: list[tuple[datetime, int]]`. When `is_unique_crash()` returns
   `True`, append `(datetime.now(), len(crash_hashes))`.
2. **`TrendAnalysis` dataclass** in `campaign_analytics.py` -- fields:
   `crashes_over_time: list[tuple[datetime, int]]`, methods: `crash_discovery_rate()`,
   `is_plateauing()` (define plateau as <5% new crashes in last 20% of campaign duration)
3. **`plot_crash_trend()`** in `visualization.py` -- render the curve using the timeline
4. **Wire at campaign end** -- call from `CampaignRunner` or session close

### Effort

Medium. The dedup logic works. The analytics and visualization are net-new, not wiring.

### Priority

Medium. The plateau proof is more convincing than raw case counts for demonstrating
campaign sufficiency in FDA submissions.

## Merge/disambiguate corpus_minimization.py and corpus_minimizer.py

**Location:** `dicom_fuzzer/core/corpus/corpus_minimization.py`,
`dicom_fuzzer/core/corpus/corpus_minimizer.py`

Two confusingly named modules doing related but distinct work:

- `corpus_minimization.py`: strip pixel data, optimize corpus,
  minimize_corpus_for_campaign, MoonLight weighted set cover,
  CoverageAwarePrioritizer, validate_corpus_quality
- `corpus_minimizer.py`: AFL-cmin style CorpusMinimizer, CoverageCollector
  ABC (Simple/Target), multi-fuzzer sync (CorpusSynchronizer)

The names differ by one suffix (-ation vs -er) and both deal with "making
the corpus smaller." A developer has to read both files to know which one
to use for a given task.

**Fix:** Consider consolidating into a clearer package structure, e.g.:

- `corpus/strip.py` -- strip_pixel_data, optimize_corpus (bulk data removal)
- `corpus/minimize.py` -- MoonLight, AFL-cmin, minimize_corpus_for_campaign
- `corpus/sync.py` -- CorpusSynchronizer, SyncMode, SyncConfig
- `corpus/coverage.py` -- CoverageCollector ABC, coverage types

Or keep two files but give them clearly distinct names
(`corpus_strip.py` + `corpus_minimize.py`).

Medium effort. Touches imports in CLI commands, engine, and tests.

## Consolidate crash data types (CrashReport, CrashRecord, WindowsCrashInfo)

**Location:** `dicom_fuzzer/core/crash/crash_analyzer.py`,
`dicom_fuzzer/core/session/fuzzing_session.py`,
`dicom_fuzzer/core/crash/windows_crash_handler.py`

Three separate dataclasses represent crash data with overlapping fields
but no shared base class or protocol:

- `CrashReport` (crash_analyzer.py) -- produced by `CrashAnalyzer.analyze_exception()`
- `CrashRecord` (fuzzing_session.py) -- consumed by `CrashTriageEngine`
- `WindowsCrashInfo` (windows_crash_handler.py) -- produced by `WindowsCrashHandler`

`CrashTriageEngine` only accepts `CrashRecord`, so crashes detected by
`CrashAnalyzer` or `WindowsCrashHandler` cannot be triaged without
manual field mapping. The reporting enrichers import `CrashTriageEngine`
directly, creating a dependency chain that skips the analyzers.

### What to do

Either:

1. Define a `CrashProtocol` (Protocol class) with shared fields
   (`crash_type`, `severity`, `exception_message`, `stack_trace`,
   `crash_hash`, `timestamp`) and make all three classes conform to it.
   `CrashTriageEngine` accepts the protocol instead of `CrashRecord`.
2. Merge into a single `CrashInfo` dataclass with optional fields for
   Windows-specific data (exception_code, registers, minidump_path).

Option 1 is lower risk (no field renames). Option 2 is simpler.

Touches: crash/, session/, reporting/. Medium effort.

## Review CrashAnalyzer's role for black-box fuzzing

**Location:** `dicom_fuzzer/core/crash/crash_analyzer.py`,
`dicom_fuzzer/core/harness/target_runner.py`

`CrashAnalyzer` is a Python-exception-only analyzer. It classifies
`MemoryError`, `RecursionError`, `AssertionError`, `TimeoutError` etc.
into crash types. But for a black-box fuzzer targeting external
executables, crashes manifest as process exit codes and signals, not
Python exceptions.

`target_runner.py` uses `CrashAnalyzer` for internal exceptions that
occur during fuzzing (e.g., pydicom errors), and `WindowsCrashHandler`
for process-level crashes. This split makes sense, but the naming
implies `CrashAnalyzer` is the primary crash handler when it's actually
the secondary one.

### What to consider

- Rename to `ExceptionAnalyzer` or `InternalCrashAnalyzer` to clarify scope
- Evaluate whether internal exceptions should be recorded as crashes at
  all (a pydicom error during mutation is a fuzzer bug, not a finding)
- If internal exceptions are worth tracking, they should flow through the
  same triage pipeline as process crashes

Low priority. Naming/architecture discussion, no functional impact.

## Add coverage-guided fuzzing (future)

**Location:** `dicom_fuzzer/core/corpus/`, `dicom_fuzzer/core/engine/`

The project is currently a pure black-box mutation fuzzer: the engine takes
a seed file, mutates it N times, and writes output. There is no feedback
loop, no seed selection, and no coverage tracking in the main fuzzing loop.

A previous `CorpusManager` with fitness scoring, coverage-hash dedup, and
eviction was built but never wired into `DICOMGenerator` or `CampaignRunner`.
It was removed as dead code (along with `CoverageSnapshot`).

To add coverage-guided fuzzing in the future:

1. **Instrument the target** -- DynamoRIO, Frida, or LLVM SanitizerCoverage
   to collect edge/branch bitmaps from the target process per test case.
2. **Feed coverage back** -- after each `TargetRunner.execute_test()`, collect
   the coverage bitmap and pass it to a corpus manager.
3. **Seed selection** -- replace the current "mutate the same seed N times"
   loop with a coverage-aware seed queue (favor seeds that found new edges).
4. **Corpus management** -- re-introduce fitness scoring, eviction, and
   coverage-hash dedup once there is actual coverage data to drive it.

This is a major architectural change. The existing `SeedCoverageInfo` type
in `coverage_types.py` is retained as a building block for this future work.

Also removed in the same cleanup pass:

- `corpus_minimizer.py` (AFL-cmin style minimizer, `CorpusSynchronizer`,
  `CoverageCollector`, etc.) -- all 12 public symbols were test-only
- `CoverageAwarePrioritizer` from `corpus_minimization.py` -- completely dead
- `minimize_crashing_study` from `study_minimizer.py` -- dead convenience wrapper
- All `__init__.py` re-exports (no production code used package-level imports)

## Establish a consistent mutation taxonomy across all fuzzers

**Location:** `dicom_fuzzer/attacks/format/` (all fuzzers)

Most fuzzers mix boundary values, malformed formats, and injection
payloads ad-hoc within the same payload list. A field like `PatientID`
ends up with null bytes, SQL injections, and length-limit violations in
a single flat list with no structural distinction. This is a product of
incremental development -- each new attack idea gets appended -- not
intentional design.

`_random_pn_attack()` in `metadata_fuzzer.py` is the one existing
exception: it explicitly selects a family ("malformed", "injection", or
"boundary") before picking a payload. The goal is to bring every attack
method in line with that pattern.

### Problem

Without a taxonomy, you cannot answer in a campaign report: "did we
exercise injection attacks against every targeted field?" The payload
families are entangled, which also makes it easy to leave a family gap
when a new field is added.

### Proposed three-family taxonomy

- **Boundary**: Empty strings, max-length violations, zero/negative
  numerics, NaN, infinity, impossible dates -- spec limit testing
- **Malformed**: Null bytes, wrong character set (e.g. lowercase CS),
  missing PN separators, tab/newline in non-text fields, invalid
  encoding sequences -- format correctness testing
- **Injection**: SQL, XSS, path traversal, Log4Shell, ANSI escapes,
  HTTP header injection -- downstream parsing exploit testing

Each attack method should select a family first, then pick a payload
from that family only. The family choice can bubble up to `mutate()` so
a single run is traceable to one family per category.

### Scope -- per fuzzer audit

Review findings from a full scan of all 18 fuzzers:

**Heavy mixing (all three families entangled within attack methods):**

- `metadata_fuzzer.py` -- injections, null bytes, and length violations
  in the same `PatientID` list; inconsistent across the five attack methods
- `structure_fuzzer.py` -- tag ordering, length overflow, and injection
  all within `mutate()`
- `header_fuzzer.py` -- `VR_MUTATIONS` dict conflates boundary/malformed/
  injection per VR type
- `encoding_fuzzer.py` -- all 10 strategies mix overlong/malformed/
  control chars/injection in single lists
- `sequence_fuzzer.py` -- all 8 strategies mix boundary, malformed,
  and injection
- `private_tag_fuzzer.py` -- 10 strategies span all three families with
  no selection logic
- `rt_dose_fuzzer.py`, `rtss_fuzzer.py`, `seg_fuzzer.py` -- modality
  fuzzers mix boundary and injection freely within each attack
- `nm_fuzzer.py`, `pet_fuzzer.py` -- energy/rotation/temporal attacks
  mix boundary, malformed, and injection
- `encapsulated_pdf_fuzzer.py` -- size/structure/metadata/injection
  across all 6 strategies

**Moderate mixing (limited but present):**

- `calibration_fuzzer.py` -- boundary + malformed + one injection
  (mismatch) per method
- `conformance_fuzzer.py` -- mostly injection per strategy but some
  removal/malformed mixed in

**Already focused (no change needed):**

- `pixel_fuzzer.py` -- boundary and malformed separated cleanly by attack
  method; per-VR focus
- `compressed_pixel_fuzzer.py` -- focused per format strategy
- `reference_fuzzer.py` -- each strategy targets one relationship type;
  families separated by method
- `uid_attacks.py` -- single-family (malformed UID format) only
- `dictionary_fuzzer.py` -- probabilistic selection (70% valid / 30%
  edge case) is a different but intentional approach; leave as-is

### Implementation approach

For each fuzzer in the "heavy mixing" group:

1. Audit each attack method and categorize every existing payload into
   boundary / malformed / injection
2. Split the flat list into three sub-lists (can be module-level
   constants or inline dicts)
3. Rewrite the method to select a family first, then sample from that
   sub-list
4. Propagate the family choice up to `mutate()` if the fuzzer supports
   it, so the selected family appears in logs/reports

Start with `metadata_fuzzer.py` as the reference implementation
(since `_random_pn_attack()` already demonstrates the pattern), then
apply the same refactor to the remaining fuzzers in the heavy-mixing
group.

Large effort overall. Each fuzzer is a contained unit so the work can
be done incrementally, one fuzzer at a time, without cross-file risk.

## Consolidate split same-module imports across the repo

**Location:** repo-wide (`dicom_fuzzer/`)

Multiple files import from the same module in separate `from X import`
blocks instead of one combined block. This is an artifact of incremental
development: each time a new symbol was needed from a module, a new
import line was appended rather than extending the existing one. The
result looks like `metadata_fuzzer.py` lines 23-34 -- four consecutive
blocks from `.dicom_dictionaries` that should be one.

A full scan found **16 files** with this pattern. They fall into three
tiers:

**Straightforward consolidation (module-level, same scope):**

- `attacks/format/metadata_fuzzer.py` -- 4 blocks from `.dicom_dictionaries`
- `attacks/format/conformance_fuzzer.py` -- 2 consecutive blocks from `.dicom_dictionaries`
- `attacks/network/pdu_mixin.py` -- 2 blocks from `.base`
- `attacks/network/tls_mixin.py` -- 2 blocks from `.base`
- `cli/utils/output.py` -- duplicate `Console` import from `rich.console`;
  2 blocks from `rich.progress`

**Verify before consolidating (may be intentional lazy imports):**

These files import inside function bodies, which defers the import cost
to the call site. This is sometimes deliberate for CLI startup time.
Check each one before merging:

- `cli/commands/calibrate.py` -- `CalibrationFuzzer` at lines 41 and 197
- `cli/commands/corpus.py` -- `study_minimizer` at lines 51 and 392
- `cli/commands/state.py` -- `state_aware_fuzzer` at lines 37, 107, 164
- `cli/commands/study.py` -- `study_mutator` at lines 41 and 195
- `cli/commands/study_campaign.py` -- `study_mutator` at lines 34, 304,
  603, 729 (4 separate imports)
- `core/corpus/study_minimizer.py` -- `target_runner` at lines 20 and 409
- `core/harness/target_runner.py` -- `dicom_fuzzer.core.crash` at lines
  18, 23, 157; `process_monitor` at lines 165 and 562
- `attacks/format/private_tag_fuzzer.py` -- `pydicom.sequence` imported
  inside two function bodies

**Leave alone (legitimate pattern):**

- `cli/controllers/network_controller.py` -- split across a
  `TYPE_CHECKING` guard; this is standard Python practice and must stay
  split
- `cli/controllers/campaign_runner.py` -- `tqdm` imported twice with
  different aliases (`tqdm` / `tqdm_iter`); intentionally distinct uses
- `attacks/network/dimse/dataset_mutator.py` -- `types` in
  `TYPE_CHECKING` guard plus runtime imports; leave as-is

### Fix

For the straightforward tier: merge into one `from X import (A, B, C)`
block. For the lazy-import tier: read each function to determine whether
the in-function import is avoiding a circular dependency or just
accidental placement; consolidate to the top only if it is safe.

Small-medium effort. No behavior change. Run the test suite after each
file to confirm nothing broke.

---

## Needs investigation / decision

Items below were surfaced during backlog review (2026-03-17) but require codebase
investigation and/or a decision before they can be written as actionable work items.
Do not plan or implement these until they have been promoted to proper entries above.

### MutationRecord naming collision

Two classes share the name `MutationRecord`: `mutator.py:34` (6 fields, internal
tracking) and `fuzzing_session.py:31` (8 fields, written to session JSON). A developer
importing from the wrong module gets the wrong class silently.

**Needs decision:** Rename one (e.g. `InternalMutationRecord` for the mutator variant)?
If yes, scope the rename and confirm no test assertions break.

### FuzzingSession pixel metadata gap

`FuzzingSession._extract_metadata()` uses `stop_before_pixels=True`. If a crash is
caused by a pixel mutation (high-priority per the pixel_fuzzer backlog items), the
session record has zero pixel context -- no Rows, Columns, BitsAllocated, or PixelData
presence flag.

**Needs decision:** Add a lightweight pixel field capture (just metadata tags, not the
pixel array) to `_extract_metadata()`? Assess whether `stop_before_pixels=True` is a
performance requirement or just a conservative default that can be relaxed.

### Centralize payloads and mutation taxonomy are order-dependent

"Centralize attack payloads in dicom_dictionaries" and "Establish a consistent mutation
taxonomy" are currently unordered independent items. Applying taxonomy without
centralizing first means family-selection logic references inline lists per fuzzer.
Centralizing without taxonomy produces uncategorized payloads in one place.

**Needs decision:** Confirm sequence: centralize payloads first, then apply taxonomy.
Add explicit ordering and cross-references between the two items.

### End-of-campaign auto-triage

Once `dicom-fuzzer triage` is a CLI command (per "Export CrashTriageEngine" item), the
natural follow-on is calling it automatically at campaign end and writing triage verdicts
into `session_<id>.json`. Currently triage results only appear when you explicitly invoke
the reporter.

**Needs decision:** Should campaign-end auto-triage be part of the CLI wiring item, or
a separate follow-on item? Investigate whether `CampaignRunner`'s session-close path is
the right hook point.

### CrashRecord.reproduction_command always None

`CrashRecord` in `fuzzing_session.py` has a `reproduction_command: str | None` field
that is always `None`. It is only meaningful once `replay --decompose` exists (item 2
of "Formalize variant terminology"). Currently this field creates false expectation that
reproduction commands are tracked.

**Needs decision:** Is this worth stubbing out visibly (e.g. a TODO comment at the field
site) or leaving as-is until the replay item is implemented? Should it be mentioned as a
dependency in the variant terminology item?
