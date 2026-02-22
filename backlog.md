# Backlog

Ideas pruned from the codebase that may be worth implementing later.

## Separate reports.py CLI from utility library

**Location:** `dicom_fuzzer/cli/commands/reports.py` (577 lines)

`reports.py` serves dual roles: (1) CLI subcommand for `dicom-fuzzer report`
and (2) utility library with 9 helper functions (`generate_json_report`,
`generate_csv_report`, `generate_coverage_chart`, `generate_markdown_report`,
`load_template`, `render_report`, `save_report`, `create_report_with_charts`,
`generate_charts`). Only 2 helpers have production consumers
(`generate_json_report` in `series_reporter.py`, `save_report` in
`tls/fuzzer.py`). The rest are test-only. `generate_charts()` is a stub
returning mock data.

**Fix:** Move the utility functions to `dicom_fuzzer/core/reporting/` (where
they logically belong) and update the 2 production imports + 9 test files.
Keep `reports.py` as a thin CLI wrapper. Also consider moving the ~100-line
inline legacy HTML template to a separate template file.

Medium effort. Touches ~12 files.

## Unify CLI setup_logging() with utils.logger.configure_logging()

**Location:** `dicom_fuzzer/cli/main.py` (lines 179-186)

`setup_logging()` uses `logging.basicConfig()` to configure stdlib logging.
The project already has `dicom_fuzzer.utils.logger.configure_logging()` with
structlog, sensitive-data redaction, and security context processors. Two
competing logging setups coexist -- the CLI uses one, the core modules use
the other.

**Fix:** Replace `setup_logging()` calls in `main()` with
`configure_logging()` from utils, then delete `setup_logging()` and its
tests. Requires verifying that structlog formatting works correctly in
CLI output (the format strings differ).

Low effort, but needs careful testing of CLI log output.

## Migrate CLI subcommands to SubcommandBase

**Location:** `dicom_fuzzer/cli/commands/` (11 subcommands)

All 11 subcommands use ad-hoc `def main(argv)` with custom error handling.
A `SubcommandBase` ABC was designed (and deleted as dead code) that would
standardize: argument parser creation, error handling, verbose traceback
support, and the `name`/`description`/`epilog` interface.

**Fix:** Create a new `SubcommandBase` in `cli/base.py` (or inline in
`cli/__init__.py`), then migrate each subcommand's `main()` to extend it.
This removes ~15 lines of boilerplate per subcommand (11 * 15 = ~165 lines).

Medium effort. Touches 11 files + tests.

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

## Remove pydicom MultiValue str() workaround in strategy cache

**Location:** `dicom_fuzzer/core/mutation/mutator.py` `_get_applicable_strategies()`

The strategy cache key converts `Modality` to `str()` because pydicom
`MultiValue` objects are unhashable in Python 3.11+ / pydicom 3.0+.
If pydicom makes `MultiValue` hashable, the `str()` conversion can be
removed and the raw value used directly in the cache key tuple.

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

It has ~35 call sites across test and integration files, so moving it
is non-trivial. A natural home would be a dedicated anonymization
utility (e.g. `dicom_fuzzer/utils/anonymizer.py`) or a data generation
helper. Worth doing when building a proper anonymization module.

## Centralize attack payloads in dicom_dictionaries

**Context:** `dicom_fuzzer/attacks/format/` (8+ files affected)

Generic attack payloads (SQL injection, XSS, command injection, format
strings, path traversal, buffer overflow strings, integer overflow values)
are duplicated across multiple fuzzer files instead of being sourced from
the central `dicom_dictionaries.py` module.

### Scope of duplication

Exact-match duplicates found:

| Payload | Duplicated in |
|---------|---------------|
| `"'; DROP TABLE patients; --"` | `dicom_dictionaries`, `metadata_fuzzer`, `private_tag_fuzzer` |
| `"%s%s%s%s%s%s%s%s%s%s"` | `metadata_fuzzer`, `private_tag_fuzzer` |
| `"<script>alert(...)</script>"` | `dicom_dictionaries`, `metadata_fuzzer`, `private_tag_fuzzer`, `sequence_fuzzer` |
| `"../../etc/passwd"` | `dicom_dictionaries`, `metadata_fuzzer`, `private_tag_fuzzer` |
| `"; ls -la"`, `"$(whoami)"` | `dicom_dictionaries`, `metadata_fuzzer`, `private_tag_fuzzer` |
| `2147483647`, `4294967295` | `dicom_dictionaries`, `header_fuzzer`, `calibration_fuzzer`, `pixel_fuzzer`, `structure_fuzzer` |
| `"A" * N` (various lengths) | 6+ files |
| Null bytes | 8+ files, 15+ locations |

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

## SEG and RTSS file fuzzing

**Context:** New attack surface not covered by existing format fuzzers

DICOM SEG (Segmentation) and RTSS (RT Structure Set) files have
complex internal structures that differ significantly from standard
image storage objects. The existing fuzzers target generic DICOM
metadata, pixel data, and headers -- but SEG and RTSS have
domain-specific structures that need targeted mutations.

### SEG-specific attack surface

- **Segment Sequence** (0062,0002): Each item defines a segment with
  SegmentNumber, SegmentLabel, SegmentAlgorithmType, AnatomicRegion.
  Mismatches between segment count and actual frame data cause crashes.
- **Dimension Index**: Per-Frame Functional Groups map frames to
  segments and slices. Corrupting this mapping is a known crash vector.
- **Binary/fractional pixel data**: Segment masks stored as 1-bit-per-pixel
  (BINARY) or 8-bit fractional. Mismatch with SegmentationType tag.
- **Referenced Series Sequence**: Links to the original image. Broken
  references stress error handling.

### RTSS-specific attack surface

- **Deeply nested sequences**: StructureSetROISequence ->
  ROIContourSequence -> ContourSequence -> ContourData. Nesting depth
  and item counts are rich mutation targets.
- **ContourData**: Thousands of float coordinates in a single
  backslash-delimited string. Malformed floats, NaN, Inf, truncated
  arrays, and coordinate count mismatches with ContourGeometricType.
- **ROI numbering**: ReferencedROINumber must match across sequences.
  Mismatches cause lookup failures.
- **Referenced Frame of Reference**: Coordinate system references.
  Invalid or missing references break spatial mapping.

### Implementation approach

Two options:

1. **New fuzzers in `attacks/format/`**: `seg_fuzzer.py` and
   `rtss_fuzzer.py` extending `FormatFuzzerBase`. Keeps the single
   `mutate(dataset) -> Dataset` interface. The fuzzers would check
   SOPClassUID to decide if the dataset is a SEG/RTSS and apply
   targeted mutations. Pro: integrates with existing engine pipeline.
2. **New attack category**: `attacks/specialized/` for modality-specific
   fuzzers that require seed files of the correct type. Pro: cleaner
   separation. Con: needs engine changes to route seeds by type.

Option 1 is simpler and recommended as a starting point. Both fuzzers
would return the dataset unmodified if it's not the right SOPClassUID,
which is consistent with `can_mutate()` in `FormatFuzzerBase`.

Requires seed SEG and RTSS files for the corpus.

## Encapsulated PDF fuzzing

**Context:** New attack surface not covered by existing format fuzzers

Encapsulated PDF Storage (SOP Class `1.2.840.10008.5.1.4.1.1.104.1`)
wraps a raw PDF inside a DICOM object. The viewer must parse the DICOM
wrapper, extract the PDF bytes from `EncapsulatedDocument` (0042,0011),
then hand them to a PDF renderer -- two parsers in series.

### Attack surface

- **EncapsulatedDocument** (0042,0011): The raw PDF bytes in an OB
  field. Truncated, corrupted, or entirely replaced content tests the
  PDF extraction and rendering pipeline.
- **MIMETypeOfEncapsulatedDocument** (0042,0012): Should be
  `"application/pdf"`. Mismatches (e.g. claiming `"image/jpeg"` or
  empty) test content-type validation.
- **DICOM metadata with valid PDF**: Corrupt the DICOM header while
  keeping the embedded PDF intact. Tests whether metadata corruption
  prevents the viewer from reaching the PDF at all.
- **Valid DICOM with malformed PDF**: Keep the DICOM wrapper clean but
  stuff in a malformed PDF. Tests the handoff between DICOM parser
  and PDF renderer.
- **Encapsulated CDA** (`1.2.840.10008.5.1.4.1.1.104.2`): Same
  pattern but for Clinical Document Architecture (XML-based clinical
  documents). Could share most of the fuzzer logic.

### Implementation

Same pattern as SEG/RTSS: new fuzzer in `attacks/format/` extending
`FormatFuzzerBase`, using `can_mutate()` to check SOPClassUID.
Requires seed Encapsulated PDF files for the corpus.

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

## Adopt or remove dead helper functions in html_templates.py

**Location:** `dicom_fuzzer/core/reporting/html_templates.py` (lines 344-592)

10 helper functions are tested (`test_html_templates.py`) but have zero
production callers: `render_badge`, `render_stat_card`, `render_alert`,
`render_info_row`, `render_code_block`, `render_details`,
`render_table_header`, `render_table_row`, `render_progress_bar`,
`html_report_header`.

Also `SEVERITY_COLORS` dict is tested but unused in production.

**Decision:** Either refactor `formatters.py` and `report_analytics.py`
to use these helpers (reducing inline HTML), or delete the helpers and
their tests. Currently they're dead weight that creates a false sense
of abstraction.

## Deduplicate critical crashes table

**Location:** `dicom_fuzzer/core/reporting/formatters.py` (lines 176-224),
`dicom_fuzzer/core/reporting/report_analytics.py` (lines 115-163)

Two nearly identical implementations of the "Top Critical Crashes" HTML
table: `HTMLSectionFormatter._format_critical_crashes_table()` and
`ReportAnalytics._format_critical_crashes_section()`. Both filter by
severity, sort by priority, render the same columns.

**Fix:** Keep one, delete the other, and have the caller reference the
surviving implementation. Or extract to a shared function.

## Fix cross-module HTML nesting

**Location:** `dicom_fuzzer/core/reporting/formatters.py` (line 48),
`dicom_fuzzer/core/reporting/enhanced_reporter.py` (line 133)

`formatters.py:format_session_overview()` opens a `<div class="content">`
tag but never closes it. `enhanced_reporter.py:_html_footer()` closes it
with a bare `</div>` before the document end. This cross-module tag
nesting is fragile -- adding or removing sections will break the HTML
structure silently.

**Fix:** Each module should manage its own tags. Either move the container
div open/close into `enhanced_reporter.py` (the orchestrator), or have
each section be self-contained.

## Fix compliance.py creating duplicate ReportAnalytics instance

**Location:** `dicom_fuzzer/core/reporting/compliance.py` (lines 45-47),
`dicom_fuzzer/core/reporting/enhanced_reporter.py` (line 57)

`ComplianceFormatter.format_fda_compliance_section()` does a deferred
import and creates a new `ReportAnalytics()` instance on every call.
Meanwhile, `EnhancedReportGenerator` already holds a `_analytics`
instance of `ReportAnalytics`.

**Fix:** Pass the `ReportAnalytics` instance to `ComplianceFormatter`
(via constructor or method parameter) instead of creating a duplicate.

## Add structured logging to HeaderFuzzer and PixelFuzzer

**Context:** `dicom_fuzzer/attacks/format/header_fuzzer.py`,
`dicom_fuzzer/attacks/format/pixel_fuzzer.py`

10 of 12 format fuzzers use `get_logger(__name__)` for structured
logging. HeaderFuzzer and PixelFuzzer are the two exceptions.

Without logging, mutations from these two fuzzers are invisible in
campaign logs. When a fuzzed file crashes the viewer, you can't trace
which HeaderFuzzer or PixelFuzzer attack method was applied or what
values were injected.

### What to add

For each fuzzer:

1. Import `from dicom_fuzzer.utils.logger import get_logger`
2. Add `logger = get_logger(__name__)` at module level
3. Add `logger.debug(...)` calls in `mutate()` and key attack methods
   to log which attack was selected and what values were injected

### Scope

- HeaderFuzzer has 8 attack methods -- add logging to `mutate()` and
  each `_*` method (which attack was chosen, which tags were modified)
- PixelFuzzer has 7 attack methods -- same pattern

Low effort, no risk. Can be done when reviewing these files.

## Rewrite StructureFuzzer no-op attacks at binary level

**Context:** `dicom_fuzzer/attacks/format/structure_fuzzer.py`

Three of StructureFuzzer's six Dataset-level attacks are partially or
fully no-ops because pydicom enforces structural correctness on write:

1. **`_corrupt_tag_ordering`** -- Swaps elements in a list then rebuilds
   a Dataset, but pydicom re-sorts by tag number on insertion. Output
   tag order is identical to input. Complete no-op.

2. **`_duplicate_tags`** -- Calls `add_new` on an existing tag, but
   pydicom overwrites instead of creating a duplicate. Result is a
   value mutation (appends "_DUPLICATE"), not a duplicate tag.

3. **`_corrupt_length_fields`** -- Changes string values (longer, empty,
   null bytes) but pydicom recalculates length fields from actual
   values on write. Output has correct lengths for new values.

### What to do

Reimplement these attacks at the binary level, similar to the existing
`corrupt_file_header()` method which already operates on raw bytes:

1. **Tag ordering**: Write file via pydicom, then swap tag byte-pairs
   in the raw output to create out-of-order tags.
2. **Duplicate tags**: Write file, then duplicate a tag's raw bytes at
   a different position in the binary stream.
3. **Length corruption**: Write file, then patch the 4-byte length
   field of a random element to a wrong value (0xFFFFFFFF, 0, or
   a value larger than actual data).

### Integration approach

Add a `mutate_bytes(file_data: bytes) -> bytes` method alongside
the existing `mutate(dataset) -> Dataset`. The engine could call
`mutate_bytes` on the serialized output of `mutate`, layering
Dataset-level and binary-level mutations.

Medium-high effort, medium risk. Requires updating the engine to
support a byte-level mutation pass.

## Nuclear Medicine (NM) modality-specific fuzzing

**Context:** SOP Class `1.2.840.10008.5.1.4.1.1.20` -- not covered by
any existing fuzzer beyond generic DICOM metadata and pixel data.

NM images have domain-specific sequences that existing fuzzers never
touch because they don't exist in CT seed files:

### Attack surface

- **EnergyWindowInformationSequence** (0054,0012): Defines energy
  windows (keV ranges) for gamma camera acquisitions. Items contain
  `EnergyWindowRangeSequence` with `EnergyWindowLowerLimit` /
  `EnergyWindowUpperLimit` (DS values). Corrupting these tests how the
  viewer handles invalid energy calibration.
- **DetectorInformationSequence** (0054,0022): Detector geometry --
  `ImageOrientationPatient`, `ImagePositionPatient`, `FieldOfViewShape`,
  `FieldOfViewDimensions` per detector. Mismatches between detectors
  stress multi-detector rendering.
- **RotationInformationSequence** (0054,0052): SPECT rotation data --
  `ScanArc`, `NumberOfFramesInRotation`, `AngularStep`,
  `RadialPosition`. Cross-field consistency is a rich target.
- **RadiopharmaceuticalInformationSequence** (0054,0016): Isotope,
  injection time, dose, half-life. Shared with PET.
- **NumberOfSlices / NumberOfTimeSlices** cross-consistency: Mismatch
  between these and actual frame count.

### Implementation

New fuzzer `attacks/format/nm_fuzzer.py` extending `FormatFuzzerBase`.
Use `can_mutate()` to check `SOPClassUID == 1.2.840.10008.5.1.4.1.1.20`
or `Modality == "NM"`. Requires NM seed files.

Medium effort. Requires NM seed file in corpus.

## PET modality-specific fuzzing

**Context:** SOP Class `1.2.840.10008.5.1.4.1.1.128` -- SUV
calibration chain and radiopharmaceutical data not covered.

PET images share some structures with NM but have unique aspects
around SUV calculation that viewers must handle correctly.

### Attack surface

- **RadiopharmaceuticalInformationSequence** (0054,0016): Same as NM,
  but more critical for PET -- `RadionuclideHalfLife`,
  `RadionuclideTotalDose`, `RadiopharmaceuticalStartDateTime` feed
  directly into decay correction and SUV computation.
- **SUV calibration chain**: `Units` (BQML/CNTS), `DecayCorrection`
  (START/ADMIN/NONE), `PatientWeight`, `PatientSize` -- these must be
  consistent for SUV calculation. Existing `MetadataFuzzer` touches
  `PatientWeight`/`PatientSize` with boundary values but doesn't
  understand the SUV dependency chain.
- **DecayFactor** / **FrameReferenceTime** / **ActualFrameDuration**:
  Temporal parameters for multi-frame PET. Inconsistencies between
  frames stress time-based rendering.
- **CorrectedImage** (0028,0051): Flags like ATTN, DECY, NORM, SCAT
  indicating which corrections were applied. Invalid combinations or
  unexpected values.

### Implementation

Could share a base with NM fuzzer since `RadiopharmaceuticalInformation
Sequence` overlaps. `attacks/format/pet_fuzzer.py` or a combined
`nuclear_medicine_fuzzer.py`. Requires PET seed files.

Medium effort. Requires PET seed file in corpus.

## RT Dose modality-specific fuzzing

**Context:** SOP Class `1.2.840.10008.5.1.4.1.1.481.2` -- dose grid
scaling and DVH structures not covered.

RT Dose has pixel-like dose grid data that the existing pixel fuzzers
partially cover, but domain-specific tags are missed.

### Attack surface

- **DoseGridScaling** (3004,000E): DS value that converts stored pixel
  values to dose (Gy). Similar to `RescaleSlope` but not in
  `CalibrationFuzzer`'s target list. Zero, negative, NaN, extreme
  values would test dose display.
- **DVHSequence** (3004,0050): Dose-Volume Histogram data with nested
  `DVHData` (DS array of dose/volume pairs), `DVHType` (CUMULATIVE/
  DIFFERENTIAL), `DVHDoseScaling`. Not targeted by any fuzzer.
- **GridFrameOffsetVector** (3004,000C): DS array defining Z-offsets
  of dose planes. Length mismatch with `NumberOfFrames`, non-monotonic
  offsets, NaN values.
- **ReferencedRTPlanSequence** (300C,0002): Links dose to treatment
  plan. `ReferenceFuzzer` covers generic references but doesn't
  construct RT-specific ones.
- **DoseType** (3004,0004): PHYSICAL/EFFECTIVE/ERROR -- invalid
  enumeration values.
- **DoseSummationType** (3004,000A): PLAN/MULTI_PLAN/FRACTION/BEAM/
  BRACHY -- mismatches with actual data structure.

### Implementation

New fuzzer `attacks/format/rt_dose_fuzzer.py`. Use `can_mutate()` to
check SOPClassUID. Requires RT Dose seed files.

Medium effort. Requires RT Dose seed file in corpus.

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

## Unify multiframe strategies with FormatFuzzerBase

**Location:** `dicom_fuzzer/core/mutation/multiframe_handler.py`, `dicom_fuzzer/attacks/multiframe/`

`MultiFrameHandler` is a parallel orchestrator that duplicates what `DicomMutator`
already does. The 8 multiframe strategies (`attacks/multiframe/`) use their own
base class (`MutationStrategyBase`), their own record type (`MultiFrameMutationRecord`),
and their own dispatch -- completely disconnected from the fuzzing pipeline.

Zero production code calls `MultiFrameHandler.mutate()`. The strategies never
run unless manually instantiated.

**Fix:** Refactor multiframe strategies to extend `FormatFuzzerBase`, return
`Dataset` (not `tuple[Dataset, list[...]]`), auto-register with `DicomMutator`,
then delete `MultiFrameHandler`, `multiframe_types.py`, and `create_multiframe_mutator`.
Touches ~10 strategy files + tests.

## Consolidate DICOM metadata extraction through DicomParser

**Location:** `dicom_fuzzer/core/dicom/parser.py`, `dicom_fuzzer/core/session/fuzzing_session.py`

`DicomParser` has a well-structured `extract_metadata()` method, but no
production code calls it. The sole production consumer (`engine/generator.py`)
only uses `DicomParser(file).dataset` as a thin parse wrapper.

Meanwhile, `FuzzingSession._extract_metadata()` does its own inline
`pydicom.dcmread` + attribute extraction, duplicating the concept while
bypassing `DicomParser` entirely.

**Fix:** Either make `FuzzingSession` use `DicomParser.extract_metadata()`,
or reshape `DicomParser`'s API to match what production code actually needs.
The remaining methods (`get_pixel_data`, `get_transfer_syntax`,
`is_compressed`, `temporary_mutation`) should also be evaluated for
production integration or removal at that time.

## Use or remove DicomSeries.metadata field

**Location:** `dicom_fuzzer/core/dicom/dicom_series.py`

`DicomSeries.metadata: dict[str, Any]` is defined but never read by any
production code. Series-level metadata is always extracted directly from
slices by consumers (series_detector, series_writer, series_reporter).

Either populate it in `SeriesDetector._create_series()` and use it
downstream, or remove it to keep the dataclass honest.

## Wire SeriesWriter into the fuzzing pipeline or remove

**Location:** `dicom_fuzzer/core/dicom/series_writer.py`

`SeriesWriter` and `SeriesMetadata` have **zero production consumers**. They are
exported from `core/dicom/__init__.py` and exercised by 25+ tests, but no
production code path ever writes fuzzed series to disk through this class.

The fuzzing pipeline currently stops at in-memory `Dataset` objects.
`SeriesWriter` was built to close that gap (organized output dirs, metadata
JSON, reproduction scripts), but was never wired in.

**Fix:** Either integrate `SeriesWriter` into the fuzzing session's output
path (e.g., `FuzzingSession` or a CLI command calls `write_series()` after
mutation), or remove it if output is handled differently.

## Wire DicomValidator into the fuzzing pipeline or remove

**Location:** `dicom_fuzzer/core/dicom/validator.py`

`DicomValidator` has **zero production consumers**. It is exported from
`core/dicom/__init__.py` and tested, but no production code ever calls it.

Validation of fuzzed DICOM files is currently done inline or not at all.
`DicomValidator` was presumably built to provide structured validation, but
was never integrated.

**Fix:** Either wire it into the pipeline (e.g., post-mutation validation
in `DicomMutator`, pre-write validation in `SeriesWriter`, or CLI `validate`
command), or remove it if validation is handled differently.

## Wire strategy hit-rate tracking into campaign reports

**Context:** `dicom_fuzzer/core/engine/generator.py`,
`dicom_fuzzer/core/reporting/statistics.py`,
`dicom_fuzzer/core/analytics/campaign_analytics.py`,
`dicom_fuzzer/core/analytics/visualization.py`

After a fuzzing campaign, the operator needs to verify that all 88 mutation
strategies fired at least once. If some strategies got 0 hits (due to
stochastic selection or seed incompatibility), the campaign has blind spots
and needs more runs or weighted selection.

### What exists

- `GenerationStats.strategies_used: dict[str, int]` in `generator.py`
  already counts hits per strategy during `generate_batch()`
- `MutationStatistics` in `statistics.py` has `times_used`,
  `effectiveness_score()`, `crashes_found` -- never populated
- `CampaignAnalyzer.analyze_strategy_effectiveness()` in
  `campaign_analytics.py` computes composite scores -- expects
  pre-built `list[MutationStatistics]`, never receives them
- `FuzzingVisualizer.plot_strategy_effectiveness()` in `visualization.py`
  renders a bar chart of strategy scores -- never called

### What's needed

1. **Persist `strategies_used` across batches** -- accumulate into a
   `dict[str, int]` that survives `generate_batch()` resets
2. **Build `MutationStatistics` from accumulated counts** -- construct
   one per strategy at campaign end
3. **Feed into `CampaignAnalyzer`** -- call
   `analyze_strategy_effectiveness()` with the built stats
4. **Render or log** -- either call `FuzzingVisualizer` for a chart,
   or emit a simple text table of (strategy, hits, hit_rate%)

### Effort

Small-medium. The counting already works. The work is plumbing: persist
the dict, build the stats objects, and add one call from the CLI/engine
into the analytics layer.

### Priority

Medium. Directly supports the "all 88 strategies fired" FDA rationale.
Without this, the operator has no proof that the campaign actually
exercised every strategy.

## Wire unique-crash-over-time curve into campaign reports

**Context:** `dicom_fuzzer/core/crash/crash_analyzer.py`,
`dicom_fuzzer/core/analytics/campaign_analytics.py`,
`dicom_fuzzer/core/analytics/visualization.py`

After a fuzzing campaign, the operator needs to prove diminishing returns
-- that the unique crash discovery rate has plateaued. If the curve is
still climbing steeply at the end, more runs are needed. If it's flat,
the campaign has saturated.

### What exists

- `CrashAnalyzer.crash_hashes: set[str]` in `crash_analyzer.py`
  deduplicates crashes via SHA256(stack_trace + exception_msg).
  `is_unique_crash()` gates recording correctly
- `TrendAnalysis` in `campaign_analytics.py` has
  `crashes_over_time: list[tuple[datetime, int]]` +
  `crash_discovery_rate()` + `is_plateauing()` -- all implemented,
  zero callers
- `FuzzingVisualizer.plot_crash_trend()` in `visualization.py` renders
  the curve -- never called

### What's needed

1. **Add timestamped discovery log to `CrashAnalyzer`** -- when
   `is_unique_crash()` returns `True`, append
   `(datetime.now(), len(crash_hashes))` to a new
   `crash_timeline: list[tuple[datetime, int]]`
2. **Feed into `TrendAnalysis`** -- pass the timeline to
   `CampaignAnalyzer.analyze_trends()` as the `crash_timeline` arg
3. **Render or log** -- call `FuzzingVisualizer.plot_crash_trend()`
   for a chart, or emit `is_plateauing()` as a pass/fail verdict

### Effort

Small. The dedup logic works. The analytics and visualization are
implemented. The work is adding one list + one append to `CrashAnalyzer`
and wiring it through to the existing analytics.

### Priority

Medium. Directly supports the "diminishing returns" FDA rationale.
The plateau proof is more convincing than raw case counts for
demonstrating campaign sufficiency.

## PyPI publishing pipeline

**Context:** `.github/workflows/ci.yml` -- the `build` job already runs
`uv build` and `twine check dist/*`, but the pipeline stops there.

The natural next step is a publish workflow that pushes to PyPI on tagged
releases. The standard pattern:

1. **Trigger**: `on: push: tags: ['v*']` (semantic version tags)
2. **Build**: Same `uv build` + `twine check` as the current `build` job
3. **Publish to TestPyPI**: Upload to test.pypi.org first for validation
4. **Publish to PyPI**: Upload to pypi.org using trusted publishing (OIDC)
   -- no API tokens needed, GitHub Actions authenticates directly with PyPI
5. **GitHub Release**: Create a GitHub Release with changelog and dist
   artifacts attached

Key decisions for later:

- **Trusted publishing vs API token**: OIDC (trusted publishing) is the
  modern approach -- configure it in PyPI project settings, no secrets needed
- **pyproject.toml metadata**: Ensure `[project]` has correct `name`,
  `version`, `description`, `authors`, `license`, `classifiers`, `urls`
- **Versioning strategy**: Manual version bumps in `pyproject.toml` or
  automated via `python-semantic-release` / `bump-my-version`
- **Changelog generation**: Manual CHANGELOG.md or auto-generated from
  conventional commits

Low effort to set up once the package metadata is finalized. The existing
`build` job proves the package already builds and passes `twine check`.

## Rename dicom_series.py to series.py for naming consistency

**Location:** `dicom_fuzzer/core/dicom/dicom_series.py`

The `core/dicom/` package has inconsistent file naming: `dicom_series.py`
carries a redundant `dicom_` prefix (the package is already `dicom/`),
while `series_detector.py` and `series_writer.py` follow a cleaner
`series_*.py` convention.

Renaming `dicom_series.py` to `series.py` would align all three files,
but touches 10+ imports across `attacks/series/`, `core/dicom/`, and tests.
Low priority -- cosmetic only, no behavior change.

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

## Clean up core/corpus/__init__.py exports

**Location:** `dicom_fuzzer/core/corpus/__init__.py`

The current `__init__.py` only re-exports from `corpus_minimization`,
`corpus_minimizer`, and `coverage_types`. It does NOT export
`StudyCorpusManager` (from `study_corpus.py`) or `StudyMinimizer`
(from `study_minimizer.py`).

Consumers import directly from submodules, which works but makes the
`__init__.py` exports misleading -- they suggest a public API surface
that's incomplete.

**Decision needed:** Either export the key classes from `__init__.py` to
provide a proper facade, or document that direct submodule imports are the
intended pattern and remove the partial re-exports.

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
