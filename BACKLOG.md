# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

## Format fuzzing -- P0: Crash-rate improvements

### Empty/present-value attacks (EmptyValueFuzzer)

**Goal:** New fuzzer targeting the .NET "present but empty" crash
pattern. fo-dicom crashes when tags exist with zero-length values
because .NET code calls `element.Get<T>()` without null/empty checks.

**Implementation:** New `EmptyValueFuzzer` in `attacks/format/`.
Each attack: add the tag with an empty value (not delete -- present
but empty). `can_mutate()` returns True for any dataset.

**Attacks (9 total, each maps to a fo-dicom crash):**

1. `_empty_pixel_spacing`: Set (0028,0030) PixelSpacing to `""`.
   Crashes ImageData construction. (fo-dicom #2043, fixed 5.2.5)

2. `_empty_voi_lut_function`: Set (0028,1056) VOILUTFunction to `""`.
   Crashes on "must contain a single value, but contains 0".
   (fo-dicom #1891, fixed 5.2.0)

3. `_empty_specific_charset`: Set (0008,0005) SpecificCharacterSet
   to `""`. IndexOutOfRangeException in GetEncodings()[0].
   (fo-dicom #1879, fixed 5.1.4)

4. `_empty_image_position`: Set (0020,0032) ImagePositionPatient
   to `""`. Geometry pipeline crash. (fo-dicom #2067)

5. `_empty_image_orientation`: Set (0020,0037)
   ImageOrientationPatient to `""`. (fo-dicom #2067)

6. `_zero_window_width`: Set (0028,1051) WindowWidth to `0` or
   `0.001` or `-1`. Division-by-zero in windowing. (fo-dicom #1905)

7. `_comma_decimal_string`: Replace `.` with `,` in DS-VR tags
   (SliceThickness, PixelSpacing, etc). "1,5" instead of "1.5".
   Locale-specific parsing crash. (fo-dicom #1296)

8. `_empty_shared_functional_group`: Set (5200,9229)
   SharedFunctionalGroupsSequence to empty Sequence (zero items).
   IndexOutOfBoundsException in FunctionalGroupValues[0].
   (fo-dicom #1884, fixed 5.1.5)

9. `_empty_window_center`: Set (0028,1050) WindowCenter to `""`.
   Null reference in LUT pipeline.

**structural pool:** All 9 attacks are structural (trigger parser/
renderer code paths, not just data substitution).

**Tests:** Parametrized test per attack verifying tag is present
and empty after mutation. Integration test with round-trip serialize.

**Effort:** 1 session (~2 hours).

### Binary encapsulation attacks (enhance CompressedPixelFuzzer)

**Goal:** Add CVE-proven encapsulated pixel data attacks that
target the fragment parsing arithmetic. Every major DICOM library
has had CVEs here.

**New sub-attacks (6 total):**

1. `_ultra_short_fragment`: Create encapsulated PixelData fragment
   (FFFE,E000 Item) with length 0, 1, or 2 bytes. Triggers unsigned
   integer underflow when parser does `buffer[length - 3]`.
   (CVE-2025-11266, GDCM <= 3.0.24, CISA ICSMA-25-345-01)

   Concrete bytes:

   ```
   FE FF 00 E0 00 00 00 00  # Fragment Item, length=0
   FE FF 00 E0 01 00 00 00 FF  # Fragment Item, length=1
   FE FF 00 E0 02 00 00 00 FF D8  # Fragment Item, length=2
   ```

2. `_remove_sequence_delimiter`: Strip the final 8 bytes
   (FFFE,E0DD + 0x00000000) from encapsulated pixel data. Parser
   reads past end of data. (fo-dicom #1339, fixed 5.1.4)

3. `_delimiter_in_fragment_content`: Inject `\xFE\xFF\xDD\xE0`
   (SequenceDelimitationItem tag bytes) inside a pixel data
   fragment's content. Parser mistakenly treats it as end-of-data,
   then parses remaining pixel bytes as DICOM tags.
   (pydicom #1140)

4. `_zero_length_final_fragment`: Add an empty (0-length) fragment
   as the last fragment before the SequenceDelimitationItem.
   (fo-dicom #1586)

5. `_orphan_delimiter_at_eof`: Append raw delimiter bytes
   (FE FF 0D E0 or FE FF DD E0) after the dataset, outside any
   sequence context. (fo-dicom #1958)

6. `_fragment_offset_underflow`: Set Basic Offset Table entry to
   a value larger than the actual fragment data, causing the parser
   to compute a negative (underflowed) buffer index when subtracting
   fragment header sizes. (CVE-2025-11266 arithmetic pattern)

**Implementation:** These operate at the binary level (mutate_bytes)
since pydicom's API normalizes the encapsulation. Use the existing
`_apply_binary_mutations` path in StructureFuzzer as reference.

**Tests:** Each sub-attack tested with a minimal encapsulated
dataset (CT with JPEG Baseline transfer syntax).

**Effort:** 2 sessions (~4 hours total).

### VR field corruption at binary level (enhance StructureFuzzer)

**Goal:** Corrupt the 2-byte VR field in Explicit VR transfer
syntax at the binary level after serialization. Targets .NET
parser VR detection logic.

**New sub-attacks (4 total):**

1. `_whitespace_vr`: Replace VR bytes with `\x20\x0A` (space +
   line feed). fo-dicom VR detection fails. (fo-dicom #1847)

2. `_null_vr`: Replace VR bytes with `\x00\x00`.

3. `_dash_vr`: Replace VR bytes with `\x2D\x2D` ("--"). Parser
   returns `DicomReaderResult.Suspended`, truncating dataset.
   (fo-dicom #1660)

4. `_vr_un_substitution`: Replace known VRs (UI, DS, CS, LO)
   with UN. Forces parser into fallback path with different
   length semantics. (fo-dicom #1941)

**Implementation:** Binary-level via `mutate_bytes()`. Find VR
byte positions by scanning for known VR strings at tag+4 offsets.

**Tests:** Verify binary output contains corrupted VR at expected
offset. Round-trip test that pydicom can still parse with force=True.

**Effort:** 1 session (~2 hours).

### Overlay origin attacks (new sub-attacks in PixelFuzzer or new OverlayFuzzer)

**Goal:** Test overlay rendering with invalid overlay parameters.

**Attacks (3 total):**

1. `_negative_overlay_origin`: Set (6000,0050) OverlayOrigin to
   `[-100, -100]`. IndexOutOfRangeException in overlay rendering.
   (fo-dicom #1559)

2. `_overlay_dimension_mismatch`: Set (6000,0010) OverlayRows and
   (6000,0011) OverlayColumns larger than image dimensions.

3. `_overlay_bit_position`: Set (6000,0102) OverlayBitPosition to
   non-zero value with (6000,0100) OverlayBitsAllocated = 1.
   Undefined behavior in bit extraction. (fo-dicom #2087)

**Effort:** 1 session (~1.5 hours).

### Private SQ as last file element (enhance PrivateTagFuzzer)

**Goal:** Trigger parser read-past-EOF on private sequences.

**Attack:** Append a private SQ tag (e.g., 7001,1001) as the very
last element in the serialized file. Give it one or more empty
sequence items (Item tag + Item Delimiter with no data between).
Parser's `IsPrivateSequence()` tries to peek beyond EOF.
(fo-dicom #487, #220)

**Effort:** 0.5 session (add to existing PrivateTagFuzzer).

### Odd-length pixel data (enhance PixelFuzzer)

**Goal:** Force pixel data to have an odd byte count. Violates
DICOM Part 5 Section 8 (all elements must have even length).
Triggers padding/truncation bugs in transcoding and rendering.
(fo-dicom #1403)

**Effort:** 0.5 session.

---

## Format fuzzing -- P1: Modality expansion

### MR modality-specific fuzzing

Expand DictionaryFuzzer or CalibrationFuzzer with MR-specific tags:
EchoTime (0018,0081), RepetitionTime (0018,0080), FlipAngle
(0018,1314), InversionTime (0018,0082), MagneticFieldStrength
(0018,0087), DiffusionBValue. MR seed already in corpus.

**Effort:** 1 session.

### DX/CR modality fuzzer

DX seed already in corpus. Add DX-specific attacks: ExposureInuAs,
DistanceSourceToDetector, ExposureTime, KVP boundary values.

**Effort:** 1 session.

---

## Multiframe fuzzing -- P1

### Functional group crash attacks

Empty/invalid values in PerFrameFunctionalGroupsSequence:

- Empty FrameContentSequence items
- Invalid numeric values in PlanePositionSequence
- Mismatched item count vs NumberOfFrames
- Empty SharedFunctionalGroupsSequence (fo-dicom #1884)

**Effort:** 1 session.

### Concurrent field mismatches

NumberOfFrames + BitsAllocated + SamplesPerPixel all wrong
simultaneously. Parsers assume mutually-consistent fields.

**Effort:** 1 session.

---

## Series/Study fuzzing -- P2

### Temporal (4D) series attacks

InstanceCreationTime chaos, temporal delta violations,
discontinuity injection for cardiac/perfusion imaging.

**Effort:** 2 sessions.

### Registration geometry attacks

Multiple series with same FrameOfReferenceUID but conflicting
ImagePositionPatient. FoR UID orphaning.

**Effort:** 1 session.

---

## Network protocol fuzzing -- Prototype to Production

### P0: PDU binary format (PS3.8 Section 7)

7 PDU type constructors: A-ASSOCIATE-RQ/AC/RJ, P-DATA-TF,
A-RELEASE-RQ/RP, A-ABORT. Variable-length encoding. Foundation
for all network fuzzing.

**Effort:** 2-3 sessions.

### P0: State machine wiring

Connect DICOMStateMachine to actual PDU receipt/send. Implement
StateAwareFuzzer.fuzz() for invalid state transitions.

**Effort:** 1-2 sessions.

### P0: DIMSE command generation

C-STORE, C-FIND, C-MOVE, C-ECHO PDU packing with embedded datasets.

**Effort:** 2 sessions.

### P1: Real TLS testing

Replace hardcoded vulnerability enumeration with actual TLS probes.

**Effort:** 1-2 sessions.

### P1: Query/Retrieve fuzzing

C-FIND/C-MOVE with query tag corruption, wildcard injection.

**Effort:** 1-2 sessions.

---

## Campaign & validation

### Full campaign run against Hermes

Overnight run with 9 seeds + 30s timeout. Analyze crash-by-strategy.

### Second-pass structural audit

After campaign data: remove/redesign zero-crash strategies.

---

## Low priority / deferred

- Structural/content code comments
- CrashAnalyzer rename
- Test flakiness investigation
- Strategy effectiveness charts
- End-of-campaign auto-triage
- VOI LUT / Palette color corruption
- Authentication negotiation fuzzing

---

## Long-term vision

### Full DICOM SOP Class coverage

186 Storage SOP Classes. Current 29 strategies. Target ~40-44.

### Coverage-guided fuzzing

DynamoRIO/Frida instrumentation, coverage feedback, seed selection.

---

## Completed (reference only)

| Item                                                           | PR(s)                             |
| -------------------------------------------------------------- | --------------------------------- |
| Audit mutations for crash potential (structural/content split) | #188, #198                        |
| Formalize variant terminology + replay --decompose             | #195, #184, #197                  |
| Re-encode pixel data (PixelReencodingFuzzer)                   | #204                              |
| Attack mode / scope filtering (--target-type)                  | #205                              |
| Move mutate_patient_info to utils/anonymizer.py                | #201                              |
| Centralize attack payloads in dicom_dictionaries               | #194                              |
| Seed corpus diversification (SEG, RTSS, PDF)                   | #206                              |
| Unify reporting CSS/HTML systems                               | #200                              |
| Make reports minimalistic and professional                     | #200 (CSS cleaned up)             |
| Consolidate crash data types (CrashRecord)                     | #203                              |
| Add can_mutate() guards to multiframe strategies               | #202                              |
| Register multiframe strategies in DicomMutator dispatch        | (all 10 registered)               |
| Track binary mutations in MutationRecord                       | #197                              |
| Seed fuzzer engine + log RNG seed                              | #184, #185                        |
| crash_by_strategy telemetry                                    | #191                              |
| Structural mutation reweighting                                | #188                              |
| Merge/disambiguate corpus_minimization vs corpus_minimizer     | (corpus_minimizer.py deleted)     |
| CrashRecord.reproduction_command always None                   | (conditionally populated)         |
| Pre-mutation safety checks (--safety-mode)                     | #209                              |
| Seed file sanitization (dicom-fuzzer sanitize)                 | #210                              |
| Seed corpus diversification (MR, DX, NM, PT, RTDOSE, RTSTRUCT) | (seed corpus populated)           |
| Surface multiframe attack type via last_variant                | #217                              |
| Mutation taxonomy (boundary/malformed/injection)               | Dropped (research: not effective) |
| Crash discovery saturation curve                               | Dropped (insufficient crash data) |
