# Backlog

Prioritized work items for reaching a complete DICOM fuzzing product.
Organized by branch and priority. Each item sized for 1 atomic session.

---

## Format fuzzing (Branch 1 -- Production)

### P0: Present-but-empty value attacks (.NET crash pattern)

**Rationale:** fo-dicom (the .NET DICOM library Hermes likely uses)
has crashed repeatedly on tags that are _present but empty_. .NET code
does `element.Get<string>()` without null/empty checks. This is the
highest-yield gap for improving crash rate against Hermes.

**New attacks to add (to existing fuzzers or a new EmptyValueFuzzer):**

- Empty `PixelSpacing` (0028,0030) -- rendering crash (fo-dicom #2043)
- Empty `VOILUTFunction` (0028,1056) -- rendering crash (fo-dicom #1891)
- Empty `SpecificCharacterSet` (0008,0005) -- write crash (fo-dicom #1879)
- Empty `ImagePositionPatient` (0020,0032) -- geometry crash (fo-dicom #2067)
- Empty `ImageOrientationPatient` (0020,0037) -- geometry crash (fo-dicom #2067)
- Empty `WindowWidth` (0028,1051) / `WindowCenter` (0028,1050)
- `WindowWidth` = 0 or -1 (fo-dicom #1905)
- Comma-decimal in DS values: "1,5" not "1.5" (fo-dicom #1296)
- Empty `SharedFunctionalGroupsSequence` (5200,9229) -- zero items,
  causes IndexOutOfBounds (fo-dicom #1884)

**Effort:** 1 day. High crash-rate impact.

### P0: Binary delimiter attacks (CVE pattern)

**Rationale:** Every major DICOM library has had CVEs from malformed
sequence/pixel data delimiters: libdicom use-after-free (CVE-2024-24793),
fo-dicom missing SequenceDelimitationItem (#1339), GDCM fragment
underflow (CVE-2025-11266).

**New attacks (enhance CompressedPixelFuzzer + StructureFuzzer):**

- Remove `SequenceDelimitationItem` (FFFE,E0DD) from encapsulated
  pixel data -- forces parser to read past end of data
- Zero-length final pixel data fragment (fo-dicom #1586)
- Fragment length that triggers unsigned integer underflow in offset
  calculation (CVE-2025-11266 pattern)
- Append orphan delimiter items (FFFE,E00D / FFFE,E0DD) at file EOF
  outside any sequence (fo-dicom #1958)
- Embedded delimiter bytes inside fragment data (pydicom #1140)
- Fragment count vs NumberOfFrames mismatch with specific arithmetic
  relationships (not random -- crafted to trigger underflow)

**Effort:** 2 days. High crash-rate impact (CVE-proven patterns).

### P1: VR confusion attacks

**Rationale:** .NET parsers that switch behavior based on VR crash
when VR=UN is used for tags with well-known VRs (fo-dicom #1941).

**New attacks (enhance HeaderFuzzer):**

- Replace known VRs with UN at binary level after serialization
- Whitespace bytes (0x20, 0x0A, 0x0D) in length field positions
  (fo-dicom #1847 -- blank char in length field)
- Blank characters in VR field positions
- Group length tags with VR=UN (fo-dicom #1941)

**Effort:** 1 day. Medium crash-rate impact.

### P1: MR modality-specific fuzzing

Expand DictionaryFuzzer or CalibrationFuzzer with MR-specific tags:
EchoTime, RepetitionTime, FlipAngle, InversionTime,
MagneticFieldStrength, DiffusionBValue. MR is ~30% of clinical DICOM
volume. MR seed file already in corpus. Low-medium effort.

### P2: Deep sequence nesting variants

The one confirmed Hermes crash was from self-referencing sequences.
Explore more variations:

- Mutual references (A->B->A)
- Long chains (A->B->C->...->Z->A)
- Sequence items with corrupted delimitation bytes
- Self-referencing at different nesting depths

**Effort:** 1 day.

### P2: Transfer syntax codec attacks

PixelReencodingFuzzer does RLE. Extend to JPEG Baseline, JPEG 2000,
JPEG-LS with corrupted codec streams that are structurally valid
enough to reach the decoder but corrupt enough to trigger buffer
overflows in the decompression path.

**Effort:** 2-3 days.

### P2: Extend modality coverage

Currently 6 modality-specific fuzzers. Clinical gaps: DX, US, MG,
Enhanced CT/MR. Each needs seed files + SOP-specific fuzzers.

---

## Multiframe fuzzing (Branch 2 -- Production)

### P1: Functional group attacks (.NET crash pattern)

Empty/invalid values in PerFrameFunctionalGroupsSequence items cause
IndexOutOfBounds in fo-dicom rendering. Add:

- Empty FrameContentSequence items
- Invalid numeric values in PlanePositionSequence
- Invalid PlaneOrientationSequence values
- Mismatched number of items vs NumberOfFrames

**Effort:** 1 day.

### P1: Concurrent field mismatches

Strategies currently apply 1 attack per invocation. Add multi-field
contradictions (NumberOfFrames + BitsAllocated + SamplesPerPixel all
wrong simultaneously). Parsers assume mutually-consistent fields.

**Effort:** 1 day.

### P2: Shared vs per-frame attribute conflicts

Both SharedFunctionalGroupsSequence and PerFrameFunctionalGroupsSequence
present with same tag but conflicting values. Tests parser
priority/override logic.

**Effort:** 1 day.

---

## Series/Study fuzzing (Branch 3 -- Production)

### P2: Temporal (4D) series attacks

Add TemporalSeriesStrategy: InstanceCreationTime chaos, frame-to-frame
temporal delta violations, temporal discontinuity injection.

**Effort:** 2 days.

### P2: Registration geometry attacks

Multiple series claiming same FrameOfReferenceUID with conflicting
ImagePositionPatient. FoR UID orphaning.

**Effort:** 1 day.

---

## Network protocol fuzzing (Branch 4 -- Prototype)

Architecture is well-designed but every core function is a stub.

### P0: Implement PDU binary format (PS3.8 Section 7)

7 PDU type constructors: A-ASSOCIATE-RQ/AC/RJ, P-DATA-TF,
A-RELEASE-RQ/RP, A-ABORT. This is the foundation.

**Effort:** 2-3 days.

### P0: Wire state machine to PDU receiver

Connect DICOMStateMachine transitions to actual PDU receipt/send.
Implement StateAwareFuzzer.fuzz().

**Effort:** 1-2 days.

### P0: Implement DIMSE command generation

C-STORE, C-FIND, C-MOVE, C-ECHO PDU packing with embedded datasets.

**Effort:** 2 days.

### P1: Implement real TLS testing

Replace hardcoded vulnerability enumeration with actual TLS probes.

**Effort:** 1-2 days.

### P1: Query/Retrieve fuzzing

C-FIND/C-MOVE with complex query tag corruption, wildcard injection.

**Effort:** 1-2 days.

### P2: Authentication negotiation fuzzing

ACSE user identity negotiation fuzzing at association level.

**Effort:** 1 day.

---

## Campaign & validation

### Run full campaign against Hermes

Full overnight run with 9 seeds, analyze crash-by-strategy data.
No code changes -- just runtime. Blocked on completing the run.

### Second-pass structural audit

After campaign data: review DictionaryFuzzer, SequenceFuzzer,
ReferenceFuzzer, CalibrationFuzzer low-value methods. Remove or
redesign content-only strategies that produce zero crashes.

---

## Low priority / deferred

- Structural/content code comments (pure documentation)
- CrashAnalyzer rename (no functional impact)
- Test flakiness investigation (low failure rate)
- Strategy effectiveness charts (text-table already works)
- End-of-campaign auto-triage (needs hook point decision)
- Overlay data attacks (rare rendering path)
- VOI LUT / Palette color corruption (uncommon)

---

## Long-term vision

### Full DICOM SOP Class coverage

186 Storage SOP Classes, ~17 domains. Current 29 strategies cover
the core. Full coverage: ~40-44 fuzzers. Diminishing returns past ~30.

### Coverage-guided fuzzing

Instrument target (DynamoRIO/Frida), feed coverage back, implement
seed selection. Major architectural change.

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
