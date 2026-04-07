# Backlog

Prioritized work items for reaching a complete DICOM fuzzing product.
Organized by branch (format, multiframe, series, network) and priority.

---

## Format fuzzing (Branch 1 -- Production)

### MR modality-specific fuzzing

Expand DictionaryFuzzer or CalibrationFuzzer with MR-specific tags:
EchoTime, RepetitionTime, FlipAngle, InversionTime,
MagneticFieldStrength, DiffusionBValue. MR is ~30% of clinical DICOM
volume. MR seed file already in corpus. Low-medium effort.

### Improve crash rate against hardened viewers

Only 1 crash found against Hermes in thousands of files. Investigate:

- **Binary-level stream fuzzing**: Corrupt raw DICOM element encoding
  (tag bytes, VR bytes, length fields) at byte level, not pydicom
  object level. Current fuzzers operate through pydicom's API which
  normalizes values -- the parser never sees truly malformed byte
  streams.
- **Deep sequence nesting variants**: The one confirmed crash was from
  recursive self-referencing sequences. Explore more variations:
  mutual references (A->B->A), long chains (A->B->C->...->Z->A),
  sequence items with corrupted delimitation bytes.
- **Transfer syntax / pixel data codec attacks**: PixelReencodingFuzzer
  does RLE. Extend to JPEG Baseline, JPEG 2000, JPEG-LS with
  corrupted codec streams that are structurally valid enough to reach
  the decoder.

### Extend modality coverage

Currently 6 modality-specific fuzzers. Clinical gaps:

- **DX (Digital X-ray)**: Already have seed. High volume modality.
- **US (Ultrasound)**: Multi-frame cine loops, SamplesPerPixel=3 (RGB)
- **MG (Mammography)**: CAD SR templates, tomosynthesis
- **Enhanced CT/MR**: Shared/per-frame functional groups (distinct
  from standard CT/MR IODs)

Each needs seed files + SOP-specific fuzzers. Do incrementally.

---

## Multiframe fuzzing (Branch 2 -- Production)

### Concurrent field mismatches

Strategies currently apply 1 attack per invocation. Add multi-field
contradictions (e.g., NumberOfFrames=100 AND BitsAllocated changed
AND SamplesPerPixel wrong simultaneously). Parsers often assume
mutually-consistent fields. Low effort.

### Shared vs per-frame attribute conflicts

Both SharedFunctionalGroupsSequence and PerFrameFunctionalGroupsSequence
can contain the same tag. Add attacks where both are present with
conflicting values -- tests parser priority/override logic. Low effort.

---

## Series/Study fuzzing (Branch 3 -- Production)

### Temporal (4D) series attacks

Medical imaging includes temporal dimension (cardiac, perfusion).
Add TemporalSeriesStrategy: InstanceCreationTime chaos, frame-to-frame
temporal delta violations, temporal discontinuity injection. Medium effort.

### Registration geometry attacks

FrameOfReferenceUID used in image registration. Add attacks where
multiple series claim same FoR with conflicting ImagePositionPatient,
or FoR UID orphaning (referenced series deleted). Low effort.

---

## Network protocol fuzzing (Branch 4 -- Prototype)

The architecture is well-designed (state machine, DIMSE commands, TLS,
PDU layer) but every core function is a stub. Bringing this to
production requires implementing the actual protocol layer.

### P0: Implement PDU binary format (PS3.8 Section 7)

Build the 7 PDU type constructors: A-ASSOCIATE-RQ/AC/RJ, P-DATA-TF,
A-RELEASE-RQ/RP, A-ABORT. Variable-length encoding, presentation
context negotiation, transfer syntax embedding. This is the
foundation -- nothing else works without it. 2-3 days.

### P0: Wire state machine to PDU receiver

Connect DICOMStateMachine transitions to actual PDU receipt/send.
Implement StateAwareFuzzer.fuzz() to generate PDU sequences that
exercise invalid state transitions. 1-2 days.

### P0: Implement DIMSE command generation

C-STORE, C-FIND, C-MOVE, C-ECHO PDU packing with embedded DICOM
datasets. Mutation at the DIMSE command level (corrupt command fields,
dataset embedding, fragment boundaries). 2 days.

### P0: Implement real TLS testing

Replace hardcoded vulnerability enumeration with actual TLS probes.
Real certificate validation bypass attempts, cipher suite negotiation
fuzzing, protocol version downgrade attacks. 1-2 days.

### P1: Query/Retrieve fuzzing

C-FIND/C-MOVE with complex query tag corruption, wildcard injection,
result set manipulation, query-level injection payloads. 1-2 days.

### P1: Authentication negotiation fuzzing

ACSE user identity negotiation fuzzing, auth bypass attempts at the
association level. 1 day.

---

## Empirically validate reweighting

Run campaign against Hermes with full seed corpus and analyze
crash-by-strategy data from session JSON. Baseline (pre-reweighting)
vs current code. No code changes needed -- just campaign runtime.
Blocked on completing a full overnight run.

### Second-pass structural audit

After campaign data: review DictionaryFuzzer (entire strategy is
content, zero crash potential), SequenceFuzzer low-value methods,
ReferenceFuzzer low-value methods, CalibrationFuzzer content methods.
Depends on campaign results.

---

## Low priority / deferred

### Enforce structural/content classification as code comments

Pure documentation. Do as part of future fuzzer modifications.

### Review CrashAnalyzer naming

Rename to ExceptionAnalyzer. No functional impact.

### Investigate test flakiness under load

test_files_are_valid_dicom fails intermittently. Low priority.

### Wire strategy effectiveness charts

CampaignAnalyzer/FuzzingVisualizer exist but are unwired. Text-table
path already answers the FDA question.

### End-of-campaign auto-triage

Call triage automatically at campaign end. Needs hook point decision.

---

## Long-term vision

### Full DICOM SOP Class coverage

186 active Storage SOP Class UIDs across ~17 domains. Current: 29
strategies. Full coverage: ~40-44 fuzzers. Diminishing returns past ~30.

### Coverage-guided fuzzing

Instrument the target (DynamoRIO/Frida/SanCov), feed coverage back,
implement seed selection. Major architectural change.

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
