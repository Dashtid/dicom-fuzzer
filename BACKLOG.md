# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

## Format fuzzing -- P1: CVE gap coverage (medium effort)

### G7: VOI LUT / Palette LUT corruption

Add VOILUTSequence with type-confused entries (e.g., OW data
where IS is expected), and Palette LUT with mismatched descriptor
(declared entry count != actual data size).

- DCMTK CVE-2024-28130 (TALOS-2024-1957, CVSS 7.5): incorrect
  type conversion in DVPSSoftcopyVOI_PList::createFromImage()
- fo-dicom #1062: VOI LUT Sequence without Modality LUT ->
  IndexOutOfRangeException

**Effort:** 1-2 sessions. New fuzzer or extend CalibrationFuzzer.

### G2: JPEG-LS codec corruption (extend CompressedPixelFuzzer)

Add JPEG-LS Lossless (1.2.840.10008.1.2.4.80) and Near-Lossless
(1.2.840.10008.1.2.4.81) transfer syntax support with malformed
JPEG-LS codestream markers.

- DCMTK CVE-2025-2357 (CWE-119): memory corruption in dcmjpls
  JPEG-LS decoder

**Effort:** 1 session.

### G10: Duplicate tags in file meta (extend StructureFuzzer)

Insert duplicate elements in group 0002 (File Meta Information).
Parsers using hash-map insertion with destroy-on-collision
double-free the original element.

- libdicom CVE-2024-24793 (TALOS-2024-1931, CVSS 8.1):
  use-after-free from duplicate tags in file meta
- libdicom CVE-2024-24794: same, sequence end parsing

Note: `_binary_duplicate_tag` explicitly skips group 0002. This
gap requires a new binary attack targeting file meta specifically.

**Effort:** 1 session.

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

## Format fuzzing -- P2: CVE gap coverage (larger scope)

### G3: Decompression bomb (deflated transfer syntax)

Create a DICOM file with Deflated Explicit VR Little Endian
transfer syntax (UID 1.2.840.10008.1.2.1.99) containing a
crafted deflate stream with >1000:1 compression ratio.

- Orthanc CVE-2026-5438 (CWE-400): gzip payload with no
  decompressed size limit -> memory exhaustion
- Orthanc CVE-2026-5439 (CWE-400): ZIP archive bomb via forged
  uncompressed size metadata
- ACM CCS 2022 research: Deflated LE transfer syntax as zip bomb

**Effort:** 2-4 sessions.

### G5: DICOMDIR path traversal

Generate malicious DICOMDIR with ReferencedFileID containing
"../" sequences or absolute paths. FileSet operations then
read/write/delete outside the DICOM file-set root.

- pydicom CVE-2026-32711 (CWE-22, CVSS 7.8): pathlib `/`
  operator discards left operand if right is absolute. Fixed
  pydicom 3.0.2 / 2.4.5.
- fo-dicom #1977: DicomDirectory deep record nesting -> recursive
  stack overflow (fixed 5.2.3)

**Effort:** 2 sessions (new fuzzer, different attack surface).

### G11: Preamble polyglot (PE/ELF/JSON payload)

Inject PE, ELF, or JSON headers into the 128-byte DICOM preamble.
The file is simultaneously valid DICOM and valid executable/data.
Targets systems that dispatch on file magic or process the preamble
as structured data.

- CVE-2019-11687: DICOM PE polyglot (original research)
- Praetorian ELFDICOM 2025: Linux ELF variant
- Orthanc CVE-2023-33466: JSON in preamble -> config overwrite
  -> Lua RCE chain

**Effort:** 2 sessions.

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

### Build local high-quality DICOM seed corpus

Assemble a diverse, realistic seed corpus in the local-only
`dicom-seeds/` directory (fully gitignored). See project wiki
for quality bar per modality and sourcing process.

**Effort:** Ongoing.

### Full campaign run

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
- Authentication negotiation fuzzing

---

## Long-term vision

### Full DICOM SOP Class coverage

186 Storage SOP Classes. Current 30 strategies. Target ~40-44.

### Coverage-guided fuzzing

DynamoRIO/Frida instrumentation, coverage feedback, seed selection.

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
| CrashRecord.reproduction_command always None                   | (conditionally populated)     |
| Pre-mutation safety checks (--safety-mode)                     | #209                          |
| Seed file sanitization (dicom-fuzzer sanitize)                 | #210                          |
| Seed corpus diversification (MR, DX, NM, PT, RTDOSE, RTSTRUCT) | (seed corpus populated)       |
| Surface multiframe attack type via last_variant                | #217                          |
| Mutation taxonomy (boundary/malformed/injection)               | Dropped (not effective)       |
| Crash discovery saturation curve                               | Dropped (insufficient data)   |
| EmptyValueFuzzer (9 present-but-empty .NET crash attacks)      | #229                          |
| StructureFuzzer binary VR corruption (4 attacks)               | #230                          |
| CompressedPixelFuzzer binary encapsulation (6 attacks)         | #231                          |
| Overlay attacks + private SQ at EOF + odd-length pixel data    | #232                          |
| Bump cryptography >= 46.0.7 (Dependabot #43)                   | #233                          |
| CVE-to-strategy coverage audit (~140 CVEs, 13 gaps, 2 rounds)  | #234, #235                    |
| Fully untrack dicom-seeds directory                            | #236                          |
| P1 CVE quick wins: G1, G4, G6, G8, G9, G12, G13 (7 gaps)       | (7 attacks across 3 fuzzers)  |
