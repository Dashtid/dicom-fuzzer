# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

## Format fuzzing -- P1: CVE gap coverage (quick wins)

Items identified by the CVE-to-strategy coverage audit
(`docs/CVE_AUDIT.md`). Each gap references specific CVEs and
proposes the target fuzzer. These 7 items can be done in a single
combined session (~4h total).

### G1: PALETTE COLOR + LUT overflow (extend PixelFuzzer)

Set PhotometricInterpretation to "PALETTE COLOR" with extreme
Rows\*Columns that overflow 32-bit in LUT allocation, and/or set
LUT descriptor entry count larger than actual LUT data.

- Orthanc CVE-2026-5443: width\*height 32-bit overflow in
  PALETTE COLOR pixel validation -> heap buffer overflow
- Orthanc CVE-2026-5445: pixel indices > palette size -> OOB read
- GDCM CVE-2024-22391 (TALOS-2024-1924): LookupTable::SetLUT
  entry count > buffer -> heap buffer overflow

Tags: PhotometricInterpretation (0028,0004),
RedPaletteColorLookupTableDescriptor (0028,1101),
RedPaletteColorLookupTableData (0028,1201), Rows, Columns.

**Effort:** ~1 hour.

### G9: HighBit >= BitsAllocated (extend PixelFuzzer)

Set HighBit to a value >= BitsAllocated. The pixel min/max
calculation uses HighBit as an array index without bounds
checking, producing an OOB write.

- DCMTK CVE-2024-52333 (TALOS-2024-2121, CVSS 8.4):
  determineMinMax() uses HighBit as index without bounds check
- DCMTK CVE-2024-47796 (TALOS-2024-2122, CVSS 8.4): same
  class, `nowindow` functionality

Existing `_bit_depth_attack` sets HighBit = BitsStored + 10 but
never explicitly >= BitsAllocated. Add a new attack type.

Tags: HighBit (0028,0102), BitsAllocated (0028,0100).

**Effort:** ~0.5 hour.

### G12: Photometric Interpretation -> wrong codec path (extend PixelFuzzer)

Set PhotometricInterpretation to YBR_RCT, YBR_ICT, YBR_FULL_422,
or other uncommon values on pixel data encoded for a different
color space. The JPEG codec selects the wrong color conversion
function, reading/writing with mismatched buffer expectations.

- GDCM CVE-2025-53618 (TALOS-2025-2210, CVSS 7.4):
  JPEGBITSCodec grayscale_convert() invoked with wrong buffer
- GDCM CVE-2025-53619: null_convert() path
- DCMTK CVE-2025-9732 (CWE-787): OOB write in YBR-to-RGB

Existing `_photometric_confusion` uses INVALID, MONOCHROME3, etc.
but is missing all YBR variants. Add them to the payload list.

Tags: PhotometricInterpretation (0028,0004).

**Effort:** ~0.5 hour.

### G13: OverlayData shorter than dimensions (extend PixelFuzzer)

Set OverlayRows\*OverlayColumns to imply more overlay bytes than
OverlayData actually contains. Renderer reads past the end of the
overlay buffer.

- fo-dicom #1728: RenderImage IndexOutOfRangeException in
  BitArray.Get when OverlayData is shorter than expected

Existing overlay attacks use `_add_overlay_scaffold()` which
creates correctly-sized data. Add a new method that sets full
dimensions but truncates OverlayData to 2 bytes.

**Effort:** ~0.5 hour.

### G4: UL-as-US dimension type confusion (extend StructureFuzzer)

Replace VR "US" with "UL" on Rows/Columns tags at the binary
level. UL expects 4-byte value; the file still has a 2-byte
value, so the parser reads into the next element causing integer
overflow in frame-size calculation.

- Orthanc CVE-2026-5442: dimension fields as VR UL instead of
  US -> huge dimensions overflow frame-size calculation

New binary attack `_binary_dimension_vr_ul` targeting tag
(0028,0010) or (0028,0011) specifically. Binary attack pool
grows from 7 to 8.

**Effort:** ~0.5 hour.

### G8: Non-standard VR in file meta (extend StructureFuzzer)

Replace a group 0002 element's VR with a fabricated 2-byte string
(e.g., "ZZ") at the binary level. Parsers that allocate based on
VR-implied length without bounds checking consume gigabytes of
heap from a tiny file.

- GDCM CVE-2026-3650 (CWE-401, **UNPATCHED** as of April 2026):
  ~150-byte file with non-standard VR in file meta causes
  allocation of ~4.2 GB. CISA ICSMA-26-083-01.

Note: existing `_binary_vr_un_substitution` and all VR attacks
skip group 0002 via `_parse_dicom_elements`. New binary attack
`_binary_nonstandard_vr_meta` must target group 0002 directly.
Binary attack pool grows from 8 to 9.

**Effort:** ~0.5 hour.

### G6: Format string injection (extend HeaderFuzzer)

Add %s, %n, %x, %p payloads to string VR mutation lists (LO, SH,
PN, LT, ST) in the VR_MUTATIONS constant. Targets C/C++ parsers
that pass DICOM string values to printf-family functions.

- Merge DICOM CVE-2024-23914 (CWE-134): format string vuln in
  MC_Open_Association() via Application Context Name

No new methods -- just expand existing VR_MUTATIONS payload
lists with format string patterns.

**Effort:** ~0.5 hour.

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
