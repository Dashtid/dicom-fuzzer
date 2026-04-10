# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

## Format fuzzing -- P0: Crash-rate improvements

(All P0 items completed in PRs #229-#232.)

---

## Format fuzzing -- P1: CVE gap coverage

Items identified by the CVE-to-strategy coverage audit
(`docs/CVE_AUDIT.md`). Each gap references specific
CVEs and proposes the target fuzzer.

### G1: PALETTE COLOR + LUT overflow (extend PixelFuzzer)

**Goal:** Set PhotometricInterpretation to "PALETTE COLOR" with
extreme Rows\*Columns that overflow 32-bit in LUT allocation,
and/or set LUT descriptor entry count larger than actual LUT data.

**CVEs:**

- Orthanc CVE-2026-5443: width\*height 32-bit overflow in
  PALETTE COLOR pixel validation -> heap buffer overflow
- Orthanc CVE-2026-5445: pixel indices > palette size -> OOB read
- GDCM CVE-2024-22391 (TALOS-2024-1924): LookupTable::SetLUT
  entry count > buffer -> heap buffer overflow

**Tags:** PhotometricInterpretation (0028,0004),
RedPaletteColorLookupTableDescriptor (0028,1101),
RedPaletteColorLookupTableData (0028,1201), Rows, Columns.

**Effort:** 1 session (~1 hour).

### G9: HighBit >= BitsAllocated (extend PixelFuzzer)

**Goal:** Set HighBit to a value >= BitsAllocated. The pixel
min/max calculation uses HighBit as an array index without
bounds checking, producing an OOB write.

**CVEs:**

- DCMTK CVE-2024-52333 (TALOS-2024-2121, CVSS 8.4):
  DiInputPixelTemplate::determineMinMax() uses HighBit as index
- DCMTK CVE-2024-47796 (TALOS-2024-2122, CVSS 8.4): same
  class, `nowindow` functionality

**Tags:** HighBit (0028,0102), BitsAllocated (0028,0100).

**Effort:** 0.5 session (verify existing \_bit_depth_attack
covers this exact combo; add explicit attack if not).

### G12: Photometric Interpretation -> wrong codec path (extend PixelFuzzer)

**Goal:** Set PhotometricInterpretation to YBR_RCT, YBR_ICT,
or other uncommon values on pixel data encoded for a different
color space. The JPEG codec selects the wrong color conversion
function, reading/writing with mismatched buffer expectations.

**CVEs:**

- GDCM CVE-2025-53618 (TALOS-2025-2210, CVSS 7.4):
  JPEGBITSCodec grayscale_convert() invoked with wrong buffer
- GDCM CVE-2025-53619: null_convert() path
- DCMTK CVE-2025-9732 (CWE-787): OOB write in YBR-to-RGB

**Tags:** PhotometricInterpretation (0028,0004).

**Effort:** 0.5 session (add YBR_RCT, YBR_ICT, YBR_FULL_422
to existing \_photometric_confusion).

### G4: UL-as-US dimension type confusion (extend StructureFuzzer)

**Goal:** Replace VR "US" with "UL" on Rows/Columns tags at the
binary level. UL expects 4-byte value; the file still has a
2-byte value, so the parser reads into the next element.

**CVE:** Orthanc CVE-2026-5442 -- dimension fields as VR UL
instead of US -> huge dimensions overflow frame-size calculation.

**Tags:** Rows (0028,0010), Columns (0028,0011) -- binary VR.

**Effort:** 0.5 session.

### G8: Non-standard VR in file meta (extend ConformanceFuzzer or StructureFuzzer)

**Goal:** Insert a DICOM element with fabricated VR (e.g., "ZZ")
in the File Meta Information header (group 0002). Parsers that
allocate based on VR-implied length without bounds checking
consume gigabytes of heap from a tiny file.

**CVE:** GDCM CVE-2026-3650 (CWE-401, **UNPATCHED** as of
April 2026): ~150-byte file with non-standard VR in file meta
causes allocation of ~4.2 GB. CISA ICSMA-26-083-01.

**Effort:** 0.5 session.

### G6: Format string injection (extend HeaderFuzzer or EncodingFuzzer)

**Goal:** Add %s, %n, %x, %p payloads to string VR fields
(LO, SH, PN, LT). Targets C/C++ parsers that pass DICOM string
values to printf-family functions.

**CVE:** Merge DICOM CVE-2024-23914 (CWE-134): format string
vuln in MC_Open_Association() via Application Context Name.

**Effort:** 0.5 session.

### G13: OverlayData shorter than dimensions (extend PixelFuzzer)

**Goal:** Set OverlayRows\*OverlayColumns to imply more overlay
bytes than OverlayData actually contains. Renderer reads past
the end of the overlay buffer.

**Issue:** fo-dicom #1728: RenderImage IndexOutOfRangeException
in BitArray.Get when OverlayData is shorter than expected.

**Note:** Existing overlay attacks create full overlay data via
\_add_overlay_scaffold(). Need a variant with truncated data.

**Effort:** 0.5 session.

### G7: VOI LUT / Palette LUT corruption

**Goal:** Add VOILUTSequence with type-confused entries (e.g.,
OW data where IS is expected), and Palette LUT with mismatched
descriptor (declared entry count != actual data size).

**CVEs:**

- DCMTK CVE-2024-28130 (TALOS-2024-1957, CVSS 7.5): incorrect
  type conversion in DVPSSoftcopyVOI_PList::createFromImage()
- fo-dicom #1062: VOI LUT Sequence without Modality LUT ->
  IndexOutOfRangeException

**Effort:** 1-2 sessions (new fuzzer or extend CalibrationFuzzer).

### G2: JPEG-LS codec corruption (extend CompressedPixelFuzzer)

**Goal:** Add JPEG-LS Lossless (1.2.840.10008.1.2.4.80) and
Near-Lossless (1.2.840.10008.1.2.4.81) transfer syntax support
with malformed JPEG-LS codestream markers.

**CVE:** DCMTK CVE-2025-2357 (CWE-119): memory corruption in
dcmjpls JPEG-LS decoder.

**Effort:** 1 session.

### G10: Duplicate tags in file meta information (extend StructureFuzzer)

**Goal:** Insert duplicate elements in group 0002 (File Meta
Information). Parsers using hash-map insertion with
destroy-on-collision double-free the original element.

**CVEs:**

- libdicom CVE-2024-24793 (TALOS-2024-1931, CVSS 8.1):
  use-after-free from duplicate tags in file meta
- libdicom CVE-2024-24794: same, sequence end parsing

**Note:** StructureFuzzer.\_binary_duplicate_tag explicitly SKIPS
group 0002. This gap requires a new binary attack that targets
file meta specifically.

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

**Goal:** Create a DICOM file with Deflated Explicit VR Little
Endian transfer syntax (UID 1.2.840.10008.1.2.1.99) containing
a crafted deflate stream with >1000:1 compression ratio.

**CVEs:**

- Orthanc CVE-2026-5438 (CWE-400): gzip payload with no
  decompressed size limit -> memory exhaustion
- Orthanc CVE-2026-5439 (CWE-400): ZIP archive bomb via
  forged uncompressed size metadata
- ACM CCS 2022 research: Deflated LE transfer syntax as zip bomb

**Effort:** 2-4 sessions (new CompressedPixelFuzzer attack or
dedicated DecompressionBombFuzzer).

### G5: DICOMDIR path traversal

**Goal:** Generate malicious DICOMDIR with ReferencedFileID
containing "../" sequences or absolute paths. FileSet operations
then read/write/delete outside the DICOM file-set root.

**CVE:** pydicom CVE-2026-32711 (CWE-22, CVSS 7.8): pathlib
`/` operator discards left operand if right is absolute.
Fixed pydicom 3.0.2 / 2.4.5.

**Effort:** 2 sessions (new fuzzer, different attack surface).

### G11: Preamble polyglot (PE/ELF/JSON payload)

**Goal:** Inject PE, ELF, or JSON headers into the 128-byte
DICOM preamble. The file is simultaneously valid DICOM and
valid executable/data. Targets systems that dispatch on file
magic or process the preamble as structured data.

**CVEs / Research:**

- CVE-2019-11687: DICOM PE polyglot (original research)
- Praetorian ELFDICOM 2025: Linux ELF variant
- Orthanc CVE-2023-33466: JSON in preamble -> config overwrite
  -> Lua RCE chain

**Effort:** 2 sessions (extend HeaderFuzzer or new attack).

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

**Goal:** Assemble a diverse, realistic seed corpus in the local-only
`dicom-seeds/` directory (gitignored as of 1.10.1). Replaces the removed
bundled stub corpus with seeds that actually exercise parser code paths.

**Quality bar (per modality):**

- **CT**: 512x512, 12-bit, IVLE. At least 3 variants from different
  vendors (GE, Siemens, Canon) to capture divergent private-tag patterns.
- **MR**: 256x256 or 320x320, 12-bit, IVLE. At least 2 sequences
  (T1, T2) and 1 enhanced MR (multiframe) example.
- **DX**: 1024x1024+, 8-14 bit. CR and DR variants.
- **NM**: Multiframe (>50 frames), 128x128, 16-bit IVLE. One dual-isotope
  and one SPECT example.
- **PET**: 128x128 or 144x144, 16-bit, IVLE. Both attenuation-corrected
  and uncorrected variants.
- **RT Dose**: Full dose cube (>100 frames), 32-bit float, EVLE.
- **RT Struct**: Real structure set with >=20 ROIs, dense contour data
  (>=10k points total). The 2.5KB stub previously bundled was useless.
- **SEG**: Multiframe segmentation with multiple segments, 1-bit,
  matching a real CT/MR geometry.
- **Encapsulated PDF**: Real clinical report PDF (>=5 pages).

**Sources:**

1. **TCIA (The Cancer Imaging Archive)** -- public, already de-identified.
   Prioritize LIDC-IDRI for CT, BraTS for MR, NSCLC-Radiomics for RT.
2. **pydicom/pydicom-data** -- small but diverse, CC0-licensed.
3. **In-house clinical data** sanitized via `dicom-fuzzer sanitize`.
   Review sanitized output for residual PHI before committing to local
   corpus (check PatientName, PatientID, InstitutionName, private tags).

**Process:**

1. Download candidate seeds to a staging area.
2. Verify with `pydicom.dcmread()` that each parses cleanly (baseline).
3. Run `dicom-fuzzer sanitize` even on "public" datasets as defense-in-depth.
4. Inspect file sizes and header dimensions against the quality bar above.
5. Copy into the appropriate `dicom-seeds/<modality>/` subdirectory using
   the filename convention documented in `dicom-seeds/README.md`.
6. Run a baseline `dicom-fuzzer <seed> -c 10` dry-run and confirm all
   modality-applicable strategies fire (non-zero hit counts in output).
7. Keep a local note of the provenance of each seed (source dataset,
   series UID, any manual modifications) outside version control.

**Non-goals:**

- **Do not commit any of these files.** The `.gitignore` excludes `*.dcm`
  globally and the `dicom-seeds/**` exception was removed in 1.10.1.
- **Do not redistribute** -- even "public" dataset files often have
  license constraints that prohibit redistribution as part of a tool.

**Effort:** Ongoing. Start with CT (highest-value for Hermes campaign),
then MR, then RT. The full corpus is a multi-session effort.

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

| Item                                                            | PR(s)                             |
| --------------------------------------------------------------- | --------------------------------- |
| Audit mutations for crash potential (structural/content split)  | #188, #198                        |
| Formalize variant terminology + replay --decompose              | #195, #184, #197                  |
| Re-encode pixel data (PixelReencodingFuzzer)                    | #204                              |
| Attack mode / scope filtering (--target-type)                   | #205                              |
| Move mutate_patient_info to utils/anonymizer.py                 | #201                              |
| Centralize attack payloads in dicom_dictionaries                | #194                              |
| Seed corpus diversification (SEG, RTSS, PDF)                    | #206                              |
| Unify reporting CSS/HTML systems                                | #200                              |
| Make reports minimalistic and professional                      | #200 (CSS cleaned up)             |
| Consolidate crash data types (CrashRecord)                      | #203                              |
| Add can_mutate() guards to multiframe strategies                | #202                              |
| Register multiframe strategies in DicomMutator dispatch         | (all 10 registered)               |
| Track binary mutations in MutationRecord                        | #197                              |
| Seed fuzzer engine + log RNG seed                               | #184, #185                        |
| crash_by_strategy telemetry                                     | #191                              |
| Structural mutation reweighting                                 | #188                              |
| Merge/disambiguate corpus_minimization vs corpus_minimizer      | (corpus_minimizer.py deleted)     |
| CrashRecord.reproduction_command always None                    | (conditionally populated)         |
| Pre-mutation safety checks (--safety-mode)                      | #209                              |
| Seed file sanitization (dicom-fuzzer sanitize)                  | #210                              |
| Seed corpus diversification (MR, DX, NM, PT, RTDOSE, RTSTRUCT)  | (seed corpus populated)           |
| Surface multiframe attack type via last_variant                 | #217                              |
| Mutation taxonomy (boundary/malformed/injection)                | Dropped (research: not effective) |
| Crash discovery saturation curve                                | Dropped (insufficient crash data) |
| EmptyValueFuzzer (9 present-but-empty .NET crash attacks)       | #229                              |
| StructureFuzzer binary VR corruption (whitespace/null/dash/UN)  | #230                              |
| CompressedPixelFuzzer binary encapsulation (6 fragment attacks) | #231                              |
| PixelFuzzer overlay attacks (origin/dimension/bit-position)     | (3 structural attacks)            |
| PrivateTagFuzzer private SQ at EOF                              | (1 structural attack)             |
| PixelFuzzer odd-length pixel data                               | (mutate_bytes override added)     |
| CVE-to-strategy coverage audit (~130 CVEs, 13 gaps)             | docs/CVE_AUDIT.md                 |
