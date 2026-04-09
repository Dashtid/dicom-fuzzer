# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

## Format fuzzing -- P0: Crash-rate improvements

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

### CVE-to-strategy coverage audit

**Goal:** Systematic cross-reference of every known DICOM CVE
(2022-2026) against existing mutation strategies. Confirm each
CVE's crash pattern is covered by at least one strategy, and
identify gaps where new attacks are needed.

**Scope:**

- Source: private CVE reference repo (curated list of DICOM CVEs
  across fo-dicom, DCMTK, GDCM, libdicom, pydicom, MicroDicom,
  Merge DICOM Toolkit, Orthanc, OsiriX, Sante PACS)
- For each CVE: document the trigger pattern, map it to the
  strategy that covers it (or flag as gap)
- Output: coverage matrix (CVE x strategy) and list of unmatched
  CVEs to drive new strategy development

**Effort:** 1 session.

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
| EmptyValueFuzzer (9 present-but-empty .NET crash attacks)      | #229                              |
| StructureFuzzer binary VR corruption (whitespace/null/dash/UN) | (4 binary attacks added)          |
