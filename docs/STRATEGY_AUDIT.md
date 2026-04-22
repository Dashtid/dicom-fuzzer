# Attack Strategy Audit

Date: 2026-04-22

This document is a point-in-time snapshot of the four attack-strategy
modules in `dicom_fuzzer/attacks/`. It drives backlog prioritization
in `BACKLOG.md` and is expected to drift -- refresh after any major
module rewrite.

---

## 1. Format (`dicom_fuzzer/attacks/format/`)

**Maturity: mature.** Broadest surface, highest test density, most
CVE-aligned. Production-ready.

### Inventory

23 strategies (17 generic + 6 modality-specific after PR #246 cleanup):

- Generic: `CalibrationFuzzer`, `DeflateBombFuzzer`, `DicomdirFuzzer`,
  `CompressedPixelFuzzer`, `ConformanceFuzzer`, `DictionaryFuzzer`,
  `EmptyValueFuzzer`, `EncodingFuzzer`, `HeaderFuzzer`, `MetadataFuzzer`,
  `PixelFuzzer`, `PixelReencodingFuzzer`, `PreambleFuzzer`,
  `PrivateTagFuzzer`, `ReferenceFuzzer`, `SequenceFuzzer`,
  `StructureFuzzer`
- Modality-specific (in-scope only): `EncapsulatedPdfFuzzer`,
  `NuclearMedicineFuzzer`, `PetFuzzer`, `RTDoseFuzzer`,
  `RTStructureSetFuzzer`, `SegmentationFuzzer`

### Capabilities

- 7 fuzzers ship `mutate_bytes()` binary-level attacks: EmptyValue,
  DeflateBomb, Pixel, CompressedPixel, Preamble, PixelReencoding,
  Structure. The other 16 are dataset-level only.
- All 13 named CVE gaps closed (see `docs/CVE_AUDIT.md` refocus
  addendum, 2026-04-13). 4 niche fo-dicom items closed in PR #252.
- StructureFuzzer alone now ships 13 binary attacks (tag ordering,
  duplicate tag, length field, VR whitespace/null/dash/UN, dimension
  VR, nonstandard meta VR, duplicate meta, SQ zero-length, SV/UV wrong
  length, SQ undefined with huge value).

### Test coverage

33 test files, ~1,260 test cases. Every fuzzer has a dedicated test file.

### Gaps worth pursuing

- **No raw VR-length-field corruption** outside StructureFuzzer's
  narrow set. pydicom recalculates lengths on serialization, so
  dataset-level attacks can't express length/value mismatch -- every
  length mutation has to be a `mutate_bytes` attack.
- **SequenceFuzzer recursion depth** is ad-hoc. No configurable
  nested-SQ bomb (1k-10k levels deep) to hit stack-guard limits.
- **No cross-VR reference fuzzing.** AT-VR elements that reference
  other tags, AE-VR elements that reference Source/Destination
  AE titles -- these forward references are currently untouched.

### Proposed next steps

1. Add `mutate_bytes` length-field sweep as a generic attack
   available to every format fuzzer (not just Structure).
2. Nested-SQ recursion bomb in SequenceFuzzer with configurable
   depth (default 10k).
3. Cross-reference attacks (AT/AE/UI forward references that
   point at tags/UIDs that don't exist or point at themselves).

---

## 2. Multiframe (`dicom_fuzzer/attacks/multiframe/`)

**Maturity: growing.** Solid dataset-level coverage, no binary-level
attacks yet.

### Inventory

10 strategies: `FrameCountMismatchStrategy`,
`FrameTimeCorruptionStrategy`, `PerFrameDimensionStrategy`,
`SharedGroupStrategy`, `FrameIncrementStrategy`,
`DimensionOverflowStrategy`, `FunctionalGroupStrategy`,
`PixelDataTruncationStrategy`, `EncapsulatedPixelStrategy`,
`DimensionIndexStrategy`

### Capabilities

- All 10 are dataset-level (`mutate()` returns modified `Dataset`).
- No `mutate_bytes()` hooks -- frame-level byte layout (Basic Offset
  Table, Item delimiters per frame, extended offset table from
  DICOM 2022) is reachable only through encaps helpers, not raw bytes.
- Dimension-Index coverage aligns with fo-dicom frame-alignment
  work.

### Test coverage

6 test files, ~180 test cases.

### Gaps worth pursuing

- **No Basic Offset Table (BOT) binary attack at the multiframe
  layer.** CompressedPixelFuzzer has one, but it doesn't know about
  multi-frame context (per-frame offsets, frame count). A
  multiframe-aware BOT attack can lie about frame boundaries.
- **Extended Offset Table (EOT)** (DICOM 2022, tag 7FE0,0001) is
  untouched. Parsers that read EOT for random frame access can
  be fed inconsistent offsets vs. actual item layout.
- **Per-frame vs shared ambiguity** -- replicate a value in both
  SharedFunctionalGroupsSequence and PerFrameFunctionalGroupsSequence
  to test precedence logic.

### Proposed next steps

1. `mutate_bytes` BOT corruption that's multiframe-aware (knows
   NumberOfFrames, can create N-mismatched offsets).
2. Extended Offset Table fuzzing strategy (new strategy class).
3. Shared/per-frame ambiguity attack.

---

## 3. Series (`dicom_fuzzer/attacks/series/`)

**Maturity: growing.** Strong 3D/temporal coverage, study-level is
newer and lighter on integration tests.

### Inventory

- `Series3DMutator` -- 12 strategies (5 core, 5 reconstruction,
  2 temporal)
- `StudyMutator` -- 6 study-level strategies (registration geometry,
  cross-series reference, etc.)
- `ParallelSeriesMutator` -- orchestrator for batch fuzzing

### Capabilities

- Multi-file attacks: slice position jitter, boundary-slice attacks,
  orientation attacks, gap/overlap, aspect-ratio tears,
  FrameOfReferenceUID mismatch, cross-slice reference tampering,
  temporal (4D) inversions.
- Study-level: registration geometry, cross-series ReferencedSeries
  tampering.
- No `mutate_bytes()` -- all attacks are dataset-level because the
  mutation is across multiple files, not within one byte stream.
- References CVE-2025-35975/36521/5943 (multi-slice parsing
  memory corruption and infinite loop patterns).

### Test coverage

8 test files, ~335 test cases. Series3DMutator is well-covered;
StudyMutator integration tests are thinner.

### Gaps worth pursuing

- **Circular `ReferencedSeriesSequence`** -- series A -> B -> A,
  tests depth-first traversal safety in study loaders.
- **Singular geometry matrices** -- zero-determinant Transform
  matrices (ImagePositionPatient + ImageOrientationPatient) that
  crash matrix-inversion code paths in reconstruction.
- **ParallelSeriesMutator has no fault isolation** -- a single
  worker crash takes down the pool.
- **No "same SOPInstanceUID across series"** attack to test
  instance-dedup logic in archivers.

### Proposed next steps

1. Circular-reference strategy (ReferencedSeriesSequence / ReferencedImageSequence).
2. Singular-matrix geometry strategy.
3. Fault isolation for ParallelSeriesMutator (per-worker try/except,
   crash counted but pool continues).

---

## 4. Network (`dicom_fuzzer/attacks/network/`)

**Maturity: mature.** Full DIMSE + TLS + state-machine coverage,
minor gaps in timing-attack integration.

### Inventory

- Top-level: `DICOMNetworkFuzzer`, `DICOMProtocolBuilder`
- DIMSE (5 files): `DIMSEFuzzer`, `DIMSECommandBuilder`,
  `DatasetMutator` for C-STORE, C-FIND, C-MOVE, C-GET, C-ECHO, N-\*
- TLS (6 files): `DICOMTLSFuzzer`, `TLSSecurityTester`,
  `DICOMAuthTester`, `PACSQueryInjector`
- Stateful (8 files): `StatefulFuzzer`, `DICOMStateMachine`
  (full PS3.8 STA1-STA7), `StateAwareFuzzer`, resource_attacks,
  timing_attacks, sequence_generator

### Capabilities

- Protocol coverage: A-ASSOCIATE, A-RELEASE, A-ABORT, P-DATA,
  DIMSE C-STORE/C-FIND/C-MOVE/C-GET/C-ECHO/N-\*
- TLS attacks: version enumeration (1.0-1.3), weak cipher probing,
  cert validation patterns (Heartbleed/POODLE/BEAST/CRIME/DROWN/ROBOT).
- State-aware sequence generation covers all 7 DICOM association
  states.
- Binary-level PDU attacks: length field, AE title, presentation
  context fuzzing.

### Test coverage

20 test files, ~595 test cases.

### Gaps worth pursuing

- **Timing/resource attacks exist but aren't wired into
  `generate_fuzz_sequences()`** -- `resource_attacks.py` and
  `timing_attacks.py` are scaffold modules that no campaign actually
  exercises.
- **TLS certificate chain depth** -- expired certs, self-signed
  chains, CA revocation scenarios (CRL/OCSP) are not generated.
- **Authentication negotiation fuzzing** (already listed in
  Low priority / deferred) remains open. With TLS pinning becoming
  common, this is the next natural layer.

### Proposed next steps

1. Wire `timing_attacks.py` + `resource_attacks.py` into
   `StatefulFuzzer.generate_fuzz_sequences()`.
2. TLS cert chain fuzzing (expired, self-signed, wrong-CN, revoked).
3. User-identity negotiation fuzzing (DICOM PS3.7 User-Identity
   Sub-Item, username/password + Kerberos + SAML + JWT).

---

## Open-source target research

Primary campaign target today is `Hermes.exe` (proprietary, .NET 8 WPF).
Valuable for real-world impact but closed-source, so crash reports stay
local. This section evaluates open-source alternatives that accept all
four attack types (format files via upload, network via DIMSE,
multiframe via DICOM file, series via multi-file study) and where a
contribution loop (report, patch, upstream) is possible.

### Recommendation: Orthanc (primary), DCMTK (secondary)

#### Orthanc (primary)

Lightweight DICOM server, C++, GPL-licensed with commercial exceptions.
Windows `.exe` installer keeps the existing `--gui-mode`-style workflow
intact (run as service, Popen, kill on timeout).

- **Accepts all four attack types:**
  - Format / multiframe: HTTP upload or C-STORE
  - Network: full DIMSE server (A-ASSOCIATE, C-STORE, C-FIND, C-MOVE)
  - Series: REST `/studies/{id}` operations + DICOMweb QIDO-RS/WADO-RS
- **Security research activity:** Machine Spirits disclosed nine CVEs
  (CVE-2026-5437 through CVE-2026-5445) against Orthanc 1.12.10 in 2026.
  All fixed in 1.12.11. Heap buffer overflows, decompression bombs,
  OOB reads in the meta-header parser.
- **Contribution loop:** active maintainer (Sebastien Jodogne, UCLouvain),
  public issue tracker, security reports handled responsively based on
  the 2026 wave.
- **Downside:** GPL. Fixes upstream as open-source patches; commercial
  forks exist but not the point here.

#### DCMTK (secondary)

C++ toolkit from OFFIS. Not a PACS server but a bundle of CLI tools
(`storescp`, `dcmdump`, `dcmconv`, `dcmrecv`, etc.) that is the
de-facto reference parser. Used by huge downstream fleet (SimpleITK,
ITK, Conquest, Weasis plugins).

- **Accepts three of four attack types out of the box:**
  - Format / multiframe: `dcmdump infile.dcm`, `dcmconv`
  - Network: `storescp` accepts C-STORE; `movescu`/`findscu` for Q/R
  - Series: parse a directory; no built-in study primitive, so
    series attacks reduce to batch-of-files
- **Security research activity:** CVE-2022-2119/2120 (path traversal
  in `storescp` SOP-UID filename), CVE-2025-9732, CVE-2025-2357
  (JPEG-LS decoder memory corruption, already in our
  `_corrupt_jpegls_codestream` attack).
- **Contribution loop:** OFFIS maintains a forum + Redmine tracker.
  Response historically slower than Orthanc but documented CVE flow.
- **Best for:** Format-heavy regression testing. Easy to integrate
  into CI -- pass a corpus directory to `dcmdump`, watch for
  nonzero exits / crashes.

### Alternatives considered

- **GDCM (Grassroots DICOM).** C++ library, very active CVE surface
  (CVE-2025-11266 OOB write, CVE-2026-3650 memory leak). Great for
  library-level fuzzing, but no server component -- Format attacks
  only. Good secondary harness after DCMTK if time allows.
- **fo-dicom.** .NET DICOM library, what we've been implicitly
  hitting via Hermes. Active releases (5.2.6 in March 2026). Good
  for .NET-ecosystem coverage but less visible CVE impact than
  C/C++ parsers.
- **dcm4chee-arc-light.** Full PACS, Java. Heavier deploy (WildFly +
  DB), payoff is less attack-surface granularity than Orthanc.
  Skip unless network-only deep-fuzzing becomes the focus.
- **Open-source viewers (OHIF, Weasis, 3D Slicer, Horos).** Less
  active as CVE targets, harder to automate crash detection (need
  headless browser for OHIF, JVM for Weasis, etc.). Not
  recommended as primary.

### Integration plan (if we adopt Orthanc)

1. Pin Orthanc 1.12.10 locally (the _pre-patch_ version with known
   CVEs) as a regression sanity check -- our fuzzer should
   reproduce CVE-2026-5437..5445 crash signatures.
2. Add `--target-mode` option: `hermes` (current, GUI mode),
   `orthanc-file` (upload via REST, check `/tools/log`), `orthanc-dimse`
   (C-STORE via `pynetdicom`).
3. Separate artifact root: `artifacts/campaigns/orthanc/` so
   Hermes campaign data stays isolated.
4. If any NEW crash is found against 1.12.11+, coordinate
   disclosure via the Orthanc security contact. Otherwise, file
   reproducer + optional patch as a public issue.
