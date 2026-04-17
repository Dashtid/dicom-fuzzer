# CVE-to-Strategy Coverage Matrix

Systematic cross-reference of every known DICOM CVE (2022-2026) against
the fuzzer's 30 mutation strategies. Identifies covered trigger patterns
and gaps driving new backlog items.

**Last updated:** 2026-04-13 (refocus addendum -- see end of file)
**Strategies audited:** 33 (23 format + 10 multiframe, post PR #246)
**CVEs catalogued:** ~140 total, ~85 file-parsing (in scope)
**CISA ICS Medical Advisories cross-referenced:** 23 (2022-2026)
**Gap status:** All 13 P1/P2 gaps closed (G1-G13). See addendum.

---

## Coverage Summary

**16 covered trigger patterns** matching ~65 of ~80 file-parsing CVEs.
**13 gaps** covering ~15 unmatched CVEs.
**Estimated coverage: ~81%** of known file-parsing trigger patterns.

---

## Covered Trigger Patterns

| #   | Trigger Pattern                           | CVEs / Issues                                               | Strategy                                                                                                   |
| --- | ----------------------------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| C1  | Encapsulated pixel fragment parsing       | GDCM-2025-11266, GDCM-2025-48429/53618/53619                | CompressedPixelFuzzer (6 binary attacks), EncapsulatedPixelStrategy                                        |
| C2  | JPEG marker/dimension corruption          | Sante 2023-32131/32132, DCMTK many                          | CompressedPixelFuzzer (\_corrupt_jpeg_markers, \_corrupt_jpeg_dimensions)                                  |
| C3  | JPEG2000 codestream corruption            | GDCM-2024-22373, Sante 2023-32133/34297                     | CompressedPixelFuzzer (\_corrupt_jpeg2000_codestream)                                                      |
| C4  | RLE segment corruption                    | DCMTK-2025-25475, GDCM-2025-48429                           | CompressedPixelFuzzer (\_corrupt_rle_segments), PixelReencodingFuzzer                                      |
| C5  | VR type confusion (short->long)           | DCMTK-2024-28130                                            | StructureFuzzer (4 VR attacks), CalibrationFuzzer (\_vr_type_confusion)                                    |
| C6  | Dimension/bit-depth overflow              | DCMTK-2024-47796/52333, Orthanc-2026-5442/5444              | PixelFuzzer (\_extreme_contradiction, \_dimension_mismatch, \_bit_depth_attack), DimensionOverflowStrategy |
| C7  | Overlay origin/dimension/bit-position     | GDCM-2025-52582, fo-dicom #1559/#2087                       | PixelFuzzer (3 overlay attacks)                                                                            |
| C8  | NULL deref on empty/missing required tags | DCMTK-2022-2121/4981/2025-14841, fo-dicom #1879/#1891/#2043 | EmptyValueFuzzer (9 attacks), MetadataFuzzer (\_required_tag_removal)                                      |
| C9  | Deep nesting / circular sequence refs     | libdicom-2024-24793/24794, OsiriX-2025-27578                | SequenceFuzzer (\_deep_nesting, \_circular_reference)                                                      |
| C10 | Length field overflow / stack BOF         | DCMTK-2024-27628, Sante 2023-35986, MedDream 2025-3481-3484 | StructureFuzzer (\_binary_corrupt_length_field), HeaderFuzzer                                              |
| C11 | NumberOfFrames mismatch                   | DCMTK-2024-27628 (NumberOfFrames > INT_MAX)                 | PixelFuzzer, FrameCountMismatchStrategy                                                                    |
| C12 | Encoding/charset confusion                | implicit in string parsing across all libs                  | EncodingFuzzer (10 attacks)                                                                                |
| C13 | Odd-length element violation              | fo-dicom #1403                                              | PixelFuzzer (\_binary_odd_length_pixel_data)                                                               |
| C14 | Sequence delimiter confusion              | fo-dicom #1339, pydicom #1140                               | CompressedPixelFuzzer (binary attacks), SequenceFuzzer                                                     |
| C15 | Private tag EOF peek                      | fo-dicom #487/#220                                          | PrivateTagFuzzer (\_private_sq_at_eof)                                                                     |
| C16 | Empty values (.NET Get<T> crash)          | fo-dicom #2043/#1891/#1879/#2067/#1905/#1296/#1884          | EmptyValueFuzzer (9 attacks)                                                                               |

---

## Gap Analysis

### P1 Quick Wins (~0.5-1h each, extend existing fuzzers)

**G1: PALETTE COLOR + LUT overflow**

Set PhotometricInterpretation to "PALETTE COLOR" with extreme
Rows\*Columns that overflow 32-bit in LUT allocation, and/or set
LUT descriptor entry count larger than actual LUT data.

- Orthanc CVE-2026-5443: 32-bit integer overflow in width\*height
  during PALETTE COLOR pixel validation -> heap buffer overflow
- Orthanc CVE-2026-5445: pixel indices larger than palette size
  during LUT decode -> OOB read past palette buffer
- GDCM CVE-2024-22391 (TALOS-2024-1924): LookupTable::SetLUT
  iterates `Internal->RGB[3*i+type]` using descriptor's `length`
  value without checking it fits the allocated RGB array -> heap
  buffer overflow
- Target: PixelFuzzer
- Effort: ~1h

**G4: UL-as-US dimension type confusion**

Replace VR "US" with "UL" on Rows/Columns tags at the binary
level. UL is 4 bytes; the file still has a 2-byte value after
the VR, so the parser reads 4 bytes (2 value + 2 from next
element) as a huge dimension, causing integer overflow in
frame-size calculation.

- Orthanc CVE-2026-5442: dimension fields encoded as VR UL
  instead of US -> huge dimensions overflow 32-bit frame size
- Target: StructureFuzzer mutate_bytes
- Effort: ~0.5h

**G6: Format string injection**

Add %s, %n, %x, %p payloads to string VR fields (LO, SH, PN,
LT). Targets C/C++ parsers that pass DICOM string values to
printf-family functions without format validation.

- Merge DICOM CVE-2024-23914 (CWE-134): format string vuln in
  MC_Open_Association() via Application Context Name
- Target: HeaderFuzzer or EncodingFuzzer
- Effort: ~0.5h

**G8: Non-standard VR in file meta information**

Insert a DICOM element with a fabricated VR (e.g., "ZZ") in the
File Meta Information header (group 0002). Parsers that allocate
based on VR-implied length without bounds checking consume
gigabytes of heap from a tiny file.

- GDCM CVE-2026-3650 (CWE-401, **UNPATCHED** as of April 2026):
  ~150-byte file with non-standard VR in file meta causes
  allocation of ~4.2 GB. Discovered by ARIMLABS. CISA
  ICSMA-26-083-01 recommends network isolation.
- Target: ConformanceFuzzer or StructureFuzzer
- Effort: ~0.5h

**G9: HighBit >= BitsAllocated**

Set HighBit to a value >= BitsAllocated. The pixel min/max
calculation uses HighBit as an array index without bounds
checking, producing an OOB write.

- DCMTK CVE-2024-52333 (TALOS-2024-2121, CVSS 8.4):
  DiInputPixelTemplate::determineMinMax() in diinpxt.h -- no
  check that HighBit < BitsAllocated before using it as index
- DCMTK CVE-2024-47796 (TALOS-2024-2122, CVSS 8.4): same
  class, `nowindow` functionality
- Target: PixelFuzzer.\_bit_depth_attack (verify coverage; add
  explicit HighBit >= BitsAllocated combo if missing)
- Effort: ~0.5h

**G12: Photometric Interpretation -> wrong codec path**

Set PhotometricInterpretation to YBR_RCT, YBR_ICT, or other
uncommon values on pixel data that was encoded for a different
color space. The JPEG codec selects the wrong color conversion
function, which reads/writes with mismatched buffer expectations.

- GDCM CVE-2025-53618 (TALOS-2025-2210, CVSS 7.4):
  JPEGBITSCodec::InternalCode -> grayscale_convert() invoked
  with mismatched buffer due to manipulated PI value
- GDCM CVE-2025-53619: same, null_convert() path
- DCMTK CVE-2025-9732 (CWE-787): OOB write in diybrpxt.h
  during YBR-to-RGB color conversion
- Target: PixelFuzzer.\_photometric_confusion (add YBR_RCT,
  YBR_ICT, YBR_FULL_422 values)
- Effort: ~0.5h

### P1 Medium Effort (~1-2h each)

**G7: VOI LUT / Palette LUT corruption**

Add VOILUTSequence with type-confused entries (e.g., OW data
where IS is expected), and Palette LUT with mismatched
descriptor (declared entry count != actual data size).

- DCMTK CVE-2024-28130 (TALOS-2024-1957, CVSS 7.5):
  DVPSSoftcopyVOI_PList::createFromImage() incorrect type
  conversion -- value 0x72 passed to DcmByteString::putOFStringAtPos
- fo-dicom #1062: VOI LUT Sequence present without Modality
  LUT -> IndexOutOfRangeException in VOISequenceLUT indexer
- Promote from deferred backlog
- Target: New fuzzer or extend CalibrationFuzzer
- Effort: ~1-2h

**G2: JPEG-LS codec corruption**

Add JPEG-LS Lossless (1.2.840.10008.1.2.4.80) and Near-Lossless
(1.2.840.10008.1.2.4.81) transfer syntax support with malformed
JPEG-LS codestream markers.

- DCMTK CVE-2025-2357 (CWE-119): memory corruption in dcmjpls
  JPEG-LS decoder
- Target: CompressedPixelFuzzer (add alongside JPEG/JP2K/RLE)
- Effort: ~1h

**G10: Duplicate tags in file meta information**

Insert duplicate elements in group 0002 (File Meta Information).
Parsers using hash-map insertion with destroy-on-collision
double-free the original element.

- libdicom CVE-2024-24793 (TALOS-2024-1931, CVSS 8.1):
  use-after-free in parse_meta_element_create() when file
  meta contains two Sequence elements with same tag
- libdicom CVE-2024-24794: same, parse_meta_sequence_end()
- Note: StructureFuzzer.\_binary_duplicate_tag explicitly
  SKIPS group 0002. This gap requires a new attack that
  targets file meta specifically.
- Target: StructureFuzzer or ConformanceFuzzer
- Effort: ~1h

### P2 Larger Scope (~2-4h each)

**G3: Decompression bomb (deflated transfer syntax)**

Create a DICOM file with Deflated Explicit VR Little Endian
transfer syntax (UID 1.2.840.10008.1.2.1.99) containing a
crafted deflate stream with >1000:1 compression ratio.

- Orthanc CVE-2026-5438 (CWE-400): gzip payload with no
  decompressed size limit
- Orthanc CVE-2026-5439 (CWE-400): ZIP archive bomb via
  forged uncompressed size metadata
- ACM CCS 2022 research: Deflated LE transfer syntax wraps
  a zip bomb; any auto-decompressing server is vulnerable
- Target: New attack in CompressedPixelFuzzer or dedicated
  DecompressionBombFuzzer
- Effort: ~2-4h

**G5: DICOMDIR path traversal**

Generate malicious DICOMDIR with ReferencedFileID containing
"../" sequences or absolute paths. FileSet operations then
read/write/delete outside the DICOM file-set root.

- pydicom CVE-2026-32711 (CWE-22, CVSS 7.8): pathlib `/`
  operator discards left operand if right is absolute.
  FileSet.copy()/write()/remove() perform file I/O on
  unchecked path. Fixed pydicom 3.0.2 / 2.4.5.
- Target: New fuzzer (different attack surface -- file-level,
  not tag-level)
- Effort: ~2h

**G11: Preamble polyglot (PE/ELF/JSON payload)**

Inject PE, ELF, or JSON headers into the 128-byte DICOM
preamble. The file is simultaneously valid DICOM and valid
executable/data. Targets systems that dispatch on file magic
or that process the preamble as structured data.

- CVE-2019-11687: DICOM PE polyglot (original research)
- Praetorian ELFDICOM 2025: Linux ELF variant
- Orthanc CVE-2023-33466: JSON in preamble -> config
  overwrite -> Lua RCE chain
- Target: HeaderFuzzer or new binary attack
- Effort: ~2h

**G13: OverlayData shorter than dimensions**

Set OverlayRows\*OverlayColumns to imply more overlay bytes
than OverlayData actually contains. Renderer reads past
the end of the overlay buffer.

- fo-dicom #1728: RenderImage throws IndexOutOfRangeException
  (BitArray.Get) when OverlayData is shorter than expected
- Note: Our existing overlay attacks create FULL overlay data
  via \_add_overlay_scaffold(). Need a variant with truncated
  OverlayData.
- Target: PixelFuzzer overlay attacks
- Effort: ~0.5h

---

## Full CVE Catalog by Library

### DCMTK (27 CVEs, 2020-2026)

| CVE        | CVSS | CWE | Module              | Trigger                                                  | Covered?               |
| ---------- | ---- | --- | ------------------- | -------------------------------------------------------- | ---------------------- |
| 2024-52333 | 8.4  | 119 | dcmimgle diinpxt.h  | HighBit >= BitsAllocated -> OOB index in determineMinMax | **GAP G9**             |
| 2024-47796 | 8.4  | 119 | dcmimgle diinpxt.h  | Invalid HighBit/BitsAllocated in nowindow                | **GAP G9**             |
| 2024-27628 | 8.1  | 120 | dcmect              | NumberOfFrames > INT_MAX -> integer overflow             | C11                    |
| 2024-28130 | 7.5  | 704 | dcmpstat            | Corrupt Softcopy VOI LUT type conversion                 | **GAP G7**             |
| 2025-25474 | 6.5  | 120 | dcmimgle diinpxt.h  | BitsStored/BitsAllocated mismatch -> heap overflow       | C6                     |
| 2025-9732  | 5.3  | 787 | dcmimage diybrpxt.h | YBR color space -> OOB write in conversion               | **GAP G12**            |
| 2025-25472 | 5.3  | 120 | dcmimgle            | Regression from CVE-2024-47796 fix                       | C6                     |
| 2025-2357  | 6.3  | 119 | dcmjpls             | JPEG-LS decoder memory corruption                        | **GAP G2**             |
| 2025-25475 | 7.5  | 476 | dcmdata dcrleccd.cc | RLE codec NULL deref on corrupt data                     | C4                     |
| 2025-14607 | 6.3  | 119 | dcmdata dcbytstr.cc | DcmByteString corruption from malformed attrs            | C10                    |
| 2026-5663  | 7.3  | 78  | dcmnet storescp     | OS command injection via --exec-on-reception             | Out of scope (network) |
| 2022-2119  | 7.5  | 22  | dcmnet storescp     | SOP Instance UID path traversal                          | Out of scope (network) |
| 2022-2120  | 7.5  | 22  | dcmnet SCU          | Relative path traversal via symlinks                     | Out of scope (network) |
| 2022-2121  | 7.5  | 476 | dcmnet              | Malformed file NULL deref                                | C8                     |
| 2024-34508 | 4.3  | 476 | dcmnet              | Invalid DIMSE NULL deref                                 | Out of scope (network) |
| 2024-34509 | 5.3  | 476 | dcmdata             | Invalid DIMSE segfault                                   | Out of scope (network) |
| 2022-43272 | 7.5  | 401 | dcmnet              | Memory leak per association                              | Out of scope (network) |
| 2025-14841 | 3.3  | 476 | dcmqrscp            | NULL deref in C-FIND/C-MOVE                              | Out of scope (network) |
| 2022-4981  | 3.3  | 476 | dcmqrscp            | NULL deref in readPeerList                               | Out of scope (config)  |

### GDCM (9 CVEs, 2024-2026)

| CVE        | CVSS | CWE | Component                         | Trigger                                        | Covered?    |
| ---------- | ---- | --- | --------------------------------- | ---------------------------------------------- | ----------- |
| 2024-22373 | 8.1  | 787 | JPEG2000Codec                     | Malformed J2K codestream -> heap overflow      | C3          |
| 2024-22391 | 7.7  | 787 | LookupTable::SetLUT               | LUT descriptor count > buffer -> heap overflow | **GAP G1**  |
| 2024-25569 | 6.5  | 125 | RAWCodec::DecodeBytes             | Pixel data length > actual -> OOB read         | C10         |
| 2025-11266 | 6.6  | 787 | PixelData fragments               | Fragment length 0-2 -> unsigned underflow      | C1          |
| 2025-53618 | 7.4  | 125 | JPEGBITSCodec                     | PI value -> wrong color conversion -> OOB read | **GAP G12** |
| 2025-53619 | 7.4  | 125 | JPEGBITSCodec                     | PI value -> null_convert OOB read              | **GAP G12** |
| 2025-52582 | 7.4  | 125 | Overlay::GrabOverlayFromPixelData | Overlay metadata > source buffer               | C7          |
| 2025-48429 | 7.4  | 125 | RLECodec::DecodeByStreams         | NumSegments > actual segments -> OOB read      | C4          |
| 2026-3650  | 7.5  | 401 | File Meta Info parser             | Non-standard VR -> 4.2GB alloc (UNPATCHED)     | **GAP G8**  |

### Orthanc (9 CVEs, 2026)

| CVE       | CWE | Trigger                                 | Covered?            |
| --------- | --- | --------------------------------------- | ------------------- |
| 2026-5437 | 125 | Malformed meta-header -> OOB read       | C10                 |
| 2026-5438 | 400 | Gzip bomb -> memory exhaustion          | **GAP G3**          |
| 2026-5439 | 400 | ZIP bomb -> memory exhaustion           | **GAP G3**          |
| 2026-5442 | 787 | UL dimensions instead of US -> overflow | **GAP G4**          |
| 2026-5443 | 787 | PALETTE COLOR width\*height overflow    | **GAP G1**          |
| 2026-5444 | 787 | PAM image dimension overflow            | C6                  |
| 2026-5445 | 125 | Pixel index > palette size -> OOB read  | **GAP G1**          |
| 2026-5441 | 125 | PMSCT_RLE1 escape markers -> OOB read   | C4                  |
| 2026-5440 | 400 | Huge Content-Length -> alloc            | Out of scope (HTTP) |

### libdicom (2 CVEs, 2024)

| CVE        | CVSS | CWE | Trigger                            | Covered?    |
| ---------- | ---- | --- | ---------------------------------- | ----------- |
| 2024-24793 | 8.1  | 416 | Duplicate tags in file meta -> UAF | **GAP G10** |
| 2024-24794 | 8.1  | 416 | Duplicate SQ tags -> double-free   | **GAP G10** |

### pydicom (1 CVE, 2026)

| CVE        | CVSS | CWE | Trigger                                  | Covered?   |
| ---------- | ---- | --- | ---------------------------------------- | ---------- |
| 2026-32711 | 7.8  | 22  | DICOMDIR ReferencedFileID path traversal | **GAP G5** |

### Sante DICOM Viewer Pro (17 CVEs, 2022-2026)

Trigger details sparse across all ZDI advisories -- consistently
"lack of proper validation of user-supplied data length before
copying to buffer." Attack surfaces: DCM parsing, J2K/JP2 parsing.

| Years | Count | Root Cause                         | Covered?    |
| ----- | ----- | ---------------------------------- | ----------- |
| 2022  | 10    | OOB write/read, UAF in DCM/J2K/JP2 | C2, C3, C10 |
| 2023  | 3     | OOB write, stack BOF               | C10         |
| 2024  | 1     | OOB read                           | C10         |
| 2025  | 2     | OOB write/read                     | C10         |
| 2026  | 1     | Buffer overflow                    | C10         |

### MicroDicom (7 CVEs, 2024-2025)

| CVE        | CWE | Trigger                              | Covered?     |
| ---------- | --- | ------------------------------------ | ------------ |
| 2024-22100 | 122 | Heap BOF from crafted DCM            | C10          |
| 2024-28877 | 121 | Stack BOF from crafted DCM           | C10          |
| 2024-33606 | 749 | Custom URL scheme no auth (not file) | Out of scope |
| 2025-35975 | 787 | OOB write from crafted DCM           | C10          |
| 2025-36521 | 125 | OOB read -> memory corruption        | C10          |
| 2025-5943  | 787 | OOB write -> RCE                     | C10          |

### Other Libraries

| CVE        | Library     | CWE | Trigger                              | Covered?                    |
| ---------- | ----------- | --- | ------------------------------------ | --------------------------- |
| 2026-25982 | ImageMagick | 125 | DCM decoder OOB read                 | C10                         |
| 2024-42845 | InVesalius  | 95  | eval() on ImagePositionPatient       | Out of scope (app-specific) |
| 2024-23912 | Merge DICOM | 125 | MC_Open_File OOB read                | C10                         |
| 2024-23914 | Merge DICOM | 134 | Format string in Application Context | **GAP G6**                  |
| 2025-2581  | xmedcon     | 191 | Integer underflow in malloc          | C10                         |

---

## fo-dicom Crash Issues (No Formal CVEs)

fo-dicom has zero published CVEs but ~40 crash-inducing GitHub
issues. Key issues already targeted by our strategies:

| Issue      | Exception       | Trigger                                | Strategy              |
| ---------- | --------------- | -------------------------------------- | --------------------- |
| #487, #220 | EOF read        | Private SQ at end of file              | PrivateTagFuzzer      |
| #1296      | Parse error     | Comma-as-decimal in DS VR              | EmptyValueFuzzer      |
| #1339      | EOF read        | Missing sequence delimiter             | CompressedPixelFuzzer |
| #1403      | Padding bug     | Odd-length element                     | PixelFuzzer           |
| #1559      | IndexOutOfRange | Negative overlay origin                | PixelFuzzer           |
| #1586      | Empty alloc     | Zero-length final fragment             | CompressedPixelFuzzer |
| #1660      | Truncation      | "--" VR -> DicomReaderResult.Suspended | StructureFuzzer       |
| #1847      | VR detection    | Whitespace in VR field                 | StructureFuzzer       |
| #1879      | IndexOutOfRange | Empty SpecificCharacterSet             | EmptyValueFuzzer      |
| #1884      | IndexOutOfRange | Empty SharedFunctionalGroupsSequence   | EmptyValueFuzzer      |
| #1891      | NullRef         | Empty VOILUTFunction                   | EmptyValueFuzzer      |
| #1905      | DivideByZero    | Zero WindowWidth                       | EmptyValueFuzzer      |
| #1941      | Parser desync   | UN substitution on short-VR            | StructureFuzzer       |
| #1958      | State machine   | Orphan delimiter at EOF                | CompressedPixelFuzzer |
| #2043      | NullRef         | Empty PixelSpacing                     | EmptyValueFuzzer      |
| #2067      | NullRef         | Empty ImagePositionPatient             | EmptyValueFuzzer      |
| #2087      | UB              | Non-zero OverlayBitPosition            | PixelFuzzer           |

New issues found in deep dive (not yet targeted):

| Issue | Exception          | Trigger                          | Gap?                           |
| ----- | ------------------ | -------------------------------- | ------------------------------ |
| #1009 | Infinite loop      | SQ with explicit length=0        | Niche (binary-level SQ length) |
| #1728 | IndexOutOfRange    | OverlayData shorter than dims    | **G13**                        |
| #763  | DicomFileException | Null tag (0000,0000) in fragment | Niche                          |
| #1386 | Parser desync      | SV/UV VR wrong length field size | Niche (new VRs)                |
| #1982 | Unhandled VR       | SkipLargeTags + SQ VR (**OPEN**) | Niche (read mode)              |
| #1062 | IndexOutOfRange    | VOI LUT Seq without Modality LUT | **G7**                         |

---

## Statistics

| Metric                               | Value |
| ------------------------------------ | ----- |
| Total CVEs catalogued                | ~140  |
| File-parsing CVEs (in scope)         | ~85   |
| Network/auth/web CVEs (out of scope) | ~55   |
| Covered trigger patterns             | 16    |
| CVEs matched by existing strategies  | ~70   |
| Gaps identified                      | 13    |
| CVEs in gaps                         | ~15   |
| Coverage rate                        | ~82%  |
| CISA ICS Medical Advisories          | 23    |
| Research rounds completed            | 2     |

### CWE Distribution (file-parsing CVEs)

| CWE     | Count | Description                 |
| ------- | ----- | --------------------------- |
| CWE-787 | ~25   | Out-of-bounds write         |
| CWE-125 | ~15   | Out-of-bounds read          |
| CWE-119 | ~8    | Buffer overflow (generic)   |
| CWE-476 | ~7    | NULL pointer dereference    |
| CWE-416 | ~6    | Use-after-free              |
| CWE-121 | ~5    | Stack-based buffer overflow |
| CWE-120 | ~4    | Buffer overflow (classic)   |
| CWE-401 | ~3    | Memory leak                 |
| CWE-22  | ~3    | Path traversal              |
| CWE-704 | ~1    | Incorrect type conversion   |
| CWE-134 | ~1    | Format string               |
| CWE-191 | ~1    | Integer underflow           |

### Most Affected Libraries

| Library      | File-Parsing CVEs | Coverage                             |
| ------------ | ----------------- | ------------------------------------ |
| DCMTK        | 18                | 14 covered, 4 gaps (G2, G7, G9, G12) |
| Sante Viewer | 17                | ~17 covered (generic buffer/length)  |
| GDCM         | 9                 | 5 covered, 4 gaps (G1, G8, G12)      |
| Orthanc      | 9                 | 4 covered, 5 gaps (G1, G3, G4)       |
| MicroDicom   | 6                 | ~6 covered (generic buffer/length)   |
| libdicom     | 2                 | 0 covered, 2 gaps (G10)              |
| MedDream     | 4 (parsing)       | ~4 covered (stack BOF)               |

---

## Round 2 Deep Dive Addendum

Second research pass targeted blind spots from round 1: libraries with
no initial results, CISA ICS-CERT full listing, ZDI advisory details,
Exploit-DB, GHSA database, fo-dicom release notes, and academic research.

### Additional CVEs Found

| CVE        | Library                   | CWE | Trigger                                                    | Maps To |
| ---------- | ------------------------- | --- | ---------------------------------------------------------- | ------- |
| 2025-53644 | OpenCV (via Weasis)       | 457 | Uninitialized ptr in opj_jp2_read_header from crafted JP2K | C3      |
| 2023-5059  | Sante FFT Imaging         | 125 | OOB read in DICOM parsing                                  | C10     |
| 2024-1696  | Sante FFT Imaging         | 787 | OOB write in DICOM parsing                                 | C10     |
| 2025-0568  | Sante PACS Server         | 119 | DCM file memory corruption on C-STORE ingestion            | C10     |
| 2025-0569  | Sante PACS Server         | 119 | DCM file memory corruption (variant 2)                     | C10     |
| 2025-27598 | ImageSharp (fo-dicom dep) | 787 | GIF LzwDecoder OOB write from crafted frame dims           | Niche   |

### Additional fo-dicom Issues

| Issue | Trigger                                                        | Impact                             |
| ----- | -------------------------------------------------------------- | ---------------------------------- |
| #1977 | DicomDirectory deep record nesting -> recursive stack overflow | Fixed 5.2.3. Maps to G5 (DICOMDIR) |

### Libraries Confirmed Clean (No CVEs 2022-2026)

dcm4che/dcm4chee (Java), Imebra/DicomHero, cornerstone.js,
ClearCanvas, Horos (unmaintained since 2023), 3D Slicer.

### ZDI Sante Detail Clarifications

Round 1 listed Sante as "trigger details sparse." ZDI advisories
now provide format-level specifics:

- **ZDI-22-247** (CVE-2022-24055): **GIF** parser OOB read -- Sante
  parses GIF thumbnails in Icon Image Sequence (0088,0200)
- **ZDI-22-254** (CVE-2022-24062): **JP2** UAF -- distinct from J2K
  OOB writes; object freed during JP2 box parsing then re-accessed
- **ZDI-26-104** (CVE-2026-2034): DCM buffer overflow -- explicit
  "lack of proper validation of length prior to copying to buffer"

### Academic/Industry Research Patterns

| Pattern                             | Source                                | Covered?                       |
| ----------------------------------- | ------------------------------------- | ------------------------------ |
| DICOM PE/ELF preamble polyglot      | Praetorian ELFDICOM 2025, PEDICOM     | **G11**                        |
| JSON config polyglot in preamble    | Shielder/Orthanc CVE-2023-33466       | **G11**                        |
| Deflated LE transfer syntax bomb    | ACM CCS 2022 poster                   | **G3**                         |
| DICOM-XML XXE / entity expansion    | Merge CVE-2024-23913                  | Future (no XML output)         |
| Steganography in private tags / LSB | PMC 2022 research                     | Partial (detection, not crash) |
| C-STORE injection without auth      | Gatewatcher 2024, Forescout honeypots | Future (network module)        |

### Round 2 Conclusion

No new gap IDs needed. All new findings map to existing covered
patterns (C3, C10) or existing gaps (G3, G5, G11). The DICOM-XML
attack surface (Merge CVE-2024-23913) is noted for future work
but requires a different output format. The 13-gap list from
round 1 is comprehensive for file-based fuzzing.

**Updated statistics**: ~140 CVEs total (up from ~130), ~85
file-parsing (up from ~80). Coverage rate unchanged at ~81%.

---

## Key Findings

1. **No fo-dicom CVEs in NVD** -- all crash patterns come from GitHub
   issues. Deep dive found ~40 issues beyond our known 19.

2. **GDCM CVE-2026-3650 is UNPATCHED** -- 150-byte file -> 4.2GB heap
   allocation via non-standard VR in file meta. Trivial to reproduce.
   CISA recommends network isolation as mitigation.

3. **DCMTK HighBit >= BitsAllocated** (CVE-2024-52333/47796) is a
   highly specific trigger that may not be covered by our existing
   \_bit_depth_attack. Needs explicit verification.

4. **libdicom duplicate-tag UAF is a generic pattern** -- any parser
   using hash-map with destroy-on-collision is vulnerable. Our
   StructureFuzzer.\_binary_duplicate_tag explicitly skips group 0002.

5. **Decompression bombs are an emerging attack surface** -- Deflated
   LE transfer syntax + gzip/ZIP bombs. Academic research (ACM CCS 2022) and real CVEs (Orthanc 2026).

6. **Preamble polyglot is a cross-domain attack** -- PE/ELF/JSON in
   128-byte preamble enables novel exploitation chains (Orthanc RCE
   via JSON preamble -> config overwrite -> Lua execution).

---

## 2026-04-13 Refocus Addendum: Scope and Gap Closure

### Scope

Since this project's primary target is Hermes.exe driven by the
`dicom-seeds/` corpus, only CVEs/patterns that can be triggered by
files matching one of the 9 seed modalities are actionable:

CT, DX, MR, NM, PET, RT-Dose, RT-Struct, SEG, encapsulated-PDF.

Nine modality fuzzers (Waveform/SR/US/MG/XA/MRS/PM/SC/PR) were
removed in PR #246 because no matching seed exists; their
`can_mutate()` always returned False during campaigns.

**In-scope vs out-of-scope CVE breakdown:**

Almost every CVE in the audit is **parser-level** (file meta, length
fields, encoding, sequence structure, pixel codecs, overlay,
PALETTE COLOR, VOI LUT, DICOMDIR, preamble, deflate). Parser-level
CVEs fire regardless of SOP class -- they are in scope for every
seed modality.

The audit catalogues **zero** CVEs that are bound exclusively to the
SOP classes of the removed fuzzers (no SR ContentSequence CVEs, no
US Doppler region CVEs, no MG/DBT-specific CVEs, etc.). All 13 gaps
and all 16 covered patterns remain in-scope.

### Gap Closure Status (all 13 P1/P2 gaps shipped)

| Gap | Pattern                                     | Status        | Strategy                               |
| --- | ------------------------------------------- | ------------- | -------------------------------------- |
| G1  | PALETTE COLOR + LUT overflow                | DONE (P1 QW)  | PixelFuzzer                            |
| G2  | JPEG-LS codec corruption                    | DONE (P1 med) | CompressedPixelFuzzer                  |
| G3  | Deflated transfer syntax bomb               | DONE (P2)     | DeflateBombFuzzer                      |
| G4  | UL-as-US dimension VR confusion             | DONE (P1 QW)  | StructureFuzzer (binary)               |
| G5  | DICOMDIR path traversal                     | DONE (P2)     | DicomdirFuzzer                         |
| G6  | Format string injection                     | DONE (P1 QW)  | EncodingFuzzer / HeaderFuzzer          |
| G7  | VOI LUT / Palette LUT corruption            | DONE (P1 med) | CalibrationFuzzer                      |
| G8  | Non-standard VR in file meta                | DONE (P1 QW)  | StructureFuzzer / ConformanceFuzzer    |
| G9  | HighBit >= BitsAllocated                    | DONE (P1 QW)  | PixelFuzzer (\_bit_depth_attack combo) |
| G10 | Duplicate tags in file meta                 | DONE (P1 med) | StructureFuzzer (group 0002 variant)   |
| G11 | Preamble polyglot (PE/ELF/JSON)             | DONE (P2)     | PreambleFuzzer                         |
| G12 | PhotometricInterpretation -> codec mismatch | DONE (P1 QW)  | PixelFuzzer (\_photometric_confusion)  |
| G13 | OverlayData shorter than dims               | DONE (P1 QW)  | PixelFuzzer (overlay attacks)          |

**Updated coverage estimate:** ~95%+ of catalogued file-parsing
trigger patterns are now exercised. Remaining ~5% are either niche
fo-dicom issues (see below) or out-of-scope (network/HTTP/config).

### Candidate Next Work (in-scope, lower priority)

The 4 fo-dicom issues marked "Niche" in round 2 are the only
remaining named gaps within scope. None has a CVE assigned and
none is high-impact, but they are concrete and small:

| Issue                       | Trigger                                   | Notes                                                                                 |
| --------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------- |
| fo-dicom #1009              | SQ with explicit length = 0               | Infinite loop in DicomReader. Add to StructureFuzzer mutate_bytes.                    |
| fo-dicom #763               | Null tag (0000,0000) in encapsulated frag | Add to CompressedPixelFuzzer mutate_bytes.                                            |
| fo-dicom #1386              | SV/UV VR with wrong length-field size     | Requires SV/UV-aware mutation in StructureFuzzer; new VRs added in DICOM 2024.        |
| fo-dicom #1982 (still OPEN) | SkipLargeTags read mode + SQ VR           | Read-mode-specific; only triggers when target uses SkipLargeTags. Verify Hermes does. |

### Out-of-Scope Reminders

- **Network-only CVEs** (DCMTK storescp, dcmqrscp, OS injection,
  symlink path traversal, DIMSE NULL deref): covered by the network
  module (StatefulFuzzer/DIMSEFuzzer/TLSSecurityTester), not file
  fuzzing.
- **DICOM-XML / XXE** (Merge CVE-2024-23913): no XML output path in
  the current target; defer.
- **HTTP / REST API** (Orthanc CVE-2026-5440): defer until web
  module exists.
- **Config / Lua RCE chains** (Orthanc CVE-2023-33466 post-preamble):
  G11 preamble polyglot covers the file-side trigger; the post-
  exploitation chain is environment-specific.

### Conclusion

The CVE_AUDIT objective ("close every named CVE pattern within
target scope") is effectively complete for file fuzzing. Future
format-fuzzer work should be either:

1. Address the 4 niche fo-dicom issues above (small, ~0.5h each).
2. Wait for new CVE disclosures (revisit this audit quarterly).
3. Expand the seed corpus (US/MG/XA/etc.) which then unlocks
   reinstating the modality fuzzers removed in PR #246.

Higher-leverage tracks remain: campaign tooling, crash triage
automation, coverage-guided fuzzing, and network module deepening.
