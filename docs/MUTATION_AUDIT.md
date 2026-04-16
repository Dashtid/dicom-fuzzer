# Mutation Audit: Structural vs. Content Classification

## Purpose

Not all mutations are equal. A **structural** mutation attacks the parser's logic,
size calculations, state machines, or memory allocation — the paths that produce
crashes, hangs, and memory corruption. A **content** mutation changes a data value
that the parser has already successfully read and stored; only the application's
rendering or business-logic layer sees it, and those layers are hardened.

The only confirmed crash to date came from deep sequence nesting — a structural
attack. This document classifies every mutation method so that the sampling budget
can be directed at high-crash-potential attacks.

### Classification criteria

| Class          | Definition                                                                                                                                                      |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **STRUCTURAL** | Attacks parser logic, size/length fields, state machines, or allocation (wrong VR type, size mismatch, delimiter injection, deep nesting, binary byte patching) |
| **CONTENT**    | Corrupts semantic values that the parser reads correctly (wrong patient name, wrong calibration number, UID reference integrity, wrong flag enumeration)        |

---

## Per-fuzzer classification

### PixelFuzzer — _already split_

| Method                         | Class      | Rationale                                                |
| ------------------------------ | ---------- | -------------------------------------------------------- |
| `_samples_per_pixel_attack`    | STRUCTURAL | Rows×Cols×Samples determines allocation size             |
| `_dimension_mismatch`          | STRUCTURAL | Declared size vs actual PixelData length — read past end |
| `_bit_depth_attack`            | STRUCTURAL | BitsAllocated drives allocation and decode math          |
| `_number_of_frames_mismatch`   | STRUCTURAL | Declared frames vs actual data — allocation mismatch     |
| `_pixel_data_truncation`       | STRUCTURAL | Parser reads past end of buffer                          |
| `_pixel_data_oversized`        | STRUCTURAL | Heap pressure / OOM probe                                |
| `_pixel_data_byte_flip`        | STRUCTURAL | XOR corruption trips codec state machines                |
| `_pixel_data_fill_pattern`     | STRUCTURAL | Uniform fill exposes decoder edge-case paths             |
| `_extreme_contradiction`       | STRUCTURAL | Multiple conflicting size fields simultaneously          |
| `_photometric_confusion`       | CONTENT    | String value; parser stores and moves on                 |
| `_pixel_representation_attack` | CONTENT    | Sign flip; no allocation effect                          |
| `_planar_configuration_attack` | CONTENT    | Interleave mode; display issue only                      |
| `_pixel_value_range_attack`    | CONTENT    | SmallestImagePixelValue metadata; rendering only         |
| `_rescale_attack`              | CONTENT    | RescaleSlope/Intercept are rendering parameters          |
| `_window_attack`               | CONTENT    | WindowCenter/Width are display parameters                |

**Status**: split already implemented. No changes needed.

---

### MetadataFuzzer — _already split_

| Method                          | Class      | Rationale                                                                                |
| ------------------------------- | ---------- | ---------------------------------------------------------------------------------------- |
| `_required_tag_removal`         | STRUCTURAL | Missing required UID halts routing; null-pointer in parsers that assume presence         |
| `_vr_length_boundary_attack`    | STRUCTURAL | VR maxlen+1 exercises fixed-size copy buffers                                            |
| `_delimiter_byte_injection`     | STRUCTURAL | DICOM Item/Delimiter bytes (FFFE,E000/E0DD) in text fields confuse byte-scanning parsers |
| `_patient_identifier_attack`    | CONTENT    | SQL/XSS/path-traversal strings; parser reads fine                                        |
| `_patient_demographics_attack`  | CONTENT    | Invalid sex/age/weight codes; no parse effect                                            |
| `_study_metadata_attack`        | CONTENT    | Date/string fields; no parse effect                                                      |
| `_series_metadata_attack`       | CONTENT    | Description strings; no parse effect                                                     |
| `_institution_personnel_attack` | CONTENT    | Name/address fields; no parse effect                                                     |
| `mutate_patient_info`           | CONTENT    | Fake demographics; no parse effect                                                       |

**Status**: split already implemented. No changes needed.

---

### ConformanceFuzzer — _already split_

| Method                       | Class      | Rationale                                              |
| ---------------------------- | ---------- | ------------------------------------------------------ |
| `_invalid_transfer_syntax`   | STRUCTURAL | Determines codec/allocation strategy                   |
| `_sop_transfer_mismatch`     | STRUCTURAL | Conflicting codec selection                            |
| `_missing_file_meta`         | STRUCTURAL | Parsers that assume preamble presence dereference null |
| `_corrupted_file_meta`       | STRUCTURAL | Preamble/version/length fields drive parser bootstrap  |
| `_retired_syntax_attack`     | STRUCTURAL | Retired codecs may have unpatched paths                |
| `_uid_format_violations`     | STRUCTURAL | Fixed-length UID copy buffers may overflow             |
| `_invalid_sop_class`         | STRUCTURAL | Unknown class may route to unguarded handler           |
| `_version_mismatch`          | CONTENT    | Version strings; parser normalizes                     |
| `_modality_sop_mismatch`     | CONTENT    | Modality tag is metadata; no allocation effect         |
| `_implementation_uid_attack` | CONTENT    | Implementation UID is informational                    |

**Status**: split already implemented. No changes needed.

---

### EncodingFuzzer — _already split_

| Method                         | Class      | Rationale                                                            |
| ------------------------------ | ---------- | -------------------------------------------------------------------- |
| `_invalid_utf8_sequences`      | STRUCTURAL | Continuation/overlong bytes crash UTF-8 state machines               |
| `_overlong_utf8`               | STRUCTURAL | CVE-2000-0884 class — overlong encodings bypass length checks        |
| `_null_byte_injection`         | STRUCTURAL | Null bytes truncate C-string reads; strlen undercount                |
| `_escape_sequence_injection`   | STRUCTURAL | ISO 2022 escapes switch charset mid-string; decoder state corruption |
| `_bom_injection`               | STRUCTURAL | BOM bytes at field start confuse VR-width calculations               |
| `_surrogate_pair_attack`       | STRUCTURAL | UTF-16 surrogates in UTF-8 context are invalid; decoder may panic    |
| `_charset_data_mismatch`       | STRUCTURAL | Encoding-aware parsers crash on bytes invalid in declared charset    |
| `_invalid_charset_value`       | CONTENT    | Unknown charset label; parser falls back to ASCII                    |
| `_mixed_encoding_attack`       | CONTENT    | Parser reads bytes; rendering produces garbage, not crash            |
| `_control_character_injection` | CONTENT    | Control chars in strings; most parsers store and continue            |

**Status**: split already implemented. No changes needed.

---

### HeaderFuzzer — _already annotated_

| Method                        | Class      | Rationale                                                 |
| ----------------------------- | ---------- | --------------------------------------------------------- |
| `_overlong_strings`           | STRUCTURAL | 1024+ char strings overflow fixed VR copy buffers         |
| `_missing_required_tags`      | STRUCTURAL | Required UIDs — null-pointer on absent assumption         |
| `_boundary_values`            | STRUCTURAL | Min/max for numeric VRs — integer overflow/underflow      |
| `_numeric_vr_mutations`       | STRUCTURAL | Boundary integers trigger overflow in VR-typed arithmetic |
| `_uid_mutations`              | STRUCTURAL | UID format violations — fixed-length buffer overflow      |
| `_comprehensive_vr_mutations` | STRUCTURAL | VR-typed mutations; wrong size drives allocation          |

**Status**: annotations present. No changes needed.

---

### PrivateTagFuzzer — _already annotated_

| Method                     | Class      | Rationale                                                      |
| -------------------------- | ---------- | -------------------------------------------------------------- |
| `_missing_creator`         | STRUCTURAL | Private data without creator — parser cannot resolve VR        |
| `_wrong_creator`           | STRUCTURAL | Wrong/malicious creator identifier breaks VR lookup            |
| `_creator_collision`       | STRUCTURAL | Multiple creators claiming same block — parser state confusion |
| `_invalid_private_vr`      | STRUCTURAL | Numeric-as-string/string-as-binary causes wrong allocation     |
| `_oversized_private_data`  | STRUCTURAL | Large OB elements — heap pressure / allocation failure         |
| `_creator_overwrite`       | STRUCTURAL | Overwrites standard tags with private — parser sees wrong VR   |
| `_reserved_group_attack`   | STRUCTURAL | Reserved groups (0x0001/0xFFFF) trigger unguarded paths        |
| `_private_sequence_attack` | STRUCTURAL | Deeply nested/circular sequences in private blocks             |
| `_binary_blob_injection`   | STRUCTURAL | JPEG/ZIP/ELF headers in OB fields — codec dispatch confusion   |
| `_private_tag_injection`   | CONTENT    | Injection strings in private text fields                       |

**Status**: annotations present. No changes needed.

---

### StructureFuzzer — _all structural, needs annotation only_

| Method                         | Class      | Rationale                                                               |
| ------------------------------ | ---------- | ----------------------------------------------------------------------- |
| `_corrupt_tag_ordering`        | STRUCTURAL | Shuffled elements violate strict parsers' sort assumption               |
| `_corrupt_length_fields`       | STRUCTURAL | Overflow/underflow/null patterns in string length fields                |
| `_insert_unexpected_tags`      | STRUCTURAL | Reserved/invalid group tags (0xFFFF, 0xDEAD) trigger unguarded handlers |
| `_duplicate_tags`              | STRUCTURAL | Duplicate tag presence crashes parsers that assume uniqueness           |
| `_length_field_attacks`        | STRUCTURAL | Extreme/zero/negative/odd/boundary length values                        |
| `_vm_mismatch_attacks`         | STRUCTURAL | Value Multiplicity mismatch — wrong array allocation size               |
| `_binary_corrupt_tag_ordering` | STRUCTURAL | Post-serialization byte swap — binary stream parser confusion           |
| `_binary_duplicate_tag`        | STRUCTURAL | Post-serialization element duplication                                  |
| `_binary_corrupt_length_field` | STRUCTURAL | Post-serialization length field overwrite                               |

**Status**: no logic changes needed. Adding `# [STRUCTURAL]` annotations.

---

### CompressedPixelFuzzer — _all structural, needs annotation only_

| Method                             | Class      | Rationale                                                           |
| ---------------------------------- | ---------- | ------------------------------------------------------------------- |
| `_corrupt_jpeg_markers`            | STRUCTURAL | JPEG marker corruption → infinite loop / buffer overflow in codec   |
| `_corrupt_jpeg_dimensions`         | STRUCTURAL | SOF dimension vs DICOM Rows/Columns mismatch → allocation error     |
| `_corrupt_jpeg2000_codestream`     | STRUCTURAL | SIZ/COD marker corruption → codestream parser state machine crash   |
| `_corrupt_rle_segments`            | STRUCTURAL | Wrong segment counts/offsets → out-of-bounds reads                  |
| `_corrupt_fragment_offsets`        | STRUCTURAL | Invalid Basic Offset Table → random memory access                   |
| `_corrupt_encapsulation_structure` | STRUCTURAL | Wrong Item/Delimiter tags break encapsulation parser                |
| `_inject_malformed_frame`          | STRUCTURAL | Bad frame injected among valid frames — per-frame allocator         |
| `_frame_count_mismatch`            | STRUCTURAL | Declared frames vs actual encapsulated frames — allocation mismatch |

**Status**: no logic changes needed. Adding `# [STRUCTURAL]` annotations.

---

### SequenceFuzzer — _needs split_

| Method                       | Class      | Rationale                                                                     |
| ---------------------------- | ---------- | ----------------------------------------------------------------------------- |
| `_deep_nesting_attack`       | STRUCTURAL | 50–1000 levels of nesting — call-stack exhaustion / stack overflow            |
| `_item_length_mismatch`      | STRUCTURAL | Extreme-length strings in items — buffer overflow                             |
| `_empty_required_sequence`   | STRUCTURAL | Empty sequences where items required — null-pointer dereference               |
| `_orphan_item_attack`        | STRUCTURAL | Item tag bytes (FFFE,E000) embedded in private data — byte-scanning confusion |
| `_delimiter_corruption`      | STRUCTURAL | Sequence delimiter bytes (FFFE,E0DD) in text — state machine violation        |
| `_massive_item_count`        | STRUCTURAL | 1000–10000 items — allocation exhaustion                                      |
| `_circular_reference_attack` | CONTENT    | Circular UIDs — stored and ignored at parse time                              |
| `_mixed_encoding_sequence`   | CONTENT    | Mixed charsets per item — rendering issue, not parse crash                    |

**Status**: split implemented.

---

### EncapsulatedPDFFuzzer — _needs split_

| Method                      | Class      | Rationale                                                              |
| --------------------------- | ---------- | ---------------------------------------------------------------------- |
| `_document_size_attack`     | STRUCTURAL | Zero/single-byte/truncated encapsulated document — boundary allocation |
| `_malformed_pdf_injection`  | STRUCTURAL | Non-PDF headers (JPEG/ELF/ZIP) in encapsulated field — codec dispatch  |
| `_pdf_structure_corruption` | STRUCTURAL | Corrupt xref, truncated stream, recursive pages, JS injection          |
| `_type_confusion`           | STRUCTURAL | Non-bytes type for binary OB field — VR type dispatch failure          |
| `_mime_type_mismatch`       | CONTENT    | Wrong MIMEType string — metadata, parser stores and continues          |
| `_pdf_metadata_corruption`  | CONTENT    | DocumentTitle / ConceptNameCodeSequence strings — content only         |

**Status**: split implemented.

---

### NMFuzzer — _needs split_

| Method                        | Class      | Rationale                                                                                 |
| ----------------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| `_energy_window_corruption`   | STRUCTURAL | Includes empty-sequence attack (null-pointer); inverted ranges exercise range-check paths |
| `_detector_geometry_mismatch` | STRUCTURAL | Count mismatch + invalid types corrupt sequence allocation                                |
| `_slice_count_mismatch`       | STRUCTURAL | Frame count vs NumberOfSlices mismatch — allocation/indexing error                        |
| `_rotation_parameter_attack`  | CONTENT    | SPECT rotation angles/steps — rendering/reconstruction values only                        |

**Status**: split implemented.

---

### RTDoseFuzzer — _needs split_

| Method                           | Class      | Rationale                                                              |
| -------------------------------- | ---------- | ---------------------------------------------------------------------- |
| `_grid_frame_offset_attack`      | STRUCTURAL | GridFrameOffsetVector length mismatch vs NumberOfFrames — indexing OOB |
| `_dvh_sequence_corruption`       | STRUCTURAL | DVH bin count mismatch — fixed-size copy into wrong-sized buffer       |
| `_dose_grid_scaling_attack`      | CONTENT    | DoseGridScaling is a rendering multiplier; parser reads it fine        |
| `_dose_type_enumeration_attack`  | CONTENT    | DoseType/DoseSummationType string enumerations — stored, not executed  |
| `_referenced_rt_plan_corruption` | CONTENT    | Plan UID cross-references — integrity issue, not parse crash           |

**Status**: split implemented.

---

### RTSSFuzzer — _needs split_

| Method                             | Class      | Rationale                                                               |
| ---------------------------------- | ---------- | ----------------------------------------------------------------------- |
| `_contour_point_count_mismatch`    | STRUCTURAL | NumberOfContourPoints vs actual ContourData length — array indexing OOB |
| `_contour_data_corruption`         | CONTENT    | NaN/Inf/extreme in ContourData DS values — math library, not parser     |
| `_roi_cross_reference_attack`      | CONTENT    | ROINumber integrity — UID reference, not parse crash                    |
| `_contour_geometric_type_mismatch` | CONTENT    | ContourGeometricType string — metadata, stored fine                     |
| `_frame_of_reference_corruption`   | CONTENT    | FrameOfReference UID — cross-reference integrity                        |

**Status**: split implemented.

---

### SegmentationFuzzer — _needs split_

| Method                          | Class      | Rationale                                                              |
| ------------------------------- | ---------- | ---------------------------------------------------------------------- |
| `_segment_sequence_corruption`  | STRUCTURAL | Duplicate/gap/zero/empty SegmentSequence — structural sequence parsing |
| `_segment_frame_mapping_attack` | STRUCTURAL | SegmentIdentificationSequence cross-ref — frame indexing OOB           |
| `_binary_pixel_type_mismatch`   | STRUCTURAL | SegmentationType vs BitsAllocated — allocation size mismatch           |
| `_referenced_series_corruption` | CONTENT    | ReferencedSeriesSequence UIDs — cross-reference integrity only         |

**Status**: split implemented.

---

### ReferenceFuzzer — _all content, needs structural additions_

| Method                        | Class      | Rationale                                                             |
| ----------------------------- | ---------- | --------------------------------------------------------------------- |
| `_orphan_reference`           | CONTENT    | Non-existent SOP instance UID — stored, navigation fails, parser fine |
| `_circular_reference`         | CONTENT    | Circular UID chains — stored fine at parse time                       |
| `_self_reference`             | CONTENT    | Self-referential UIDs — stored fine                                   |
| `_invalid_frame_reference`    | CONTENT    | Out-of-range frame numbers — rendering issue, not parse crash         |
| `_mismatched_study_reference` | CONTENT    | Study/series hierarchy mismatch — integrity issue                     |
| `_broken_series_reference`    | CONTENT    | Empty/duplicate instance refs — integrity issue                       |
| `_frame_of_reference_attack`  | CONTENT    | FoR UID corruption — spatial ref integrity                            |
| `_duplicate_references`       | CONTENT    | Identical object refs — stored fine                                   |
| `_massive_reference_chain`    | CONTENT    | Long UID chains (100–1000) — performance issue, not crash             |
| `_reference_type_mismatch`    | CONTENT    | Wrong SOP class in ref — integrity issue                              |
| `_uid_length_overflow`        | STRUCTURAL | **NEW** — UID > 64 chars overflows fixed-length UID copy buffers      |
| `_uid_non_ascii`              | STRUCTURAL | **NEW** — non-ASCII bytes in UID crash byte-scanning UID validators   |

**Status**: implemented -- 2 new structural methods added, existing 10 demoted to content at 15%.

---

### PetFuzzer — _all content, needs structural addition_

| Method                                  | Class      | Rationale                                                                  |
| --------------------------------------- | ---------- | -------------------------------------------------------------------------- |
| `_suv_calibration_chain_attack`         | CONTENT    | Units/DecayCorrection/PatientWeight — calibration metadata                 |
| `_temporal_parameter_corruption`        | CONTENT    | DecayFactor/FrameReferenceTime — timing values, parser stores fine         |
| `_corrected_image_flag_attack`          | CONTENT    | CorrectedImage flag combinations — stored fine                             |
| `_corrupt_radiopharmaceutical_sequence` | STRUCTURAL | **NEW** — empty/malformed RadiopharmaceuticalInformationSequence structure |

**Status**: implemented -- `_corrupt_radiopharmaceutical_sequence` added; existing 3 demoted to content at 33%.

---

### CalibrationFuzzer — _all content, needs structural additions_

| Method                      | Class      | Rationale                                                                 |
| --------------------------- | ---------- | ------------------------------------------------------------------------- |
| `fuzz_pixel_spacing`        | CONTENT    | PixelSpacing DS values — rendering calibration, parser fine               |
| `fuzz_hounsfield_rescale`   | CONTENT    | RescaleSlope/Intercept — HU conversion, parser fine                       |
| `fuzz_window_level`         | CONTENT    | WindowCenter/Width — display parameters, parser fine                      |
| `fuzz_slice_thickness`      | CONTENT    | SliceThickness DS value — calibration only                                |
| `_vr_type_confusion`        | STRUCTURAL | **NEW** — put Sequence item in DS field; VR-dispatch allocates wrong type |
| `_oversized_numeric_string` | STRUCTURAL | **NEW** — 100 KB PixelSpacing string overflows VR fixed-copy buffers      |

**Status**: implemented -- 2 new structural methods added; existing 4 demoted to content at 33%.

---

### DictionaryFuzzer — _internal split, annotations only_

Internal 70%/30% split already implemented: 70% valid dictionary values (content),
30% edge cases (empty, null, very long — borderline structural). Add inline
annotations; no logic changes needed.

---

## Summary

| Fuzzer                | Structural | Content | Status                      |
| --------------------- | ---------- | ------- | --------------------------- |
| StructureFuzzer       | 9          | 0       | Annotate only               |
| CompressedPixelFuzzer | 8          | 0       | Annotate only               |
| PixelFuzzer           | 9          | 3       | Already split               |
| MetadataFuzzer        | 3          | 6       | Already split               |
| ConformanceFuzzer     | 7          | 3       | Already split               |
| EncodingFuzzer        | 7          | 3       | Already split               |
| HeaderFuzzer          | 6          | 0       | Already annotated           |
| PrivateTagFuzzer      | 9          | 1       | Already annotated           |
| SequenceFuzzer        | 6          | 2       | Split implemented           |
| EncapsulatedPDFFuzzer | 4          | 2       | Split implemented           |
| NMFuzzer              | 3          | 1       | Split implemented           |
| RTDoseFuzzer          | 2          | 3       | Split implemented           |
| RTSSFuzzer            | 1          | 4       | Split implemented           |
| SegmentationFuzzer    | 3          | 1       | Split implemented           |
| ReferenceFuzzer       | 0+2 new    | 10      | New structural + split impl |
| PetFuzzer             | 0+1 new    | 3       | New structural + split impl |
| CalibrationFuzzer     | 0+2 new    | 4       | New structural + split impl |
| DictionaryFuzzer      | ~30%       | ~70%    | Annotate only               |
