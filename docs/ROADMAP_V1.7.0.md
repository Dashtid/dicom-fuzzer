# DICOM Fuzzer v1.7.0 - 3D Medical Application Fuzzing

**Status**: Implemented
**Released**: 2025-12-22
**Focus**: Enhanced 3D reconstruction, measurement, and study-level fuzzing

---

## Executive Summary

This release focuses on vulnerabilities specific to 3D medical imaging applications that process patient studies. Based on 2025 CVE research and DICOM security best practices, we're adding:

1. **Study-Level Fuzzing** - Multi-series coordination attacks
2. **Reconstruction Attack Vectors** - Geometry and interpolation exploitation
3. **Measurement/Calibration Fuzzing** - PixelSpacing and HU manipulation
4. **Memory Stress Testing** - Large series and long-duration testing

---

## Gap Analysis

### Already Implemented (v1.5.0)

| Feature                                       | Module                | Coverage |
| --------------------------------------------- | --------------------- | -------- |
| Slice position attacks (NaN, Inf, duplicates) | `series_mutator.py`   | Complete |
| ImageOrientationPatient flipping              | `series_mutator.py`   | Partial  |
| PixelSpacing variation                        | `series_mutator.py`   | Basic    |
| Boundary slice targeting                      | `series_mutator.py`   | Complete |
| Gradient mutations                            | `series_mutator.py`   | Complete |
| Series consistency validation                 | `series_validator.py` | Complete |
| Geometry validation (spacing, overlap)        | `series_validator.py` | Complete |
| Memory exhaustion warnings                    | `series_validator.py` | Basic    |
| Rows/Columns boundary values                  | `header_fuzzer.py`    | Complete |
| SliceThickness invalid values                 | `header_fuzzer.py`    | Basic    |

### Gaps to Fill (v1.7.0)

| Gap                                 | Priority | Rationale                                              |
| ----------------------------------- | -------- | ------------------------------------------------------ |
| Study-level multi-series attacks    | P1       | Cross-series reference corruption, PatientID conflicts |
| FrameOfReferenceUID attacks         | P1       | Registration and fusion failures                       |
| Non-orthogonal orientation vectors  | P2       | Invalid reconstruction basis                           |
| Systematic slice gap injection      | P2       | Missing slice handling in reconstruction               |
| ImagerPixelSpacing vs PixelSpacing  | P2       | Measurement calibration bypass                         |
| RescaleSlope/Intercept extremes     | P2       | HU calculation corruption                              |
| WindowCenter/WindowWidth edge cases | P3       | Display/measurement visibility                         |
| Large series stress (1000+ slices)  | P3       | Memory handling validation                             |

---

## Phase 1: Study-Level Framework

**New Module**: `dicom_fuzzer/strategies/study_mutator.py`

### Features

1. **StudyMutator Class**
   - Orchestrate mutations across multiple series in a study
   - Maintain study-level consistency where needed, break it for attacks

2. **Cross-Series Reference Attacks**
   - Corrupt `ReferencedSeriesSequence` to point to non-existent series
   - Create circular references between series
   - Break `StudyInstanceUID` consistency across series

3. **Patient Consistency Attacks**
   - Different PatientID/PatientName across series in same study
   - Conflicting PatientBirthDate, PatientSex
   - Mixed demographic data to test viewer merging logic

4. **Frame of Reference Attacks**
   - Different `FrameOfReferenceUID` for series that should be co-registered
   - Same `FrameOfReferenceUID` for unrelated series (fusion confusion)
   - Invalid/empty `FrameOfReferenceUID`

### API Design

```python
from dicom_fuzzer.strategies.study_mutator import StudyMutator, StudyMutationStrategy

mutator = StudyMutator(severity="aggressive")

# Load multiple series as a study
study = mutator.load_study(study_dir)

# Apply study-level attacks
fuzzed_study, records = mutator.mutate_study(
    study,
    strategy=StudyMutationStrategy.CROSS_SERIES_REFERENCE,
    mutation_count=5
)
```

### Files to Create

- `dicom_fuzzer/strategies/study_mutator.py` (~400 lines)
- `tests/test_strategies/test_study_mutator.py` (~300 lines)

---

## Phase 2: 3D Reconstruction Attack Vectors

**Enhance**: `dicom_fuzzer/strategies/series_mutator.py`

### New Mutation Strategies

1. **Non-Orthogonal Orientation Vectors**
   - ImageOrientationPatient with non-unit vectors
   - Non-perpendicular row/column vectors (dot product != 0)
   - Degenerate vectors (zero length, parallel)

2. **Systematic Slice Gap Injection**
   - Remove every Nth slice systematically
   - Create large gaps in specific anatomical regions
   - Remove boundary slices (first/last 3)

3. **Slice Overlap Injection**
   - Multiple slices at exact same Z position
   - Slices with Z-spacing < SliceThickness (overlap)
   - Negative slice spacing (reversed order)

4. **Voxel Aspect Ratio Attacks**
   - Extreme non-isotropic spacing (10:1 ratio)
   - PixelSpacing[0] != PixelSpacing[1] (non-square pixels)
   - SliceThickness >> in-plane spacing (pancake voxels)

5. **Frame of Reference Corruption** (series-level)
   - Empty FrameOfReferenceUID
   - Mismatched across slices in same series
   - Invalid UID format

### Code Changes

Add to `SeriesMutationStrategy` enum:

```python
NON_ORTHOGONAL_ORIENTATION = "non_orthogonal_orientation"
SYSTEMATIC_SLICE_GAP = "systematic_slice_gap"
SLICE_OVERLAP_INJECTION = "slice_overlap_injection"
VOXEL_ASPECT_RATIO = "voxel_aspect_ratio"
FRAME_OF_REFERENCE = "frame_of_reference"
```

### Files to Modify

- `dicom_fuzzer/strategies/series_mutator.py` (+200 lines)
- `tests/test_strategies/test_series_mutator.py` (+150 lines)

---

## Phase 3: Measurement/Calibration Fuzzing

**New Module**: `dicom_fuzzer/strategies/calibration_fuzzer.py`

### Features

1. **PixelSpacing Calibration Attacks**
   - `PixelSpacing` vs `ImagerPixelSpacing` mismatch
   - `PixelSpacingCalibrationType` = "GEOMETRY" with wrong values
   - Zero or negative pixel spacing

2. **Hounsfield Unit Manipulation**
   - `RescaleSlope` = 0 (divide by zero)
   - `RescaleSlope` = NaN, Inf, -Inf
   - `RescaleIntercept` extreme values (-32768, 32767)
   - Inconsistent rescale parameters across slices

3. **Window/Level Edge Cases**
   - `WindowWidth` = 0 (divide by zero in normalization)
   - `WindowCenter` at extreme values
   - Multiple window/level presets with conflicts
   - Negative window width

4. **Distance/Volume Calculation Attacks**
   - `SliceThickness` = 0 (volume calculation failure)
   - `SpacingBetweenSlices` != actual spacing
   - Conflicting thickness metadata

### API Design

```python
from dicom_fuzzer.strategies.calibration_fuzzer import CalibrationFuzzer

fuzzer = CalibrationFuzzer()

# Single file calibration attacks
fuzzed_ds = fuzzer.fuzz_pixel_spacing(dataset)
fuzzed_ds = fuzzer.fuzz_hounsfield_rescale(dataset)
fuzzed_ds = fuzzer.fuzz_window_level(dataset)

# Series-level calibration inconsistency
fuzzed_series = fuzzer.inject_calibration_inconsistency(series)
```

### Files to Create

- `dicom_fuzzer/strategies/calibration_fuzzer.py` (~300 lines)
- `tests/test_strategies/test_calibration_fuzzer.py` (~200 lines)

---

## Phase 4: Memory & Stress Testing

**New Module**: `dicom_fuzzer/harness/stress_tester.py`

### Features

1. **Large Series Generation**
   - Generate 1000+ slice synthetic series
   - Configurable dimensions (4096x4096 max)
   - Memory footprint estimation

2. **Long-Duration Stability Testing**
   - Extended viewer sessions with fuzzed data
   - Memory leak detection over time
   - Resource monitoring (CPU, RAM, GPU)

3. **Incremental Loading Attacks**
   - Partial series loading (simulate interrupted transfers)
   - Missing middle slices
   - Corrupt slice in middle of valid series

4. **Large Pixel Data**
   - 16-bit deep (vs 8-bit)
   - Multi-frame DICOM with 100+ frames
   - Compressed with invalid compression params

### API Design

```python
from dicom_fuzzer.harness.stress_tester import StressTester, StressTestConfig

config = StressTestConfig(
    max_slices=1000,
    max_dimensions=(4096, 4096),
    duration_minutes=60,
    monitor_memory=True
)

tester = StressTester(config)

# Generate stress corpus
stress_series = tester.generate_large_series(slice_count=1000)

# Run long-duration test
results = tester.run_duration_test(
    viewer_path="path/to/viewer.exe",
    series=stress_series,
    duration_minutes=60
)

print(f"Memory peak: {results.memory_peak_mb} MB")
print(f"Crashes detected: {len(results.crashes)}")
```

### Files to Create

- `dicom_fuzzer/harness/stress_tester.py` (~350 lines)
- `tests/test_harness/test_stress_tester.py` (~200 lines)

---

## Implementation Summary

| Phase              | Module                       | New Lines  | New Tests | Priority |
| ------------------ | ---------------------------- | ---------- | --------- | -------- |
| P1: Study-Level    | `study_mutator.py`           | ~400       | ~50       | High     |
| P2: Reconstruction | `series_mutator.py` (extend) | ~200       | ~40       | High     |
| P3: Calibration    | `calibration_fuzzer.py`      | ~300       | ~40       | Medium   |
| P4: Stress Testing | `stress_tester.py`           | ~350       | ~30       | Medium   |
| **Total**          | **4 modules**                | **~1,250** | **~160**  | -        |

---

## CLI Integration

New subcommands for v1.7.0:

```bash
# Study-level fuzzing
dicom-fuzzer study --fuzz /path/to/study --output ./fuzzed

# Calibration attacks
dicom-fuzzer calibrate --attack rescale --input series/ --output ./output

# Stress testing
dicom-fuzzer stress --generate 1000 --dimensions 2048x2048 --output ./large

# Long-duration test
dicom-fuzzer stress --duration 60 --viewer "path/to/viewer.exe" --input ./large
```

---

## Testing Strategy

1. **Unit Tests**: Each new mutation type has dedicated tests
2. **Integration Tests**: Full workflow from study loading to fuzzed output
3. **Benchmark Tests**: Performance baselines for large series handling
4. **CVE Validation**: Verify attacks against known vulnerable software

---

## Security Research References

- [DICOM 3D Reconstruction Vulnerabilities](https://ajronline.org/doi/full/10.2214/AJR.19.21958)
- [Cybersecurity in PACS and Medical Imaging (PMC)](https://pmc.ncbi.nlm.nih.gov/articles/PMC7728878/)
- [DICOM Pixel Spacing Calibration (NEMA)](https://dicom.nema.org/medical/dicom/current/output/chtml/part03/sect_10.7.html)
- [CVE-2025-5943: MicroDicom OOB Write](https://www.hipaajournal.com/microdicom-dicom-viewer-vulnerability-june-2025/)
- [DICOM-Fuzzer Research (SpringerLink)](https://link.springer.com/chapter/10.1007/978-3-030-41114-5_38)

---

## Success Criteria

1. All 4 phases implemented with 100% test coverage on new code
2. Documentation updated (ARCHITECTURE.md, README.md, CHANGELOG.md)
3. CLI subcommands functional and documented
4. At least 3 unique crash vectors discovered in testing against open-source viewers
5. Performance: Generate 1000-slice series in < 60 seconds

---

**Last Updated**: 2025-12-22
**Author**: DICOM Fuzzer Team
