# Architecture

Modular security testing framework for DICOM implementations.

## Stack

- Python 3.11+
- pydicom (DICOM parsing)
- structlog (logging)
- pytest/Hypothesis (testing)

## Project Structure

```text
dicom-fuzzer/
├── dicom_fuzzer/
│   ├── cli/           # Command-line interfaces
│   ├── core/          # Core fuzzing logic (~70 modules)
│   ├── cve/           # CVE replication (deterministic)
│   ├── attacks/       # Attack modules (format, series, network, multiframe)
│   ├── analytics/     # Campaign analytics
│   ├── adapters/      # Viewer-specific automation
│   ├── harness/       # Target execution harness
│   └── utils/         # Utilities
│   └── tools/         # Scripts, examples, benchmarks
├── tests/             # Test suite
└── docs/              # Documentation
```

## Core Components

| Component    | Module                      | Purpose                        |
| ------------ | --------------------------- | ------------------------------ |
| Parser       | `core/parser.py`            | DICOM parsing, metadata        |
| Mutator      | `core/mutator.py`           | Strategy registration          |
| Generator    | `core/generator.py`         | Batch fuzzed file generation   |
| Validator    | `core/validator.py`         | DICOM compliance checking      |
| Crash Triage | `core/crash_triage.py`      | Crash analysis and severity    |
| Coverage     | `core/coverage_tracker.py`  | Coverage-guided selection      |
| Session      | `core/fuzzing_session.py`   | Campaign lifecycle             |
| Reporter     | `core/enhanced_reporter.py` | HTML/JSON reports              |
| Network      | `core/network_fuzzer.py`    | DICOM protocol fuzzing         |
| GUI Monitor  | `core/gui_monitor.py`       | Process monitoring             |

## Data Flow

```text
Input DICOM
    │
    ▼
Parsing (DicomParser)
    │
    ▼
Mutation (Strategy Selection → Apply)
    │
    ▼
Generation (Batch Write)
    │
    ▼
Validation (Security + Compliance)
    │
    ▼
Reporting (HTML/JSON)
```

### Coverage-Guided Flow

```text
Corpus → Mutate → Execute Target → Track Coverage → Detect Crashes
                        │
              New path? → Add to corpus
                        │
              Crash? → Deduplicate → Minimize → Triage
```

## Attack Architecture

```text
attacks/
├── format/               # DICOM file format attacks (13 fuzzers)
│   ├── HeaderFuzzer          # VR and tag mutations
│   ├── PixelFuzzer           # Image dimensions, pixel data
│   ├── MetadataFuzzer        # Patient/study metadata
│   ├── StructureFuzzer       # File structure, length fields
│   ├── SequenceFuzzer        # Nested sequences, items
│   ├── MultiFrameFuzzer      # Multi-frame specific
│   ├── CompressedPixelFuzzer # JPEG/RLE encapsulation
│   ├── EncodingFuzzer        # Character sets, text encoding
│   ├── ConformanceFuzzer     # SOP Class, Transfer Syntax
│   ├── ReferenceFuzzer       # Reference chains, links
│   ├── PrivateTagFuzzer      # Vendor-specific tags
│   ├── CalibrationFuzzer     # Measurement/calibration
│   └── DictionaryFuzzer      # Domain-based dictionary mutations
├── series/               # Multi-slice 3D volume mutations
│   ├── Series3DMutator       # Main class with mixins
│   ├── CoreMutationsMixin    # Metadata, slice operations
│   ├── Reconstruction3DAttacksMixin  # 3D reconstruction
│   ├── TemporalAttacksMixin  # Cross-slice temporal
│   ├── StudyMutator          # Cross-series study-level
│   └── ParallelSeriesMutator # Multi-process wrapper
├── multiframe/           # Multi-frame mutation strategies
│   ├── FrameCountMismatchStrategy   # NumberOfFrames attacks
│   ├── FrameTimeCorruptionStrategy  # Temporal info corruption
│   ├── DimensionOverflowStrategy    # Integer overflow via dimensions
│   └── ...                          # 5 more frame-level strategies
└── network/              # Network protocol fuzzing
    ├── dimse/                # DIMSE protocol layer
    ├── tls/                  # TLS security testing
    └── stateful/             # Stateful protocol fuzzing
```

CLI strategy flags (`-s metadata,pixel`) map to format fuzzers internally.

## CVE Module

CVE replication is deterministic (not fuzzing). Located in `dicom_fuzzer/cve/`:

```text
cve/
├── registry.py      # CVE metadata and lookup
├── generator.py     # File generation from templates
└── payloads/        # Per-CVE exploit payloads
```

Usage: `dicom-fuzzer cve --list`

## Extending

1. Subclass `MutationStrategy`
2. Implement `mutate()` method
3. Register with mutator

See [attacks/](../dicom_fuzzer/attacks/) for examples.
