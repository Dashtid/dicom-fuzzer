# Architecture

Mutation-based fuzzer for robustness testing of DICOM viewers and parsers.

## Stack

- Python 3.11+
- pydicom (DICOM parsing)
- structlog (logging)
- pytest/Hypothesis (testing)

## Project Structure

```text
dicom-fuzzer/
├── dicom_fuzzer/
│   ├── cli/           # Command-line interface (11 subcommands)
│   ├── core/          # Core logic
│   │   ├── dicom/         # Parsing, validation, series detection
│   │   ├── mutation/      # Mutation engine and strategies
│   │   ├── engine/        # File generation pipeline
│   │   ├── corpus/        # Corpus management and minimization
│   │   ├── crash/         # Crash analysis and triaging
│   │   ├── session/       # Campaign lifecycle
│   │   ├── reporting/     # HTML/JSON report generation
│   │   ├── harness/       # Target execution and process monitoring
│   │   ├── adapters/      # Viewer-specific automation
│   │   └── analytics/     # Campaign analytics and visualization
│   ├── cve/           # CVE replication (deterministic, 22 CVEs)
│   ├── attacks/       # Attack modules (format, series, network, multiframe)
│   ├── utils/         # Utilities
│   └── tools/         # Benchmarks and scripts
├── tests/             # Test suite (5000+ tests)
└── docs/              # Documentation
```

## Core Components

| Component       | Module                                | Purpose                      |
| --------------- | ------------------------------------- | ---------------------------- |
| Parser          | `core/dicom/parser.py`                | DICOM parsing, metadata      |
| Mutator         | `core/mutation/mutator.py`            | Mutation strategy engine     |
| Generator       | `core/engine/generator.py`            | Batch fuzzed file generation |
| Validator       | `core/dicom/validator.py`             | DICOM compliance checking    |
| Crash Triage    | `core/crash/crash_triage.py`          | Crash analysis and severity  |
| Corpus          | `core/corpus/corpus.py`               | Corpus management            |
| Session         | `core/session/fuzzing_session.py`     | Campaign lifecycle           |
| Reporter        | `core/reporting/enhanced_reporter.py` | HTML/JSON reports            |
| Target Runner   | `core/harness/target_runner.py`       | Target execution harness     |
| Process Monitor | `core/harness/process_monitor.py`     | Process monitoring           |

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
Target Testing (optional: feed files to viewer)
    │
    ▼
Crash Detection → Deduplication → Triaging
    │
    ▼
Reporting (HTML/JSON)
```

## Attack Architecture

```text
attacks/
├── format/               # DICOM file format attacks (12 fuzzers, all inherit FormatFuzzerBase)
│   ├── FormatFuzzerBase      # ABC: mutate(dataset) + strategy_name
│   ├── HeaderFuzzer          # VR and tag mutations
│   ├── PixelFuzzer           # Image dimensions, pixel data
│   ├── MetadataFuzzer        # Patient/study/series/institution metadata
│   ├── StructureFuzzer       # File structure, length fields
│   ├── SequenceFuzzer        # Nested sequences, items
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
├── multiframe/           # Multi-frame mutation strategies (10 strategies)
│   ├── FrameCountMismatchStrategy   # NumberOfFrames attacks
│   ├── FrameTimeCorruptionStrategy  # Temporal info corruption
│   ├── DimensionOverflowStrategy    # Integer overflow via dimensions
│   ├── EncapsulatedPixelStrategy    # BOT/EOT/fragment attacks
│   ├── DimensionIndexStrategy       # Dimension index module attacks
│   └── ...                          # 5 more frame-level strategies
└── network/              # Network protocol fuzzing (experimental)
    ├── dimse/                # DIMSE protocol layer
    ├── tls/                  # TLS security testing
    └── stateful/             # Stateful protocol fuzzing
```

CLI strategy flags (`-s metadata,pixel`) map to format fuzzers internally.

## CVE Module

CVE replication is deterministic (not fuzzing). Located in `dicom_fuzzer/cve/`:

```text
cve/
├── registry.py      # CVE metadata and lookup (22 CVEs)
├── generator.py     # File generation from templates
└── payloads/        # Per-CVE mutation payloads
```

Usage: `dicom-fuzzer cve --list`

## Extending

1. Subclass `FormatFuzzerBase`
2. Implement `mutate(dataset)` method and `strategy_name` property
3. Register in `attacks/format/__init__.py`

See [attacks/format/](../dicom_fuzzer/attacks/format/) for examples.
