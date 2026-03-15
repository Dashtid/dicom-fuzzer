# DICOM Fuzzer

Mutation-based fuzzer for robustness testing of DICOM medical imaging viewers and parsers. Generates malformed DICOM files and feeds them into target applications to find crashes and vulnerabilities.

[![CI](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Installation

```bash
git clone https://github.com/Dashtid/DICOM-Fuzzer.git
cd DICOM-Fuzzer
uv sync
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
```

## Quick Start

```bash
# Generate 100 fuzzed DICOM files
dicom-fuzzer input.dcm -c 100 -o ./artifacts/output

# Fuzz and test against a target viewer
dicom-fuzzer input.dcm -c 1000 -t ./viewer.exe --timeout 10

# Generate seed corpus for AFL/WinAFL
dicom-fuzzer generate-seeds input.dcm -c 500 -o ./seeds/
```

## Features

### Fuzzing

- 28 mutation strategies across 4 tiers: metadata, structure/encoding, pixel/modality-specific, multi-frame
- 18 format fuzzers (generic + modality-specific: SEG, RTSS, RT Dose, NM, PET, Encapsulated PDF)
- 10 multiframe strategies (frame count, temporal, dimensional, encapsulated pixel)
- 3D series fuzzing (CT/MRI volumetric data)
- Study-level cross-series attacks
- Network protocol fuzzing (DIMSE, TLS) -- experimental

### Analysis

- Automatic crash detection and deduplication
- Crash triaging with severity and exploitability scoring
- Test case minimization
- Corpus management
- HTML campaign reports with per-strategy hit rates

### Integration

- CLI with 11 subcommands
- Python API for custom workflows
- Docker container for isolated execution
- CI/CD compatible

## CLI Reference

```bash
dicom-fuzzer --help              # Main fuzzing campaign
dicom-fuzzer target --help       # Target testing
dicom-fuzzer generate-seeds --help  # Seed corpus generation
dicom-fuzzer report --help       # Report generation
dicom-fuzzer corpus --help       # Corpus management
dicom-fuzzer tls --help          # TLS/auth testing
```

See [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for full command documentation.

## Python API

```python
from dicom_fuzzer.core.mutation.mutator import DicomMutator
import pydicom

mutator = DicomMutator()
dataset = pydicom.dcmread("input.dcm")

for i in range(100):
    fuzzed = mutator.apply_mutations(dataset)
    fuzzed.save_as(f"artifacts/output/fuzz_{i:04d}.dcm")
```

## Project Structure

```text
dicom-fuzzer/
├── dicom_fuzzer/    # Main package
│   ├── attacks/     # Attack modules (format, series, network, multiframe)
│   ├── cli/         # Command-line interface (11 subcommands)
│   ├── core/        # Engine, mutation, corpus, crash analysis, harness, reporting
│   └── utils/       # Logging, hashing, identifiers
├── tests/           # Test suite
├── docs/            # Documentation
└── artifacts/       # Runtime output (gitignored)
```

## Documentation

- [Quick Start Guide](docs/QUICKSTART.md)
- [CLI Reference](docs/CLI_REFERENCE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Security

This tool is for authorized security testing only. See [SECURITY.md](SECURITY.md).

## License

MIT - see [LICENSE](LICENSE)
