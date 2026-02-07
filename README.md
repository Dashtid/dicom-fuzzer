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

# Replicate known CVEs against a target
dicom-fuzzer cve --all -t template.dcm --target ./viewer.exe
```

## Features

### Fuzzing

- 12 mutation strategies: metadata, pixel, header, structure, encoding, sequences, compressed pixel, conformance, references, private tags, calibration, dictionary
- 3D series fuzzing (CT/MRI volumetric data)
- Multi-frame fuzzing (temporal, dimensional, encapsulated pixel)
- Study-level cross-series attacks
- Network protocol fuzzing (DIMSE, TLS) -- experimental

### CVE Replication

- 22 known DICOM CVEs with 75 deterministic variants
- Filter by product, category, or specific CVE ID
- Run generated files against a target viewer for validation
- Not fuzzing -- produces deterministic output for specific vulnerabilities

### Analysis

- Automatic crash detection and deduplication
- Crash triaging with severity and exploitability scoring
- Test case minimization
- Corpus management

### Integration

- CLI with 11 subcommands
- Python API for custom workflows
- Docker container for isolated execution
- CI/CD compatible

## CLI Reference

```bash
dicom-fuzzer --help              # Main help
dicom-fuzzer cve --help          # CVE replication
dicom-fuzzer report --help       # Report generation
dicom-fuzzer corpus --help       # Corpus management
dicom-fuzzer tls --help          # TLS/auth testing
```

See [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for full command documentation.

## Python API

```python
from dicom_fuzzer.core.mutation.mutator import DicomMutator
from dicom_fuzzer.core.types import MutationSeverity
import pydicom

mutator = DicomMutator()
dataset = pydicom.dcmread("input.dcm")

for i in range(100):
    fuzzed = mutator.mutate(dataset.copy(), severity=MutationSeverity.MODERATE)
    fuzzed.save_as(f"artifacts/output/fuzz_{i:04d}.dcm")
```

## Project Structure

```text
dicom-fuzzer/
├── dicom_fuzzer/    # Main package
│   ├── attacks/     # Attack modules (format, series, network, multiframe)
│   ├── cli/         # Command-line interface (11 subcommands)
│   ├── core/        # Engine, mutation, corpus, crash analysis, harness, reporting
│   ├── cve/         # CVE replication (deterministic, 22 CVEs)
│   └── utils/       # Logging, hashing, identifiers
├── tests/           # Test suite
├── docs/            # Documentation
└── artifacts/       # Runtime output (gitignored)
```

## Documentation

- [Quick Start Guide](docs/QUICKSTART.md)
- [CLI Reference](docs/CLI_REFERENCE.md)
- [CVE Reference](docs/CVE_REFERENCE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Security

This tool is for authorized security testing only. See [SECURITY.md](SECURITY.md).

## License

MIT - see [LICENSE](LICENSE)
