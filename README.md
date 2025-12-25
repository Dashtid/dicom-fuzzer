# DICOM Fuzzer

Security testing framework for DICOM medical imaging systems. Identifies vulnerabilities in PACS servers, medical imaging viewers, and DICOM parsers through automated fuzzing.

[![CI](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Dashtid/DICOM-Fuzzer/branch/main/graph/badge.svg)](https://codecov.io/gh/Dashtid/DICOM-Fuzzer)
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
# Basic fuzzing
dicom-fuzzer input.dcm -c 100 -o ./artifacts/output

# With target application testing
dicom-fuzzer input.dcm -c 1000 -t ./viewer.exe --timeout 10

# Generate HTML report
dicom-fuzzer report ./artifacts/output --format html
```

## Features

### Fuzzing

- Mutation-based and grammar-aware DICOM fuzzing
- **CVE-based security mutations enabled by default** (20 CVEs, 26 mutations)
- Coverage-guided fuzzing with corpus management
- 3D series fuzzing (CT/MRI volumetric data)
- Network protocol fuzzing (DIMSE, TLS)

### Analysis

- Automatic crash detection and deduplication
- Crash triaging with severity/exploitability scoring
- Test case minimization (delta debugging)
- Stability tracking for non-deterministic behavior

### Integration

- CLI with 10+ subcommands
- Python API for custom workflows
- Docker targets (DCMTK, Orthanc)
- CI/CD pipeline ready

## CLI Reference

```bash
dicom-fuzzer --help              # Main help
dicom-fuzzer fuzz --help         # Fuzzing options
dicom-fuzzer report --help       # Report generation
dicom-fuzzer corpus --help       # Corpus management
dicom-fuzzer tls --help          # TLS/auth testing
dicom-fuzzer differential --help # Cross-parser testing
```

See [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for full command documentation.

## Python API

```python
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
import pydicom

session = FuzzingSession(output_dir="./artifacts/output")
mutator = DicomMutator()
dataset = pydicom.dcmread("input.dcm")

for i in range(100):
    fuzzed = mutator.mutate(dataset)
    fuzzed.save_as(f"artifacts/output/fuzz_{i:04d}.dcm")

session.save_report()
```

## Project Structure

```text
dicom-fuzzer/
├── dicom_fuzzer/    # Main package
├── tests/           # Test suite (2000+ tests)
├── tools/           # Scripts, examples, generators
├── configs/         # Docker, targets, seeds
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
