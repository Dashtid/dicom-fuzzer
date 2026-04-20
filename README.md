# DICOM Fuzzer

Mutation-based fuzzer for robustness testing of DICOM medical imaging viewers and parsers. Generates malformed DICOM files and feeds them into target applications to find crashes and vulnerabilities.

[![CI](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Installation

### For end users (run the CLI)

Install from PyPI as an isolated tool so `dicom-fuzzer` is on your PATH everywhere, without polluting your system Python:

```bash
# Recommended: uv (fast, modern)
uv tool install dicom-fuzzer

# Alternative: pipx (same idea, different manager)
pipx install dicom-fuzzer

# Alternative: pip into the active environment
pip install dicom-fuzzer
```

After installation:

```bash
dicom-fuzzer --help
```

Optional extras are needed only for specific features (target process monitoring, Windows crash dump parsing, HTML reports, GUI automation):

```bash
uv tool install "dicom-fuzzer[all]"
# or, if you only need specific extras:
pip install dicom-fuzzer psutil minidump tqdm rich matplotlib jinja2 pywinauto
```

### For contributors (develop the code)

```bash
git clone https://github.com/Dashtid/DICOM-Fuzzer.git
cd DICOM-Fuzzer
uv sync
source .venv/Scripts/activate  # Windows/Git Bash
# source .venv/bin/activate    # macOS/Linux
```

To run your local checkout as a global CLI while developing:

```bash
uv tool install --editable .
```

Source edits take effect immediately with no reinstall.

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

- **Format fuzzing (production):** 24 single-file mutation strategies targeting VR types, pixel data, sequences, encoding, and modality-specific tags
- Modality-specific fuzzers: CT/MR calibration, NM, PET, RT Dose, RT Structure Set, Segmentation, Secondary Capture, Encapsulated PDF, Pixel Reencoding
- Target scope filtering (`--target-type viewer|web|pacs`)
- Multiframe fuzzing (WIP): 10 strategies for enhanced imaging objects -- functional groups, frame counts, dimension indices
- Series/study fuzzing (WIP): cross-series geometry, temporal ordering, patient consistency
- Network protocol fuzzing (WIP): PDU construction, DIMSE commands, state machine, TLS

### Supported SOP classes

Seed corpus plus dedicated fuzzer coverage (mutations are only
meaningful when both exist):

| Modality          | SOP Class UID                 | Modality fuzzer     |
| ----------------- | ----------------------------- | ------------------- |
| CT Image          | 1.2.840.10008.5.1.4.1.1.2     | `calibration`       |
| MR Image          | 1.2.840.10008.5.1.4.1.1.4     | `calibration`       |
| NM Image          | 1.2.840.10008.5.1.4.1.1.20    | `nuclear_medicine`  |
| PET Image         | 1.2.840.10008.5.1.4.1.1.128   | `pet`               |
| RT Dose           | 1.2.840.10008.5.1.4.1.1.481.2 | `rt_dose`           |
| RT Structure Set  | 1.2.840.10008.5.1.4.1.1.481.3 | `rt_structure_set`  |
| Segmentation      | 1.2.840.10008.5.1.4.1.1.66.4  | `segmentation`      |
| Secondary Capture | 1.2.840.10008.5.1.4.1.1.7     | `secondary_capture` |
| Encapsulated PDF  | 1.2.840.10008.5.1.4.1.1.104.1 | `encapsulated_pdf`  |

Generic fuzzers (`structure`, `metadata`, `header`, `preamble`,
`sequence`, `dictionary`, etc.) run across all modalities.

### Analysis

- Automatic crash detection and deduplication
- Crash triaging with severity and exploitability scoring
- Test case minimization
- Corpus management
- Markdown campaign reports with per-strategy hit rates

### Integration

- CLI with 14 subcommands
- Python API for custom workflows
- Docker container for isolated execution
- CI/CD compatible

## CLI Reference

```bash
dicom-fuzzer --help                 # Main fuzzing campaign
dicom-fuzzer target --help          # Target testing
dicom-fuzzer generate-seeds --help  # Seed corpus generation
dicom-fuzzer sanitize --help        # Strip PHI from seed files
dicom-fuzzer replay --help          # Decompose fuzzed files
dicom-fuzzer report --help          # Report generation
dicom-fuzzer triage --help          # Crash triaging
dicom-fuzzer corpus --help          # Corpus management
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
│   ├── cli/         # Command-line interface (14 subcommands)
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
