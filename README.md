# DICOM Fuzzer

A security testing tool for fuzzing DICOM medical imaging implementations.

[![CI/CD](https://github.com/Dashtid/dicom-fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/dicom-fuzzer/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/dicom-fuzzer)](https://pypi.org/project/dicom-fuzzer/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/dicom-fuzzer)](https://pypi.org/project/dicom-fuzzer/)

## Overview

DICOM Fuzzer identifies vulnerabilities in medical imaging systems, PACS servers, and medical device software through mutation-based fuzzing.

**Features:**

- Mutation-based fuzzing of DICOM metadata, headers, and pixel data
- Directory input with recursive scanning for batch fuzzing
- Synthetic DICOM generation (no PHI concerns)
- GUI application testing mode for DICOM viewers
- Coverage-guided fuzzing with code coverage tracking
- Crash intelligence with automated triage, minimization, and stability tracking
- 3D series fuzzing for CT/MRI multi-slice data
- Production stability with resource management and error recovery

## Installation

```bash
pip install dicom-fuzzer
```

Or from source:

```bash
git clone https://github.com/Dashtid/dicom-fuzzer.git
cd dicom-fuzzer
pip install -e .
```

## Quick Start

### Command Line

```bash
# Generate 100 fuzzed files from a single DICOM
dicom-fuzzer input.dcm -c 100 -o ./output

# Fuzz all files in a directory
dicom-fuzzer ./dicom_folder/ -c 10 -o ./output

# Recursive directory scan
dicom-fuzzer ./data/ --recursive -c 5 -o ./output

# Test a DICOM viewer
dicom-fuzzer input.dcm -c 500 -t ./viewer.exe --stop-on-crash

# Test GUI applications (viewers that don't exit)
dicom-fuzzer input.dcm -c 20 -t ./Affinity.exe --gui-mode --timeout 5
```

### Generate Synthetic Test Data

```bash
# Generate 10 synthetic CT images (no PHI)
dicom-fuzzer samples --generate -c 10 -m CT -o ./samples

# Generate a series of 20 MR slices
dicom-fuzzer samples --generate --series -c 20 -m MR -o ./samples

# List public DICOM sample sources
dicom-fuzzer samples --list-sources
```

### Python API

```python
from dicom_fuzzer.core.mutator import DicomMutator
import pydicom

dataset = pydicom.dcmread("sample.dcm")
mutator = DicomMutator()

for i in range(100):
    fuzzed = mutator.apply_mutations(dataset, num_mutations=5)
    fuzzed.save_as(f"output/fuzzed_{i:04d}.dcm")
```

## Documentation

- [Quick Start Guide](docs/QUICKSTART.md)
- [Examples](docs/EXAMPLES.md)
- [Fuzzing Guide](docs/FUZZING_GUIDE.md)
- [Crash Intelligence](docs/CRASH_INTELLIGENCE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)

## Safety

This tool is for authorized security testing only.

- Only test systems you own or have permission to test
- Use anonymized or synthetic test data
- Comply with HIPAA, GDPR, and applicable regulations
- See [SECURITY.md](SECURITY.md) for vulnerability reporting

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## License

MIT License - see [LICENSE](LICENSE).
