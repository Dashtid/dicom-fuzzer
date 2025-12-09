# DICOM Fuzzer

A security testing tool for fuzzing DICOM medical imaging implementations.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/dicom-fuzzer)](https://pypi.org/project/dicom-fuzzer/)

## Overview

DICOM Fuzzer identifies vulnerabilities in medical imaging systems, PACS servers, and medical device software through mutation-based fuzzing.

**Features:**

- Mutation-based fuzzing of DICOM metadata, headers, and pixel data
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
# Generate 100 fuzzed files
dicom-fuzzer input.dcm -c 100 -o ./output

# Test a DICOM viewer
dicom-fuzzer input.dcm -c 500 -t ./viewer.exe --stop-on-crash
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
