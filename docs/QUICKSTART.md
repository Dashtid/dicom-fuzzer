# Quick Start Guide

Get fuzzing in under 5 minutes.

## Prerequisites

- Python 3.11+
- Git
- DICOM files for testing

## Installation

### Using uv (Recommended)

```bash
# Install uv
# Windows: powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
# Linux/macOS: curl -LsSf https://astral.sh/uv/install.sh | sh

git clone https://github.com/Dashtid/DICOM-Fuzzer.git
cd DICOM-Fuzzer
uv sync --all-extras
```

### Using pip

```bash
git clone https://github.com/Dashtid/DICOM-Fuzzer.git
cd DICOM-Fuzzer
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev,docs,network]"
```

## First Fuzzing Campaign

```bash
# Prepare directories
mkdir -p artifacts/input artifacts/output

# Copy your DICOM files
cp /path/to/your/*.dcm artifacts/input/

# Run fuzzing (10 variants)
uv run dicom-fuzzer artifacts/input/sample.dcm -c 10 -o artifacts/output

# View results
ls artifacts/output/
cat artifacts/output/session_report.json
```

## Fuzzing Strategies

| Strategy        | Purpose                     |
| --------------- | --------------------------- |
| metadata        | Patient info, study details |
| pixel           | Image data corruption       |
| header          | DICOM tag mutations         |
| structure       | File format validation      |
| transfer_syntax | Encoding/compression        |
| sequence        | Nested element handling     |

Combine strategies: `--strategies metadata,pixel,header`

## Getting Test Data

Use DICOM files matching your target application's expected input.

**Public sources:**

- [TCIA](https://www.cancerimagingarchive.net/) - Cancer imaging archives
- [OsiriX Library](https://www.osirix-viewer.com/resources/dicom-image-library/) - Multi-modality samples
- [pydicom test files](https://github.com/pydicom/pydicom/tree/main/tests/test_files) - Parser edge cases

**Generate synthetic:**

```bash
uv run python -m dicom_fuzzer.utils.dicom_generator -o artifacts/synthetic/ -c 10
```

## Troubleshooting

**Module not found:**

```bash
source .venv/bin/activate  # Activate venv
uv run dicom-fuzzer --help  # Or use uv run prefix
```

**No DICOM files found:**

```bash
file artifacts/input/*.dcm  # Verify files are valid DICOM
```

**Out of memory:**

```bash
--count 10  # Reduce batch size
```

## Next Steps

- [CLI_REFERENCE.md](CLI_REFERENCE.md) - Full command reference
- [ARCHITECTURE.md](ARCHITECTURE.md) - System internals
- [../CONTRIBUTING.md](../CONTRIBUTING.md) - Contribute
