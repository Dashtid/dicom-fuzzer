# Quick Start

## Prerequisites

- Python 3.11+
- Git

## Installation

```bash
# Using uv (recommended)
git clone https://github.com/Dashtid/DICOM-Fuzzer.git
cd DICOM-Fuzzer
uv sync --all-extras

# Using pip
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Optional Dependencies

Core fuzzing works out of the box. For target testing and reporting,
install the optional packages:

```bash
pip install psutil minidump tqdm rich matplotlib jinja2 pywinauto
```

| Package    | Required for                        |
| ---------- | ----------------------------------- |
| psutil     | `--gui-mode`, resource monitoring   |
| minidump   | Windows crash dump analysis         |
| tqdm       | Progress bars                       |
| rich       | Rich console output                 |
| matplotlib | Chart generation in reports         |
| jinja2     | Enhanced HTML reports               |
| pywinauto  | `--response-aware` dialog detection |

Missing packages are reported at startup during pre-flight checks.

## Basic Usage

```bash
# Fuzz a single file (100 variants)
dicom-fuzzer input.dcm -o ./output

# Fuzz with specific count
dicom-fuzzer input.dcm -c 50 -o ./output

# Fuzz a directory
dicom-fuzzer ./dicom_folder/ -r -o ./output
```

## Test Against a Target

```bash
# CLI application
dicom-fuzzer input.dcm -t /path/to/viewer --timeout 5

# GUI application (DICOM viewer)
dicom-fuzzer input.dcm -t ./viewer.exe --gui-mode --timeout 10
```

## CVE Replication

Generate deterministic files that replicate known DICOM CVEs (not fuzzing).

```bash
# List available CVEs
dicom-fuzzer cve --list

# Generate all CVE files
dicom-fuzzer cve --all -t template.dcm -o ./cve_output

# Generate specific CVE
dicom-fuzzer cve --cve CVE-2025-5943 -t template.dcm -o ./output

# Generate and test against a target viewer
dicom-fuzzer cve --all -t template.dcm --target ./viewer.exe
```

## List Sample Sources

```bash
dicom-fuzzer samples --list-sources
```

## Strategies

| CLI Flag    | Fuzzers Applied                    |
| ----------- | ---------------------------------- |
| `metadata`  | MetadataFuzzer, EncodingFuzzer     |
| `pixel`     | PixelFuzzer, CompressedPixelFuzzer |
| `header`    | HeaderFuzzer, PrivateTagFuzzer     |
| `structure` | StructureFuzzer, SequenceFuzzer    |

Combine: `-s metadata,pixel,header` (default: all)

## Next Steps

- [CLI_REFERENCE.md](CLI_REFERENCE.md) - Full command reference
- [CVE_REFERENCE.md](CVE_REFERENCE.md) - CVE details
- [ARCHITECTURE.md](ARCHITECTURE.md) - System internals
