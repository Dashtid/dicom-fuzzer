# DICOM Fuzzer Quick Start Guide

Get started with DICOM Fuzzer in under 5 minutes.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Your First Fuzzing Campaign](#your-first-fuzzing-campaign)
- [Common Fuzzing Workflows](#common-fuzzing-workflows)
- [Understanding Fuzzing Strategies](#understanding-fuzzing-strategies)
- [Quick Tips](#quick-tips)
- [What's Next?](#whats-next)
- [Getting Test Data](#getting-test-data)
- [Troubleshooting](#troubleshooting)
- [Need Help?](#need-help)

## Prerequisites

- **Python**: 3.11, 3.12, or 3.13
- **Git**: For cloning the repository
- **DICOM Files**: Sample DICOM files for testing (see [Getting Test Data](#getting-test-data))

## Installation

### Option 1: Using uv (Recommended - Fastest)

```bash
# Install uv package manager
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/Dashtid/DICOM-Fuzzer.git
cd DICOM-Fuzzer

# Install dependencies (creates virtual environment automatically)
uv sync --all-extras
```

### Option 2: Using pip (Traditional)

```bash
# Clone the repository
git clone https://github.com/Dashtid/DICOM-Fuzzer.git
cd DICOM-Fuzzer

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev,docs,network]"
```

## Your First Fuzzing Campaign

### Step 1: Get Sample DICOM Files

```bash
# Create directories
mkdir -p samples/input samples/output

# Option A: Use your own DICOM files
cp /path/to/your/dicom/files/*.dcm samples/input/

# Option B: Download sample DICOM files (examples)
# From: https://www.rubomedical.com/dicom_files/
# Or: https://github.com/pydicom/pydicom/tree/main/tests/test_files
```

### Step 2: Run Basic Fuzzing

```bash
# Using uv
uv run python -m dicom_fuzzer.cli \
    --input samples/input/sample.dcm \
    --output samples/output/ \
    --count 10 \
    --strategies metadata,pixel

# Using activated virtual environment
python -m dicom_fuzzer.cli \
    --input samples/input/sample.dcm \
    --output samples/output/ \
    --count 10 \
    --strategies metadata,pixel
```

**What this does**:

- Reads `sample.dcm` from `samples/input/`
- Generates 10 fuzzed variants
- Applies metadata and pixel data mutations
- Saves results to `samples/output/`

### Step 3: View Results

```bash
# List generated files
ls -lh samples/output/

# Expected output:
# fuzzed_0a1b2c3d.dcm
# fuzzed_4e5f6a7b.dcm
# fuzzed_8c9d0e1f.dcm
# ... (10 files total)

# Check fuzzing session report
cat samples/output/session_report.json
```

## Common Fuzzing Workflows

### Workflow 1: Test DICOM Viewer with Fuzzed Files

```bash
# 1. Generate 50 fuzzed files with all strategies
uv run python -m dicom_fuzzer.cli \
    --input samples/input/ct_scan.dcm \
    --output samples/viewer_test/ \
    --count 50 \
    --strategies metadata,header,pixel,structure

# 2. Test your DICOM viewer
# Open fuzzed files in your viewer application
# Monitor for crashes, hangs, or rendering issues
```

### Workflow 2: Fuzz 3D DICOM Series

```bash
# 1. Prepare multi-slice series (e.g., CT or MRI)
mkdir -p samples/series/input samples/series/output

# 2. Run 3D series fuzzing
uv run python examples/demo_3d_series.py \
    --input-dir samples/series/input/ \
    --output-dir samples/series/output/ \
    --num-mutations 20

# 3. Validate series integrity
uv run python -m dicom_fuzzer.series.validator \
    --input samples/series/output/
```

### Workflow 3: Coverage-Guided Fuzzing (Advanced)

```bash
# 1. Run with coverage tracking
uv run python -m dicom_fuzzer.core.coverage_fuzzer \
    --corpus samples/corpus/ \
    --output samples/coverage_output/ \
    --duration 3600 \
    --target-binary /path/to/dicom_viewer

# 2. View coverage report
open samples/coverage_output/coverage_report.html
```

## Understanding Fuzzing Strategies

DICOM Fuzzer includes multiple mutation strategies:

| Strategy            | What It Does                        | Example Use Case                      |
| ------------------- | ----------------------------------- | ------------------------------------- |
| **metadata**        | Mutates patient info, study details | Test PHI handling, patient matching   |
| **pixel**           | Corrupts pixel data                 | Test image rendering, memory handling |
| **header**          | Mutates DICOM tags                  | Test tag parsing, buffer overflows    |
| **structure**       | Modifies file structure             | Test format validation                |
| **transfer_syntax** | Changes encoding                    | Test decompression, codec handling    |
| **sequence**        | Fuzzes sequence elements            | Test nested data handling             |

**Combine strategies** for comprehensive testing:

```bash
--strategies metadata,pixel,header,structure
```

## Quick Tips

### Start Small

Begin with 10-20 fuzzed files to understand the output before scaling up.

### Use Appropriate Strategies

- **PACS testing**: Focus on `metadata` and `header`
- **Viewer testing**: Use `pixel` and `structure`
- **Network testing**: Use `transfer_syntax` and `sequence`

### Monitor Target Application

Watch for:

- **Crashes**: Segmentation faults, access violations
- **Hangs**: Infinite loops, deadlocks
- **Memory leaks**: Increasing memory usage
- **Unexpected behavior**: Incorrect rendering, data corruption

### Save Crash-Inducing Files

When you find a file that crashes the target:

```bash
# Copy to crash collection
cp samples/output/fuzzed_abc123.dcm crash_samples/

# Minimize the test case
uv run python -m dicom_fuzzer.core.mutation_minimization \
    --input crash_samples/fuzzed_abc123.dcm \
    --output crash_samples/minimized_abc123.dcm
```

## What's Next?

Now that you've run your first fuzzing campaign, explore these resources:

1. **[FUZZING_GUIDE.md](FUZZING_GUIDE.md)** - Comprehensive fuzzing methodology
2. **[EXAMPLES.md](EXAMPLES.md)** - Practical examples and use cases
3. **[CRASH_INTELLIGENCE.md](CRASH_INTELLIGENCE.md)** - Crash analysis and triaging
4. **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and internals
5. **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contribute to the project

## Getting Test Data

### Public DICOM Sample Sources

1. **PyDICOM Test Files**

   ```bash
   git clone https://github.com/pydicom/pydicom.git
   cp pydicom/tests/test_files/*.dcm samples/input/
   ```

2. **DICOM Sample Library**
   - https://www.rubomedical.com/dicom_files/
   - https://barre.dev/medical/samples/

3. **Generate Synthetic DICOM**
   ```bash
   uv run python -m dicom_fuzzer.utils.dicom_generator \
       --output samples/synthetic/ \
       --count 10 \
       --modality CT
   ```

## Troubleshooting

### Issue: "Module not found" errors

**Solution**:

```bash
# Ensure virtual environment is activated
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

# Or use uv run prefix
uv run python -m dicom_fuzzer.cli --help
```

### Issue: "No DICOM files found"

**Solution**:

```bash
# Verify files are valid DICOM
file samples/input/*.dcm

# Should output: "DICOM medical imaging data"
```

### Issue: Out of memory errors

**Solution**:

```bash
# Reduce batch size
--count 10  # Instead of 1000

# Process files individually
for file in samples/input/*.dcm; do
    uv run python -m dicom_fuzzer.cli \
        --input "$file" \
        --output samples/output/ \
        --count 5
done
```

### Issue: Permission denied on output directory

**Solution**:

```bash
# Create output directory with proper permissions
mkdir -p samples/output
chmod 755 samples/output
```

## Need Help?

- **Documentation**: [docs/README.md](README.md)
- **Issues**: https://github.com/Dashtid/DICOM-Fuzzer/issues
- **Security**: [SECURITY.md](../SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](../CONTRIBUTING.md)

---

Start with the basic workflow above and experiment with different strategies and parameters.
