# DICOM Fuzzer Troubleshooting Guide

Comprehensive troubleshooting guide for common issues encountered when using DICOM-Fuzzer.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [File Generation Problems](#file-generation-problems)
3. [Target Testing Issues](#target-testing-issues)
4. [Resource Limit Problems](#resource-limit-problems)
5. [Performance Issues](#performance-issues)
6. [Platform-Specific Issues](#platform-specific-issues)
7. [Error Codes Reference](#error-codes-reference)
8. [Getting Help](#getting-help)

---

## Installation Issues

### ModuleNotFoundError: No module named 'pydicom'

**Problem**: Missing required dependencies.

**Solution**:

```bash
# Install all dependencies
pip install -r requirements.txt

# Or install directly
pip install pydicom pytest hypothesis psutil tqdm
```

### Python Version Too Old

**Problem**: `Python 3.11+ required, found 3.10`.

**Solution**:

```bash
# Check your Python version
python --version

# Install Python 3.11 or later
# Download from https://www.python.org/downloads/

# Or use pyenv (Unix/Linux/macOS)
pyenv install 3.11
pyenv local 3.11
```

### Permission Denied During Installation

**Problem**: Cannot install packages due to permissions.

**Solution**:

```bash
# Option 1: Use virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Unix/Linux/macOS
# or
venv\Scripts\activate  # Windows

pip install -r requirements.txt

# Option 2: Install with --user flag
pip install --user -r requirements.txt
```

---

## File Generation Problems

### No Files Generated

**Problem**: `generator.generate_batch()` returns empty list.

**Diagnosis**:

```python
from dicom_fuzzer.core.generator import DICOMGenerator

generator = DICOMGenerator(output_dir="./test_output")
files = generator.generate_batch("input.dcm", count=10)

print(f"Generated: {len(files)} files")
print(f"Skipped: {generator.stats.skipped_due_to_write_errors}")
```

**Common Causes**:

1. **Output directory not writable** - Check permissions
2. **Disk full** - Check available disk space
3. **Invalid input file** - Verify DICOM file is valid

**Solutions**:

```bash
# Check disk space
df -h .  # Unix/Linux/macOS
dir  # Windows

# Check write permissions
ls -ld output_directory  # Unix/Linux/macOS
icacls output_directory  # Windows

# Validate input DICOM
python -c "import pydicom; pydicom.dcmread('input.dcm')"
```

### Files Generated But Corrupted

**Problem**: Generated files cannot be read by DICOM tools.

**Diagnosis**:

```python
from dicom_fuzzer.core.validator import DicomValidator
from dicom_fuzzer.core.parser import DicomParser

validator = DicomValidator()
result, dataset = validator.validate_file("generated.dcm")

if not result.is_valid:
    print("Errors:", result.errors)
    print("Warnings:", result.warnings)
```

**Solutions**:

- Use less aggressive mutation strategies
- Enable validation after generation
- Check for file write errors in logs

### "Input file is empty" Error

**Problem**: Input DICOM file validation fails.

**Solution**:

```bash
# Check file size
ls -lh input.dcm  # Unix/Linux/macOS
dir input.dcm  # Windows

# Verify it's a valid DICOM file
python -c "import pydicom; ds = pydicom.dcmread('input.dcm', force=True); print(ds)"
```

---

## Target Testing Issues

### "Target executable not found"

**Problem**: Cannot find specified target application.

**Solution**:

```bash
# Verify path exists
ls /path/to/target.exe  # Unix/Linux/macOS
dir C:\path\to\target.exe  # Windows

# Use absolute path
dicom-fuzzer input.dcm -t /absolute/path/to/target.exe

# Check executable permissions (Unix/Linux/macOS)
chmod +x /path/to/target.exe
```

### All Tests Hang/Timeout

**Problem**: Every test case times out.

**Diagnosis**:

- Target application may require GUI (and server has no display)
- Target waiting for user input
- Target application crashed but not returning

**Solutions**:

```bash
# Test target manually first
./target.exe test.dcm

# Increase timeout
dicom-fuzzer input.dcm -t target.exe --timeout 30

# Use headless mode if target supports it
./target.exe --headless test.dcm
```

### Circuit Breaker Opens Too Quickly

**Problem**: "Test skipped - circuit breaker open" after only a few failures.

**Solution**:

```python
# Adjust circuit breaker threshold in code
runner = TargetRunner(target_executable="./app")
runner.circuit_breaker.failure_threshold = 10  # Default is 5

# Or disable circuit breaker
runner = TargetRunner(
    target_executable="./app",
    enable_circuit_breaker=False
)
```

### No Crashes Detected Despite Known Bugs

**Problem**: Expected crashes not being detected.

**Diagnosis**:

```python
# Enable verbose logging
logging.basicConfig(level=logging.DEBUG)

# Check exit codes manually
result = runner.execute_test("test.dcm")
print(f"Status: {result.result}")
print(f"Exit code: {result.exit_code}")
print(f"Stderr: {result.stderr}")
```

**Solutions**:

- Increase test file count (more mutations = better coverage)
- Use different mutation strategies
- Verify target actually processes the file
- Check if target is catching exceptions internally

---

## Resource Limit Problems

### "Resource limit exceeded" on Windows

**Problem**: Resource limits not enforced or warnings displayed.

**Explanation**: Memory and CPU limits only work on Unix/Linux/macOS. Windows only supports disk space checking.

**Solution**:

```bash
# On Windows, resource limits are informational only
# Use Windows Resource Manager for system-level limits

# Or run in WSL2 for full support
wsl
cd /mnt/c/path/to/project
python main.py ...
```

### Memory Errors During Generation

**Problem**: `MemoryError` or `Out of memory` during fuzzing.

**Solution**:

```python
from dicom_fuzzer.core.resource_manager import ResourceLimits, ResourceManager

# Set lower memory limits
limits = ResourceLimits(
    max_memory_mb=512,  # 512MB instead of 1GB
    max_memory_mb_hard=1024
)

manager = ResourceManager(limits)

with manager.limited_execution():
    # Your fuzzing code here
    pass
```

**Or use CLI**:

```bash
dicom-fuzzer input.dcm --max-memory 512 --max-memory-hard 1024
```

### Disk Space Warnings

**Problem**: "Insufficient disk space" warnings during pre-flight check.

**Solution**:

```bash
# Free up disk space
rm -rf old_fuzzed_files/
rm -rf artifacts/old_campaigns/

# Or use external storage
dicom-fuzzer input.dcm -o /mnt/external/fuzzed_files/

# Adjust minimum disk space requirement
dicom-fuzzer input.dcm --min-disk-space 500  # Require only 500MB
```

---

## Performance Issues

### Extremely Slow File Generation

**Problem**: Generating 1000 files takes hours instead of minutes.

**Diagnosis**:

```python
import time
from dicom_fuzzer.core.generator import DICOMGenerator

generator = DICOMGenerator(output_dir="./test")

start = time.time()
files = generator.generate_batch("input.dcm", count=100)
elapsed = time.time() - start

print(f"Generated {len(files)} files in {elapsed:.2f}s")
print(f"Rate: {len(files)/elapsed:.1f} files/sec")
```

**Expected Performance**:

- Simple mutations: 50-100 files/sec
- Complex mutations: 10-50 files/sec
- With validation: 5-20 files/sec

**Solutions**:

```python
# Disable unnecessary features
generator = DICOMGenerator(
    output_dir="./output",
    skip_write_errors=True,  # Don't retry failed writes
)

# Use faster strategies
files = generator.generate_batch(
    "input.dcm",
    count=1000,
    strategies=["metadata"]  # Fastest strategy
)

# Generate in parallel (advanced)
from concurrent.futures import ProcessPoolExecutor
# ... implement parallel generation
```

### High Memory Usage

**Problem**: Python process consuming excessive memory.

**Diagnosis**:

```python
import psutil
import os

process = psutil.Process(os.getpid())
memory_mb = process.memory_info().rss / (1024 * 1024)
print(f"Memory usage: {memory_mb:.0f} MB")
```

**Solutions**:

```python
# Generate in smaller batches
generator = DICOMGenerator(output_dir="./output")

all_files = []
batch_size = 100

for i in range(0, 1000, batch_size):
    files = generator.generate_batch("input.dcm", count=batch_size)
    all_files.extend(files)

    # Force garbage collection
    import gc
    gc.collect()
```

---

## Platform-Specific Issues

### Windows: "Access Denied" Errors

**Problem**: Cannot write to output directory.

**Solution**:

```powershell
# Run as administrator
powershell -Command "Start-Process python -ArgumentList 'script.py' -Verb RunAs"

# Or change directory permissions
icacls C:\output /grant Users:F /T

# Use user profile directory instead
dicom-fuzzer input.dcm -o %USERPROFILE%\fuzzed_files
```

### macOS: "Operation not permitted"

**Problem**: macOS security restrictions preventing file access.

**Solution**:

```bash
# Grant Terminal/Python Full Disk Access
# System Preferences > Security & Privacy > Privacy > Full Disk Access
# Add Terminal.app or Python

# Or use accessible directory
dicom-fuzzer input.dcm -o ~/Documents/fuzzed_files/
```

### Linux: "Too many open files"

**Problem**: System file descriptor limit reached.

**Solution**:

```bash
# Check current limit
ulimit -n

# Increase temporarily
ulimit -n 4096

# Increase permanently
echo "* soft nofile 4096" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 10000" | sudo tee -a /etc/security/limits.conf

# Restart session for changes to take effect
```

---

## Error Codes Reference

### Exit Codes

| Code | Meaning              | Action                       |
| ---- | -------------------- | ---------------------------- |
| 0    | Success              | Normal operation             |
| 1    | General error        | Check error message and logs |
| 2    | Command line error   | Review command syntax        |
| 130  | Interrupted (Ctrl+C) | User cancelled operation     |

### Execution Status Codes

| Status             | Meaning             | Typical Cause                  |
| ------------------ | ------------------- | ------------------------------ |
| SUCCESS            | Test passed         | Target processed file normally |
| CRASH              | Application crashed | Segfault, assertion failure    |
| HANG               | Test timed out      | Infinite loop, deadlock        |
| ERROR              | Generic error       | Non-zero exit code             |
| OOM                | Out of memory       | Memory exhaustion              |
| RESOURCE_EXHAUSTED | Resource limit hit  | CPU/memory/disk limit exceeded |
| SKIPPED            | Test not run        | Circuit breaker open           |

### Common Log Messages

**"No file meta information present"**

- **Severity**: Warning
- **Meaning**: DICOM file missing standard metadata
- **Action**: Often harmless for fuzzing, can ignore

**"Resource limit exceeded"**

- **Severity**: Error
- **Meaning**: Operation exceeded configured limits
- **Action**: Increase limits or reduce workload

**"Circuit breaker open"**

- **Severity**: Info
- **Meaning**: Too many consecutive failures, stopping tests
- **Action**: Fix target application or adjust threshold

---

## Getting Help

### Enable Debug Logging

```python
import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

Or via CLI:

```bash
dicom-fuzzer input.dcm -v  # Verbose mode
```

### Collect System Information

```python
import sys
import platform
import pydicom
from dicom_fuzzer import __version__

print(f"DICOM-Fuzzer: {__version__}")
print(f"Python: {sys.version}")
print(f"Platform: {platform.platform()}")
print(f"pydicom: {pydicom.__version__}")
```

### Check Test Coverage

```bash
pytest --cov=dicom_fuzzer --cov-report=html
# Open htmlcov/index.html to see coverage report
```

### Run Stress Tests

```bash
# Run stress tests to verify stability
pytest tests/test_stress.py -v

# Run error scenario tests
pytest tests/test_error_scenarios.py -v
```

### Report Issues

When reporting issues, include:

1. **DICOM-Fuzzer version**: `python -c "from dicom_fuzzer import __version__; print(__version__)"`
2. **Python version**: `python --version`
3. **Operating system**: `uname -a` (Unix) or `ver` (Windows)
4. **Full error message** with traceback
5. **Minimal reproducible example**
6. **Relevant log output** (with `-v` flag)

**Where to Report**:

- GitHub Issues: https://github.com/yourusername/DICOM-Fuzzer/issues
- Documentation: See `docs/` directory for guides

---

## Quick Troubleshooting Checklist

Before reporting issues, verify:

- [ ] Using Python 3.11 or later
- [ ] All dependencies installed (`pip list | grep -E 'pydicom|pytest|hypothesis'`)
- [ ] Input DICOM file is valid (`pydicom.dcmread()` succeeds)
- [ ] Sufficient disk space (>1GB free)
- [ ] Output directory is writable
- [ ] Target executable exists and is executable
- [ ] Tried with verbose logging (`-v` flag)
- [ ] Reviewed relevant sections above

---

## Advanced Debugging

### Profile Performance

```python
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()

# Your fuzzing code here
generator.generate_batch("input.dcm", count=1000)

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)  # Top 20 slowest functions
```

### Memory Profiling

```python
from memory_profiler import profile

@profile
def generate_files():
    generator = DICOMGenerator(output_dir="./test")
    return generator.generate_batch("input.dcm", count=1000)

generate_files()
```

### Test Individual Components

```python
# Test parser
from dicom_fuzzer.core.parser import DicomParser
parser = DicomParser("input.dcm")
print(parser.dataset)

# Test mutator
from dicom_fuzzer.core.mutator import DicomMutator
mutator = DicomMutator()
mutated = mutator.mutate(parser.dataset)

# Test validator
from dicom_fuzzer.core.validator import DicomValidator
validator = DicomValidator()
result = validator.validate(mutated)
print(result)
```

---

**Document Version**: 1.0
**Last Updated**: January 2025
**Maintainers**: DICOM-Fuzzer Development Team
