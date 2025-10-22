# Production Fuzzing Examples

This directory contains production-ready fuzzing examples for real DICOM applications.

## Available Examples

### `fuzz_dcmtk.py` - DCMTK dcmdump Parser Fuzzing

Complete end-to-end fuzzing workflow for the DCMTK dcmdump DICOM file parser.

**Quick Start:**
```bash
# Generate seeds and run 100 test cases
python examples/production_fuzzing/fuzz_dcmtk.py --quick-start

# Custom seed corpus with 1000 iterations
python examples/production_fuzzing/fuzz_dcmtk.py --seeds ./my_seeds --iterations 1000

# Docker mode (isolated, instrumented with ASAN)
python examples/production_fuzzing/fuzz_dcmtk.py --docker --iterations 500
```

**What it does:**
1. Downloads/loads seed DICOM files
2. Generates fuzzed files with intelligent mutations
3. Executes dcmdump against each fuzzed file
4. Detects crashes, hangs, and errors
5. Saves crash samples for analysis
6. Generates comprehensive HTML and JSON reports

**Output:**
- `fuzzing_output/fuzzed/` - Generated test cases
- `fuzzing_output/crashes/` - Crash-inducing files
- `fuzzing_output/reports/` - HTML/JSON reports

---

## Prerequisites

### Option 1: Local Installation

Install DCMTK on your system:

**Ubuntu/Debian:**
```bash
sudo apt-get install dcmtk
dcmdump --version
```

**macOS:**
```bash
brew install dcmtk
dcmdump --version
```

**Windows:**
Download from https://dicom.offis.de/dcmtk.php.en

### Option 2: Docker (Recommended)

Build the DCMTK Docker image:

```bash
# From project root
docker-compose build dcmtk

# Or build manually
docker build -t dicom-fuzzer/dcmtk -f docker/dcmtk/Dockerfile .
```

Then use `--docker` flag with fuzzing scripts.

---

## Seed Corpus Preparation

### Quick Start: Generated Seeds

```bash
python scripts/download_public_seeds.py --source generated --count 50 --output ./seeds
```

### Recommended: Real DICOM Files

For best results, use real DICOM files from your target environment:

```bash
# Import real DICOM files
python scripts/import_seed_corpus.py /path/to/dicom/files --output ./seeds

# Strip PixelData to focus on parser (recommended)
python scripts/import_seed_corpus.py /path/to/dicom/files --strip-pixels --output ./seeds
```

Public DICOM sources:
- **pydicom test data**: Included with pydicom library
- **The Cancer Imaging Archive (TCIA)**: https://www.cancerimagingarchive.net/
- **dicomlibrary.com**: Public DICOM samples

---

## Fuzzing Workflows

### 1. Quick Smoke Test (5 minutes)

Test if fuzzing setup works:

```bash
python examples/production_fuzzing/fuzz_dcmtk.py --quick-start --iterations 50
```

### 2. Short Campaign (1 hour)

Find shallow bugs with moderate fuzzing:

```bash
# Download seeds
python scripts/download_public_seeds.py --source all --output ./seeds

# Fuzz with 1000 iterations
python examples/production_fuzzing/fuzz_dcmtk.py --seeds ./seeds --iterations 1000
```

### 3. Deep Campaign (overnight)

Thorough fuzzing to find edge cases:

```bash
# Use real DICOM files
python scripts/import_seed_corpus.py /path/to/medical/images --strip-pixels --output ./corpus

# Run 10,000 iterations
python examples/production_fuzzing/fuzz_dcmtk.py --seeds ./corpus --iterations 10000
```

### 4. Docker-Isolated Fuzzing (recommended for production)

Run with AddressSanitizer instrumentation:

```bash
# Build Docker image with ASAN
docker-compose build dcmtk

# Fuzz in isolated container
python examples/production_fuzzing/fuzz_dcmtk.py --docker --seeds ./seeds --iterations 5000
```

---

## Interpreting Results

### Crash Severity

Crashes are automatically analyzed and classified:

- [OK] **Exit code 0**: File parsed successfully
- [CRASH] **Negative exit codes**: Segmentation fault, assertion failure
- [HANG] **Timeout**: Parser hung (potential infinite loop)
- [ERROR] **Non-zero exit**: Parse error (may or may not be a bug)

### Report Files

After fuzzing, check:

1. **HTML Report**: `fuzzing_output/reports/fuzzing_report_*.html`
   - Interactive crash browser
   - Mutation traceability
   - Session timeline

2. **JSON Report**: `fuzzing_output/reports/fuzzing_report_*.json`
   - Machine-readable results
   - Import into spreadsheet/database

3. **Crash Samples**: `fuzzing_output/crashes/crash_*.dcm`
   - Minimal test cases that trigger crashes
   - Use for bug reproduction

### Crash Triage

Analyze crashes to determine severity:

```bash
# Reproduce crash manually
dcmdump fuzzing_output/crashes/crash_0001.dcm

# Examine with debugger (if DCMTK built with debug symbols)
gdb --args dcmdump fuzzing_output/crashes/crash_0001.dcm
```

---

## Advanced Usage

### Custom Mutation Strategies

Edit `fuzz_dcmtk.py` to customize fuzzing behavior:

```python
# Focus on specific mutation strategies
mutated = self.mutator.apply_mutations(
    dataset,
    strategies=["metadata", "header"],  # Skip pixel and structure
    num_mutations=5,
    severity=MutationSeverity.HIGH
)
```

### Stop on First Crash

Useful for debugging:

```bash
python examples/production_fuzzing/fuzz_dcmtk.py --seeds ./seeds --stop-on-crash
```

### Parallel Fuzzing

Run multiple fuzzing instances in parallel:

```bash
# Terminal 1
python examples/production_fuzzing/fuzz_dcmtk.py --output ./fuzz_run_1 --iterations 5000

# Terminal 2
python examples/production_fuzzing/fuzz_dcmtk.py --output ./fuzz_run_2 --iterations 5000

# Terminal 3
python examples/production_fuzzing/fuzz_dcmtk.py --output ./fuzz_run_3 --iterations 5000
```

---

## Fuzzing Other Targets

### Template for Custom Targets

Copy `fuzz_dcmtk.py` and modify:

1. Change `TargetConfig`:
   ```python
   TargetConfig(
       name="my_dicom_viewer",
       executable="/path/to/viewer",
       args=["--load", "{input_file}"],
       timeout=30.0
   )
   ```

2. Adjust crash detection patterns
3. Customize mutation strategies
4. Update report names

See [docs/TARGET_INTEGRATION.md](../../docs/TARGET_INTEGRATION.md) for details.

---

## Troubleshooting

### Issue: "dcmdump: command not found"

**Solution**: Install DCMTK or use `--docker` flag

### Issue: "No crashes found after 1000 iterations"

**Possible causes:**
- Target is robust (good!)
- Need more diverse seed corpus
- Need more aggressive mutations
- Try higher severity: `MutationSeverity.HIGH`

### Issue: "All tests timeout"

**Possible causes:**
- Timeout too short (increase in `TargetConfig`)
- Target stuck in infinite loop on all inputs
- System resource constraints

### Issue: "Docker image build fails"

**Solution**:
```bash
# Check Docker is running
docker ps

# Rebuild with verbose output
docker build --progress=plain -t dicom-fuzzer/dcmtk -f docker/dcmtk/Dockerfile .
```

---

## Contributing

Found a bug with DCMTK fuzzing? Improved the fuzzing workflow? Submit a PR!

1. Document your changes
2. Update this README if workflow changes
3. Include example command for others to reproduce

---

## References

- **DCMTK**: https://dicom.offis.de/dcmtk.php.en
- **Fuzzing Best Practices**: https://google.github.io/clusterfuzz/
- **DICOM Standard**: https://www.dicomstandard.org/
