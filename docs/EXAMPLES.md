# DICOM Fuzzer Examples

Practical examples demonstrating common fuzzing scenarios and use cases.

## Table of Contents

- [Basic Fuzzing Examples](#basic-fuzzing-examples)
- [3D Series Fuzzing](#3d-series-fuzzing)
- [Coverage-Guided Fuzzing](#coverage-guided-fuzzing)
- [Crash Analysis](#crash-analysis)
- [Network Protocol Fuzzing](#network-protocol-fuzzing)
- [Integration with CI/CD](#integration-with-cicd)
- [Custom Mutation Strategies](#custom-mutation-strategies)
- [Performance Testing](#performance-testing)

---

## Basic Fuzzing Examples

### Example 1: Fuzz Single DICOM File

Test a DICOM viewer with metadata mutations:

```python
"""Basic fuzzing example - Single file with metadata mutations."""
from pathlib import Path
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.parser import DicomParser

# Initialize
parser = DicomParser()
mutator = DicomMutator()

# Load DICOM file
input_file = Path("samples/input/ct_scan.dcm")
dataset = parser.parse_file(input_file)

# Apply metadata mutations
mutator.start_session()
mutated_dataset = mutator.mutate(dataset, strategies=["metadata"])

# Save output
output_file = Path("samples/output/fuzzed_ct_scan.dcm")
mutated_dataset.save_as(output_file)
mutator.end_session()

print(f"[+] Fuzzed file saved to: {output_file}")
```

**Expected Output**:

```
[+] Fuzzed file saved to: samples/output/fuzzed_ct_scan.dcm
```

### Example 2: Batch Fuzzing with Multiple Strategies

Generate 100 fuzzed files with combined strategies:

```python
"""Batch fuzzing with multiple mutation strategies."""
from pathlib import Path
from dicom_fuzzer.core.generator import DICOMGenerator
from dicom_fuzzer.core.mutator import DicomMutator

# Setup
input_file = Path("samples/input/mr_brain.dcm")
output_dir = Path("samples/batch_output/")
output_dir.mkdir(parents=True, exist_ok=True)

# Generate fuzzed files
generator = DICOMGenerator(output_dir=output_dir)
mutator = DicomMutator()

strategies = ["metadata", "pixel", "header"]
num_files = 100

generated_files = generator.generate_batch(
    source_file=input_file,
    output_dir=output_dir,
    count=num_files,
    mutator=mutator,
    strategies=strategies
)

print(f"[+] Generated {len(generated_files)} fuzzed files")
print(f"[+] Strategies used: {', '.join(strategies)}")
print(f"[+] Output directory: {output_dir}")
```

**Expected Output**:

```
[+] Generated 100 fuzzed files
[+] Strategies used: metadata, pixel, header
[+] Output directory: samples/batch_output/
```

### Example 3: Fuzzing with Severity Levels

Control mutation severity for gradual testing:

```python
"""Fuzzing with different severity levels."""
from pathlib import Path
from dicom_fuzzer.core.mutator import DicomMutator, MutationSeverity
from dicom_fuzzer.core.parser import DicomParser

parser = DicomParser()
mutator = DicomMutator()
input_file = Path("samples/input/sample.dcm")
dataset = parser.parse_file(input_file)

# Test with increasing severity
severities = [
    MutationSeverity.LOW,      # Minimal changes
    MutationSeverity.MEDIUM,   # Moderate changes
    MutationSeverity.HIGH,     # Significant changes
    MutationSeverity.CRITICAL  # Extreme changes
]

for severity in severities:
    mutator.start_session()
    mutated = mutator.mutate(dataset, severity=severity)

    output_file = Path(f"samples/output/fuzzed_{severity.name.lower()}.dcm")
    mutated.save_as(output_file)
    mutator.end_session()

    print(f"[+] {severity.name} severity: {output_file}")
```

**Expected Output**:

```
[+] LOW severity: samples/output/fuzzed_low.dcm
[+] MEDIUM severity: samples/output/fuzzed_medium.dcm
[+] HIGH severity: samples/output/fuzzed_high.dcm
[+] CRITICAL severity: samples/output/fuzzed_critical.dcm
```

---

## 3D Series Fuzzing

### Example 4: Fuzz Complete CT Series

Test 3D viewer with multi-slice series:

```python
"""Fuzz a complete 3D DICOM series (CT/MRI)."""
from pathlib import Path
from dicom_fuzzer.series.detector import SeriesDetector
from dicom_fuzzer.series.mutator import SeriesMutator
from dicom_fuzzer.series.validator import SeriesValidator

# Initialize components
detector = SeriesDetector()
mutator = SeriesMutator()
validator = SeriesValidator()

# Detect series in directory
input_dir = Path("samples/ct_series/input/")
series_list = detector.detect_series(input_dir)

print(f"[+] Found {len(series_list)} series")

# Fuzz first series
if series_list:
    series = series_list[0]
    print(f"[+] Fuzzing series: {series.series_uid}")
    print(f"[+] Slices: {series.num_instances}")

    # Apply 3D mutations
    output_dir = Path("samples/ct_series/output/")
    fuzzed_series = mutator.fuzz_series(
        series=series,
        output_dir=output_dir,
        strategies=["slice_order", "slice_spacing", "orientation"]
    )

    # Validate output
    validation_result = validator.validate_series(fuzzed_series)

    print(f"[+] Validation: {'PASS' if validation_result.is_valid else 'FAIL'}")
    print(f"[+] Output: {output_dir}")
```

**Expected Output**:

```
[+] Found 1 series
[+] Fuzzing series: 1.2.840.113619.2.55.3.12345.54321
[+] Slices: 120
[+] Validation: PASS
[+] Output: samples/ct_series/output/
```

### Example 5: Test Slice Ordering Attacks

Reorder slices to test viewer robustness:

```python
"""Test DICOM viewer's handling of misordered slices."""
from pathlib import Path
from dicom_fuzzer.series.mutator import SeriesMutator

mutator = SeriesMutator()
input_dir = Path("samples/series/input/")
output_dir = Path("samples/series/misordered/")

# Apply slice order mutations
strategies = [
    "reverse_slices",        # Reverse slice order
    "random_shuffle",        # Random shuffling
    "duplicate_slices",      # Duplicate middle slice
    "skip_slices",          # Skip every other slice
]

for strategy in strategies:
    strategy_output = output_dir / strategy
    strategy_output.mkdir(parents=True, exist_ok=True)

    mutator.fuzz_series_directory(
        input_dir=input_dir,
        output_dir=strategy_output,
        strategies=[strategy]
    )

    print(f"[+] Strategy '{strategy}': {strategy_output}")
```

**Expected Output**:

```
[+] Strategy 'reverse_slices': samples/series/misordered/reverse_slices
[+] Strategy 'random_shuffle': samples/series/misordered/random_shuffle
[+] Strategy 'duplicate_slices': samples/series/misordered/duplicate_slices
[+] Strategy 'skip_slices': samples/series/misordered/skip_slices
```

---

## Coverage-Guided Fuzzing

### Example 6: Coverage-Guided Fuzzing Campaign

Automatically discover new code paths:

```python
"""Coverage-guided fuzzing to maximize code coverage."""
from pathlib import Path
from dicom_fuzzer.core.coverage_fuzzer import CoverageFuzzer
from dicom_fuzzer.core.coverage_tracker import CoverageTracker

# Setup
corpus_dir = Path("samples/corpus/")
output_dir = Path("samples/coverage_output/")
target_binary = Path("/usr/bin/dcmdjpeg")  # Example DCMTK tool

# Initialize fuzzer
fuzzer = CoverageFuzzer(
    corpus_dir=corpus_dir,
    coverage_tracker=CoverageTracker()
)

# Run fuzzing campaign
results = fuzzer.fuzz(
    target_binary=target_binary,
    output_dir=output_dir,
    duration_seconds=3600,  # 1 hour
    max_iterations=10000
)

# Print statistics
print(f"[+] Iterations: {results.iterations}")
print(f"[+] Coverage: {results.coverage_percentage:.2f}%")
print(f"[+] Unique crashes: {results.unique_crashes}")
print(f"[+] New paths found: {results.new_paths}")
```

**Expected Output**:

```
[+] Iterations: 10000
[+] Coverage: 87.34%
[+] Unique crashes: 3
[+] New paths found: 127
```

### Example 7: Corpus Minimization

Reduce corpus size while maintaining coverage:

```python
"""Minimize corpus while preserving code coverage."""
from pathlib import Path
from dicom_fuzzer.core.corpus import Corpus

corpus = Corpus(Path("samples/corpus/"))

# Initial corpus stats
print(f"[+] Initial corpus size: {len(corpus)}")
print(f"[+] Total size: {corpus.total_size_mb:.2f} MB")

# Minimize corpus
minimized = corpus.minimize(
    target_coverage=0.95,  # Maintain 95% coverage
    max_files=100           # Limit to 100 files
)

print(f"[+] Minimized corpus size: {len(minimized)}")
print(f"[+] Size reduction: {corpus.reduction_percentage:.1f}%")
print(f"[+] Coverage retained: {minimized.coverage_percentage:.2f}%")
```

**Expected Output**:

```
[+] Initial corpus size: 450
[+] Total size: 2.34 MB
[+] Minimized corpus size: 98
[+] Size reduction: 78.2%
[+] Coverage retained: 95.12%
```

---

## Crash Analysis

### Example 8: Automatic Crash Triaging

Analyze and deduplicate crashes:

```python
"""Automatically triage and deduplicate crashes."""
from pathlib import Path
from dicom_fuzzer.core.crash_analyzer import CrashAnalyzer
from dicom_fuzzer.core.crash_deduplication import CrashDeduplicator

# Initialize
analyzer = CrashAnalyzer()
deduplicator = CrashDeduplicator()

# Analyze crash directory
crash_dir = Path("samples/crashes/")
crashes = analyzer.analyze_directory(crash_dir)

print(f"[+] Total crashes: {len(crashes)}")

# Deduplicate
unique_crashes = deduplicator.deduplicate(crashes)

print(f"[+] Unique crashes: {len(unique_crashes)}")

# Triage by severity
for crash in unique_crashes:
    print(f"\n[!] Crash: {crash.id}")
    print(f"    Severity: {crash.severity}")
    print(f"    Type: {crash.crash_type}")
    print(f"    File: {crash.trigger_file}")
    print(f"    Stack trace preview:")
    print(f"    {crash.stack_trace[:200]}...")
```

**Expected Output**:

```
[+] Total crashes: 47
[+] Unique crashes: 5

[!] Crash: crash_001
    Severity: CRITICAL
    Type: SEGMENTATION_FAULT
    File: fuzzed_abc123.dcm
    Stack trace preview:
    0x00007fff5fc1d000 libDICOM.so.1.2.3
    0x00007fff5fc1d123 DicomParser::readPixelData()
    ...
```

### Example 9: Mutation Minimization

Minimize crash-inducing test case:

```python
"""Minimize test case that triggers a crash."""
from pathlib import Path
from dicom_fuzzer.core.mutation_minimization import MutationMinimizer

minimizer = MutationMinimizer()

# Original crash file
crash_file = Path("samples/crashes/crash_large.dcm")
output_file = Path("samples/crashes/crash_minimal.dcm")

# Target command that crashes
target_command = ["dcmdjpeg", "{input}", "/dev/null"]

print(f"[+] Original size: {crash_file.stat().st_size} bytes")

# Minimize while preserving crash
minimized = minimizer.minimize(
    input_file=crash_file,
    output_file=output_file,
    target_command=target_command,
    timeout=10
)

print(f"[+] Minimized size: {output_file.stat().st_size} bytes")
print(f"[+] Reduction: {minimized.reduction_percentage:.1f}%")
print(f"[+] Still crashes: {'YES' if minimized.preserves_crash else 'NO'}")
```

**Expected Output**:

```
[+] Original size: 524288 bytes
[+] Minimized size: 2048 bytes
[+] Reduction: 99.6%
[+] Still crashes: YES
```

---

## Network Protocol Fuzzing

### Example 10: DICOM DIMSE Protocol Fuzzing

Fuzz DICOM network operations:

```python
"""Fuzz DICOM network protocol (DIMSE)."""
from dicom_fuzzer.network.dimse_fuzzer import DimseFuzzer
from dicom_fuzzer.network.connection import DicomConnection

# Connect to PACS
connection = DicomConnection(
    host="192.168.1.100",
    port=11112,
    calling_ae="FUZZER",
    called_ae="PACS_SERVER"
)

# Initialize fuzzer
fuzzer = DimseFuzzer(connection)

# Fuzz C-STORE operation
print("[+] Fuzzing C-STORE...")
fuzzer.fuzz_c_store(
    input_file=Path("samples/input/sample.dcm"),
    num_iterations=100,
    strategies=["header", "transfer_syntax"]
)

# Fuzz C-FIND operation
print("[+] Fuzzing C-FIND...")
fuzzer.fuzz_c_find(
    query_level="STUDY",
    num_iterations=50,
    strategies=["query_fuzzing", "tag_manipulation"]
)

print(f"[+] Results saved to: {fuzzer.results_dir}")
```

**Expected Output**:

```
[+] Fuzzing C-STORE...
[+] Fuzzing C-FIND...
[+] Results saved to: fuzzing_results/dimse_2025-10-28_14-32-15
```

---

## Integration with CI/CD

### Example 11: GitHub Actions Integration

Add fuzzing to CI/CD pipeline:

```yaml
# .github/workflows/fuzzing.yml
name: DICOM Fuzzing

on:
  schedule:
    - cron: "0 2 * * *" # Daily at 2 AM
  workflow_dispatch:

jobs:
  fuzz:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: |
          pip install -e ".[dev,network]"

      - name: Run fuzzing campaign
        run: |
          python -m dicom_fuzzer.cli \
            --input samples/input/ \
            --output fuzzing_results/ \
            --count 1000 \
            --strategies metadata,pixel,header \
            --report fuzzing_report.json

      - name: Analyze crashes
        run: |
          python -m dicom_fuzzer.core.crash_analyzer \
            --crashes fuzzing_results/crashes/ \
            --output crash_report.html

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: fuzzing-results
          path: |
            fuzzing_results/
            crash_report.html
```

### Example 12: Docker-Based Fuzzing

Run fuzzing in isolated container:

```dockerfile
# Dockerfile.fuzzing
FROM python:3.11-slim

WORKDIR /fuzzing

# Install DICOM Fuzzer
COPY . .
RUN pip install -e ".[dev,network]"

# Copy samples
COPY samples/input /fuzzing/input
RUN mkdir -p /fuzzing/output

# Run fuzzing on container start
ENTRYPOINT ["python", "-m", "dicom_fuzzer.cli"]
CMD ["--input", "/fuzzing/input/", \
     "--output", "/fuzzing/output/", \
     "--count", "100", \
     "--strategies", "metadata,pixel,header"]
```

**Usage**:

```bash
# Build image
docker build -t dicom-fuzzer -f Dockerfile.fuzzing .

# Run fuzzing
docker run -v $(pwd)/output:/fuzzing/output dicom-fuzzer

# Extract results
docker cp container_id:/fuzzing/output ./results
```

---

## Custom Mutation Strategies

### Example 13: Create Custom Mutation Strategy

Implement domain-specific mutations:

```python
"""Custom mutation strategy for RT (Radiotherapy) DICOM."""
from dicom_fuzzer.core.mutator import MutationStrategy
from pydicom.dataset import Dataset

class RTDoseMutationStrategy(MutationStrategy):
    """Mutate Radiotherapy dose distribution data."""

    name = "rt_dose"
    severity = MutationSeverity.MEDIUM

    def mutate(self, dataset: Dataset) -> Dataset:
        """Apply RT-specific mutations."""
        # Check if RT Dose module
        if dataset.get("Modality") != "RTDOSE":
            return dataset

        # Mutate dose grid
        if "DoseGridScaling" in dataset:
            # Introduce scaling errors
            original = float(dataset.DoseGridScaling)
            dataset.DoseGridScaling = original * 1.5

        # Mutate dose units
        if "DoseUnits" in dataset:
            dataset.DoseUnits = "INVALID_UNIT"

        # Corrupt dose pixel data
        if hasattr(dataset, "pixel_array"):
            pixels = dataset.pixel_array
            # Introduce hot spots
            pixels[100:110, 100:110] = pixels.max() * 2
            dataset.PixelData = pixels.tobytes()

        return dataset

# Register and use custom strategy
from dicom_fuzzer.core.mutator import DicomMutator

mutator = DicomMutator()
mutator.register_strategy(RTDoseMutationStrategy())

# Apply custom mutation
dataset = mutator.mutate(
    dataset,
    strategies=["rt_dose"]
)

print(f"[+] Custom RT dose mutation applied")
print(f"[+] Dose grid scaling modified: {dataset.DoseGridScaling}")
print(f"[+] Dose units corrupted: {dataset.DoseUnits}")
```

**Expected Output**:

```
[+] Custom RT dose mutation applied
[+] Dose grid scaling modified: 1.5e-4
[+] Dose units corrupted: INVALID_UNIT
```

---

## Performance Testing

### Example 14: Benchmark Fuzzing Performance

Measure fuzzing throughput:

```python
"""Benchmark fuzzing performance and throughput."""
import time
from pathlib import Path
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.parser import DicomParser

parser = DicomParser()
mutator = DicomMutator()

input_file = Path("samples/input/large_series.dcm")
dataset = parser.parse_file(input_file)

# Benchmark
num_iterations = 1000
strategies = ["metadata", "pixel", "header"]

start_time = time.time()
mutator.start_session()

for i in range(num_iterations):
    mutated = mutator.mutate(dataset, strategies=strategies)
    output = Path(f"samples/benchmark/fuzzed_{i:04d}.dcm")
    mutated.save_as(output)

mutator.end_session()
elapsed = time.time() - start_time

# Calculate metrics
throughput = num_iterations / elapsed
avg_time = elapsed / num_iterations

print(f"[+] Performance Benchmarks:")
print(f"    Total iterations: {num_iterations}")
print(f"    Total time: {elapsed:.2f}s")
print(f"    Throughput: {throughput:.2f} files/sec")
print(f"    Average time per file: {avg_time*1000:.2f}ms")
```

**Expected Output**:

```
[+] Performance Benchmarks:
    Total iterations: 1000
    Total time: 45.67s
    Throughput: 21.90 files/sec
    Average time per file: 45.67ms
```

---

## More Examples

For additional examples and use cases:

- **[examples/](../examples/)** - Demonstration scripts
- **[tests/](../tests/)** - Test suite with comprehensive examples
- **[FUZZING_GUIDE.md](FUZZING_GUIDE.md)** - Advanced fuzzing techniques
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Implementation details

## Contributing Examples

To contribute an example:

1. Add your example to `examples/` directory
2. Document usage in this file
3. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
