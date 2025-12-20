# AFL++ Persistent Mode Harness for DICOM Fuzzing

High-performance fuzzing harness using AFL++ persistent mode for 10-20x speed improvement over traditional fork-based fuzzing.

## Quick Start

### Build the Harness

```bash
# Install AFL++
apt-get install afl++

# Compile with AFL++ instrumentation
afl-clang-fast -O2 -o dicom_harness afl_persistent.c

# Or compile for standalone testing
gcc -DSTANDALONE -O2 -o dicom_test afl_persistent.c
```

### Run Fuzzing

```bash
# Prepare corpus (use stripped files for faster fuzzing)
dicom-fuzzer samples --strip-pixel-data ./corpus -o ./corpus_stripped

# Run AFL++
afl-fuzz -i ./corpus_stripped -o ./findings ./dicom_harness
```

### Parallel Fuzzing

```bash
# Master instance
afl-fuzz -M main -i corpus -o findings ./dicom_harness

# Secondary instances (run on additional cores)
afl-fuzz -S fuzzer01 -i corpus -o findings ./dicom_harness
afl-fuzz -S fuzzer02 -i corpus -o findings ./dicom_harness
```

## Performance Tuning

### Persistent Mode Configuration

Edit `afl_persistent.c`:

```c
#define PERSISTENT_ITERATIONS 1000  // Increase for more speed
#define MAX_INPUT_SIZE (100 * 1024 * 1024)  // Adjust per target
```

### Corpus Optimization

For maximum throughput:

1. Strip PixelData: `dicom-fuzzer samples --strip-pixel-data corpus -o corpus_opt`
2. Use small seed files (<10KB preferred)
3. Diverse but minimal corpus

### AFL++ Options

```bash
# Recommended options for DICOM fuzzing
afl-fuzz \
  -i corpus \
  -o findings \
  -m 512 \           # Memory limit MB
  -t 1000 \          # Timeout ms
  -x dicom.dict \    # Use DICOM dictionary
  ./dicom_harness
```

## Integration with Target Libraries

### Fuzzing pydicom (via Python C API)

```c
// Replace parse_dicom() with:
#include <Python.h>
static ParseResult parse_dicom(const uint8_t *buf, size_t len) {
    // Call pydicom.dcmread() through C API
}
```

### Fuzzing GDCM

```c
// Link with GDCM
#include <gdcmReader.h>
static ParseResult parse_dicom(const uint8_t *buf, size_t len) {
    gdcm::Reader reader;
    // Use GDCM parser
}
```

## Sanitizer Integration (ASan/UBSan/MSan)

Memory safety bugs are critical in medical device software. Use sanitizers to detect:

- Buffer overflows (ASan)
- Use-after-free (ASan)
- Undefined behavior (UBSan)
- Uninitialized memory (MSan)

### AddressSanitizer (ASan)

Detects memory errors including buffer overflows and use-after-free.

```bash
# Build with ASan
afl-clang-fast -O2 -fsanitize=address \
  -fno-omit-frame-pointer \
  -o dicom_harness_asan afl_persistent.c

# Run with ASan environment
export ASAN_OPTIONS="abort_on_error=1:symbolize=1:detect_leaks=0"
afl-fuzz -i corpus -o findings_asan ./dicom_harness_asan
```

**ASan Options for Fuzzing:**

```bash
# Recommended ASAN_OPTIONS for fuzzing
export ASAN_OPTIONS="\
  abort_on_error=1:\
  symbolize=1:\
  detect_leaks=0:\
  malloc_context_size=30:\
  allocator_may_return_null=1:\
  detect_stack_use_after_return=1"
```

### UndefinedBehaviorSanitizer (UBSan)

Detects undefined behavior including integer overflows and null pointer dereferences.

```bash
# Build with UBSan
afl-clang-fast -O2 -fsanitize=undefined \
  -fno-sanitize-recover=all \
  -o dicom_harness_ubsan afl_persistent.c

# Environment settings
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
afl-fuzz -i corpus -o findings_ubsan ./dicom_harness_ubsan
```

**UBSan Checks Enabled:**

- Integer overflow (signed/unsigned)
- Null pointer dereference
- Misaligned pointer access
- Out-of-bounds array access
- Invalid shift operations
- Division by zero

### Combined ASan + UBSan

For comprehensive coverage, combine both sanitizers:

```bash
# Build with ASan + UBSan
afl-clang-fast -O2 \
  -fsanitize=address,undefined \
  -fno-omit-frame-pointer \
  -fno-sanitize-recover=all \
  -o dicom_harness_sanitized afl_persistent.c

# Combined environment
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0"
export UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
afl-fuzz -i corpus -o findings_combined ./dicom_harness_sanitized
```

### MemorySanitizer (MSan)

Detects uninitialized memory reads. Requires special build (not compatible with ASan).

```bash
# Build with MSan (requires clang, not gcc)
clang -O2 -fsanitize=memory \
  -fno-omit-frame-pointer \
  -o dicom_harness_msan afl_persistent.c

# Environment
export MSAN_OPTIONS="exit_code=86:halt_on_error=1"
```

**Note:** MSan requires all libraries to be instrumented. Use `msan` build targets.

### libFuzzer with Sanitizers

For the libFuzzer harness, sanitizers are enabled at compile time:

```bash
# libFuzzer + ASan + UBSan (recommended)
clang++ -O1 \
  -fsanitize=fuzzer,address,undefined \
  -fno-omit-frame-pointer \
  -o dicom_libfuzzer libfuzzer_harness.cpp

# Run with corpus
./dicom_libfuzzer corpus/ -max_len=10485760 -dict=dicom.dict
```

### AFL++ Custom Mutator with Sanitizers

```bash
# Build custom mutator shared library
cd custom_mutators
afl-clang-fast -shared -fPIC -O2 \
  -fsanitize=address,undefined \
  -o dicom_mutator.so dicom_mutator.c

# Use with AFL++
AFL_CUSTOM_MUTATOR_LIBRARY=./custom_mutators/dicom_mutator.so \
afl-fuzz -i corpus -o findings ./dicom_harness_sanitized
```

### Crash Triage with Sanitizers

When crashes are found, triage with sanitizers for better diagnostics:

```bash
# Reproduce crash with ASan for stack trace
./dicom_harness_asan < findings/crashes/id:000000*

# Get symbolized output
ASAN_OPTIONS="symbolize=1" ./dicom_harness_asan < crash_file 2>&1 | \
  llvm-symbolizer
```

### Performance Considerations

| Sanitizer  | Overhead | Use Case             |
| ---------- | -------- | -------------------- |
| None       | 1x       | Maximum throughput   |
| ASan       | 2-3x     | Memory safety bugs   |
| UBSan      | 1.5x     | Undefined behavior   |
| ASan+UBSan | 3-4x     | Comprehensive        |
| MSan       | 3-5x     | Uninitialized memory |

**Strategy:** Run parallel instances:

- 50% without sanitizers (maximize coverage)
- 25% with ASan (memory bugs)
- 25% with UBSan (undefined behavior)

### CI/CD Integration

GitHub Actions example for sanitizer builds:

```yaml
jobs:
  fuzz-asan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          apt-get install -y afl++
          cd harness
          afl-clang-fast -O2 -fsanitize=address \
            -o dicom_harness_asan afl_persistent.c
          timeout 3600 afl-fuzz -i ../corpus -o findings \
            ./dicom_harness_asan || true
      - uses: actions/upload-artifact@v4
        with:
          name: asan-findings
          path: harness/findings/
```

## Files

- `afl_persistent.c` - AFL++ persistent mode harness
- `libfuzzer_harness.cpp` - libFuzzer-compatible harness
- `dicom.dict` - AFL dictionary for DICOM-aware mutations
- `custom_mutators/dicom_mutator.c` - Structure-aware AFL++ custom mutator

## FDA Compliance Note

This harness supports FDA 2025 cybersecurity requirements for fuzz testing.
Document the following for submissions:

- Total iterations executed
- Code coverage achieved
- Unique crashes found
- Remediation of findings

Generate compliance reports: `dicom-fuzzer fda-report`
