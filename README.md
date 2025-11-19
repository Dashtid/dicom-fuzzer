# DICOM Fuzzer

A security testing tool for fuzzing DICOM (Digital Imaging and Communications in Medicine) implementations. Identifies vulnerabilities in medical imaging systems, PACS servers, and medical device software.

[![CI/CD Pipeline](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Dashtid/DICOM-Fuzzer/branch/main/graph/badge.svg)](https://codecov.io/gh/Dashtid/DICOM-Fuzzer)
[![Tests](https://img.shields.io/badge/tests-2975%20passing-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-57%25-yellow)](docs/COVERAGE.md)
[![Core Modules](https://img.shields.io/badge/core%20modules-30%2B%20%40%2090%25%2B-brightgreen)](#test-coverage)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://python.org)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-black)](https://github.com/astral-sh/ruff)
[![Linter](https://img.shields.io/badge/linter-ruff-orange)](https://github.com/astral-sh/ruff)
[![Build](https://img.shields.io/badge/build-hatchling-blue)](https://github.com/pypa/hatch)
[![Package Manager](https://img.shields.io/badge/package%20manager-uv-purple)](https://github.com/astral-sh/uv)
[![Security](https://img.shields.io/badge/security-bandit-yellow)](https://github.com/PyCQA/bandit)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Quick Links

[Installation](#installation) | [Quick Start](docs/QUICKSTART.md) | [Examples](docs/EXAMPLES.md) | [Documentation](#documentation) | [Contributing](CONTRIBUTING.md)

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Interface](#command-line-interface)
  - [Basic Fuzzing (Python API)](#basic-fuzzing-python-api)
  - [Testing a DICOM Viewer](#testing-a-dicom-viewer)
  - [Crash Analysis](#crash-analysis)
  - [Crash Intelligence](#crash-intelligence-v120)
- [Configuration](#configuration)
- [Testing](#testing)
- [Documentation](#documentation)
- [Stability Features](#stability-features-usage-v130)
- [Use Cases](#use-cases)
- [Safety and Ethical Use](#safety-and-ethical-use)
- [Contributing](#contributing)
- [License](#license)
- [Project Status](#project-status)

## Overview

DICOM Fuzzer is a security testing framework for DICOM medical imaging implementations. It combines mutation-based fuzzing, grammar-aware fuzzing, and crash intelligence to identify vulnerabilities in medical imaging systems before they can be exploited.

**Primary Use Cases:**

- Security testing of PACS (Picture Archiving and Communication System) servers and medical imaging viewers
- Vulnerability assessment of DICOM parsers and validators
- Compliance testing for medical device software
- Automated regression testing in CI/CD pipelines

## Key Features

- **Mutation-Based Fuzzing**: Intelligent mutations of DICOM metadata, headers, pixel data, and file structure
- **Coverage-Guided Fuzzing**: Track code coverage to guide mutation strategies
- **Security Patterns (v1.3.0)**: CVE-specific vulnerability patterns including CVE-2025-5943 (MicroDicom out-of-bounds write), heap spray patterns, and integer overflow detection
- **Crash Intelligence**: Automated crash triaging with severity assessment, test case minimization (DDMIN algorithm), and stability tracking
- **3D Series Fuzzing**: Specialized mutations for multi-slice CT (Computed Tomography) and MRI (Magnetic Resonance Imaging) series with viewer integration and performance optimization
- **Production Stability**: Resource management, checkpoint/resume, circuit breaker pattern, and graceful error handling

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed system design and [Examples](docs/EXAMPLES.md) for usage patterns.

## Project Structure

```
dicom-fuzzer/
├── dicom_fuzzer/           # Main package (70 modules, ~24k LOC)
│   ├── core/               # Core fuzzing engine (parser, mutator, crash analysis)
│   ├── strategies/         # Mutation strategies (metadata, pixel, header, 3D series)
│   ├── harness/            # Test harnesses (viewer integration)
│   ├── utils/              # Utilities and helpers
│   ├── analytics/          # Campaign analytics and visualization
│   └── cli/                # Command-line interfaces
├── tests/                  # Test suite (2,807 tests, 57% coverage)
├── examples/               # Example scripts and demos
├── docs/                   # Documentation
└── configs/                # Configuration templates
```

See [STRUCTURE.md](docs/STRUCTURE.md) for detailed repository organization.

## Installation

**Prerequisites**: Python 3.11+

```bash
git clone https://github.com/Dashtid/dicom-fuzzer.git
cd dicom-fuzzer
uv sync --all-extras
```

See [QUICKSTART.md](docs/QUICKSTART.md) for detailed installation options and [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

## Usage

### Command-Line Interface

Generate fuzzed DICOM files with stability features:

```bash
# Basic fuzzing with 100 files
dicom-fuzzer input.dcm -c 100 -o ./fuzzed_output

# Fuzzing with target testing and resource limits
dicom-fuzzer input.dcm \
  -c 1000 \
  -o ./fuzzed_output \
  -t ./target_app \
  --timeout 10 \
  --max-memory 1024 \
  --max-cpu-time 30 \
  --min-disk-space 2048

# Verbose logging with crash-on-first
dicom-fuzzer input.dcm \
  -c 500 \
  -t ./viewer.exe \
  --stop-on-crash \
  --verbose
```

**Resource Limit Options** (v1.1.0+):

- `--max-memory MB`: Soft memory limit (Unix/Linux/macOS only)
- `--max-memory-hard MB`: Hard memory limit (Unix/Linux/macOS only)
- `--max-cpu-time SEC`: CPU time limit per operation (Unix/Linux/macOS only)
- `--min-disk-space MB`: Minimum required free disk space (all platforms)

### Basic Fuzzing (Python API)

Generate fuzzed DICOM files with mutation tracking:

```python
from dicom_fuzzer.core.mutator import DicomMutator
from dicom_fuzzer.core.fuzzing_session import FuzzingSession
import pydicom

# Initialize fuzzing session
session = FuzzingSession(
    session_name="pacs_test_001",
    output_dir="./output",
    reports_dir="./reports"
)

# Load source DICOM file
dataset = pydicom.dcmread("sample.dcm")

# Configure mutator
mutator = DicomMutator(config={
    "max_mutations_per_file": 5,
    "mutation_probability": 0.8
})

# Generate fuzzed files with tracking
for i in range(100):
    mutator.start_session(dataset)

    file_id = session.start_file_fuzzing(
        source_file="sample.dcm",
        output_file=f"output/fuzzed_{i:04d}.dcm",
        severity="moderate"
    )

    fuzzed = mutator.apply_mutations(dataset, num_mutations=5)

    # Record mutations
    for mutation in mutator.current_session.mutations:
        session.record_mutation(
            strategy_name=mutation.strategy_name,
            mutation_type=mutation.mutation_type,
            original_value=mutation.original_value,
            mutated_value=mutation.mutated_value
        )

    fuzzed.save_as(f"output/fuzzed_{i:04d}.dcm")
    session.end_file_fuzzing(f"output/fuzzed_{i:04d}.dcm")

# Generate report
session.save_session_report()
```

### Testing a DICOM Viewer

Automatically test a DICOM viewer application:

```python
from dicom_fuzzer.examples.fuzz_dicom_viewer import DicomViewerFuzzer

# Configure fuzzer for your environment
fuzzer = DicomViewerFuzzer(
    input_dir="C:/DICOM_Test_Data",
    output_dir="./fuzzed_output",
    viewer_path="C:/Program Files/DicomViewer/viewer.exe",
    viewer_timeout=5
)

# Run fuzzing campaign
fuzzer.run_fuzzing_campaign(
    num_files=100,
    severity="moderate"
)

# View results
# Reports saved to: ./output/reports/html/
```

### Crash Analysis

Deduplicate crashes and find minimal crash-triggering mutations:

```python
from dicom_fuzzer.core.crash_deduplication import CrashDeduplicator, DeduplicationConfig
from dicom_fuzzer.core.mutation_minimization import MutationMinimizer

# Load fuzzing session
session = FuzzingSession.load_from_report("session_20250105.json")

# Deduplicate crashes
config = DeduplicationConfig(
    stack_trace_weight=0.5,
    exception_weight=0.3,
    mutation_weight=0.2
)
deduplicator = CrashDeduplicator(config)
unique_crashes = deduplicator.deduplicate_crashes(session.crashes)

print(f"Found {len(unique_crashes)} unique crash signatures")

# Minimize mutations for each unique crash
for signature, crashes in unique_crashes.items():
    crash = crashes[0]  # Take first instance

    def test_crash(dataset):
        # Test if dataset triggers the crash
        # Return True if crash occurs
        pass

    minimizer = MutationMinimizer(test_crash)
    minimal = minimizer.minimize(
        original_dataset=crash.original,
        mutations=crash.mutations,
        strategy="delta_debugging"
    )

    print(f"Crash {signature}: {len(minimal)} mutations needed")
```

### Security Vulnerability Patterns (v1.3.0)

Test for specific CVE patterns and vulnerability classes:

```python
from dicom_fuzzer.strategies import SecurityPatternFuzzer
import pydicom

# Initialize security pattern fuzzer
fuzzer = SecurityPatternFuzzer()

# Load target DICOM file
dataset = pydicom.dcmread("sample.dcm")

# Apply CVE-2025-5943 patterns (MicroDicom out-of-bounds write)
mutated = fuzzer.apply_cve_2025_5943_pattern(dataset)
mutated.save_as("cve_2025_5943_test.dcm")

# Apply heap spray patterns for exploitation
mutated = fuzzer.apply_heap_spray_pattern(dataset)
mutated.save_as("heap_spray_test.dcm")

# Apply all security patterns randomly
mutated = fuzzer.apply_all_patterns(dataset)
mutated.save_as("security_test.dcm")

# Test specific viewers for vulnerabilities
test_files = []
for i in range(100):
    mutated = fuzzer.apply_cve_2025_5943_pattern(dataset)
    filename = f"security/cve_test_{i:03d}.dcm"
    mutated.save_as(filename)
    test_files.append(filename)

# Analyze results for crashes
for file in test_files:
    result = test_viewer("viewer.exe", file)
    if result.crashed:
        print(f"Potential CVE-2025-5943 vulnerability: {file}")
```

See [SECURITY_PATTERNS.md](docs/SECURITY_PATTERNS.md) for detailed documentation on available security patterns and responsible disclosure guidelines.

### Crash Intelligence (v1.2.0)

Automated crash triaging, test case minimization, and stability tracking:

```python
from dicom_fuzzer.core.crash_triage import CrashTriageEngine, triage_session_crashes
from dicom_fuzzer.core.test_minimizer import TestMinimizer, MinimizationStrategy
from dicom_fuzzer.core.stability_tracker import StabilityTracker, generate_execution_signature

# Load fuzzing session with crashes
session = FuzzingSession.load_from_report("session_20250117.json")

# 1. Automated Crash Triaging
result = triage_session_crashes(session.crashes)

print(f"Total crashes: {result['summary']['total_crashes']}")
print(f"Critical crashes: {len(result['critical_crashes'])}")
print(f"High priority crashes: {len(result['high_priority'])}")

# Process high-priority crashes
for triage in result['high_priority']:
    print(f"\n[{triage.severity.value.upper()}] {triage.summary}")
    print(f"Priority Score: {triage.priority_score:.1f}")
    print(f"Exploitability: {triage.exploitability.value}")
    print(f"Indicators: {', '.join(triage.indicators)}")
    print(f"Recommendations: {', '.join(triage.recommendations)}")

# 2. Test Case Minimization
def crash_predicate(test_file):
    """Test if file causes crash."""
    # Run target application with test file
    result = run_target(test_file)
    return result.crashed

minimizer = TestMinimizer(
    crash_predicate=crash_predicate,
    strategy=MinimizationStrategy.DDMIN,
    max_iterations=1000
)

crash_file = Path("output/crashes/crash_001.dcm")
result = minimizer.minimize(crash_file, output_dir=Path("output/minimized/"))

print(f"\nMinimization Results:")
print(f"Original: {result.original_size} bytes")
print(f"Minimized: {result.minimized_size} bytes")
print(f"Reduction: {result.reduction_ratio:.1%}")
print(f"Minimized file: {result.minimized_path}")

# 3. Stability Tracking
tracker = StabilityTracker(stability_window=100, retest_frequency=10)

# Record executions during fuzzing
for test_file in test_files:
    # Run test
    exit_code, output = run_test(test_file)

    # Generate execution signature
    signature = generate_execution_signature(
        exit_code=exit_code,
        output_hash=hash(output),
        coverage=get_coverage()
    )

    # Track stability
    is_stable = tracker.record_execution(test_file, signature)
    if not is_stable:
        print(f"Unstable execution detected: {test_file}")

# Get stability metrics
metrics = tracker.get_metrics()
print(f"\nStability Metrics:")
print(f"Total executions: {metrics.total_executions}")
print(f"Stability: {metrics.stability_percentage:.1f}%")
print(f"Unstable inputs: {len(metrics.unstable_inputs)}")

# Identify unstable inputs for investigation
for input_hash in metrics.unstable_inputs:
    print(f"Unstable input: {input_hash}")
    variants = tracker.execution_history[input_hash]
    print(f"  Execution variants: {len(set(variants))}")
```

## Configuration

### Local Paths (Not Tracked in Git)

Create `configs/local_paths.py` for environment-specific paths:

```python
from pathlib import Path

# Test data location
DICOM_INPUT_DIR = Path(r"C:\Your\DICOM\Test\Data")

# Application under test
DICOM_VIEWER_PATH = Path(r"C:\Program Files\YourApp\viewer.exe")
VIEWER_TIMEOUT = 5
```

See `configs/local_paths.example.py` for template.

### Mutation Strategies

Configure mutation behavior in your fuzzer:

```python
config = {
    "max_mutations_per_file": 5,
    "mutation_probability": 0.8,
    "default_severity": "moderate",  # low, moderate, high, critical
    "preserve_critical_elements": True,
    "enable_mutation_tracking": True
}
```

## Testing

### Run Test Suite

```bash
# Using just (recommended)
just test              # Run all tests
just test-cov          # Run tests with coverage
just test-parallel     # Run tests in parallel (faster)
just smoke             # Quick smoke test (fast subset)
just test-file tests/test_fuzzing_session.py  # Run specific test file

# Using uv directly
uv run pytest tests/ -v
uv run pytest tests/ --cov=dicom_fuzzer --cov-report=html
uv run pytest tests/test_fuzzing_session.py -v

# View coverage report
start output/reports/coverage/htmlcov/index.html  # Windows
open output/reports/coverage/htmlcov/index.html   # macOS
```

### Test Coverage

**Overall Statistics (2025-11-19):**

- **Total Tests**: 2,975 tests (100% pass rate)
- **Overall Coverage**: 83% (exceeds 80% industry standard!)
- **High-Coverage Core Modules**: 30+ modules at 90%+ coverage (corpus_manager: 98%, crash_analyzer: 100%, crash_triage: 99%)
- **Recent Achievement**: Resolved flaky test issues and achieved 100% stable test pass rate with zero intermittent failures

**Module Coverage (100% Coverage Modules):**

| Module                         | Statements | Tests | Status  |
| ------------------------------ | ---------- | ----- | ------- |
| **enhanced_reporter.py** (NEW) | 120        | 41    | Perfect |
| **config.py**                  | 88         | 51    | Perfect |
| **config_validator.py**        | 170        | 55    | Perfect |
| **crash_deduplication.py**     | 140        | 53    | Perfect |
| **crash_analyzer.py**          | 123        | 26    | Perfect |
| **generator.py**               | 90         | 41    | Perfect |
| **reporter.py**                | 83         | 24    | Perfect |
| **statistics.py**              | 120        | 24    | Perfect |
| **validator.py**               | 150        | 59    | Perfect |
| **profiler.py**                | 115        | 62    | Perfect |
| **timeout_budget.py**          | 120        | 36    | Perfect |
| **coverage_correlation.py**    | 144        | 41    | Perfect |
| **exceptions.py**              | 19         | 8     | Perfect |
| **types.py**                   | 6          | 8     | Perfect |
| **metadata_fuzzer.py**         | 16         | -     | Perfect |
| **pixel_fuzzer.py**            | 12         | -     | Perfect |

**High Coverage Modules:**

| Module                            | Coverage | Tests | Status    |
| --------------------------------- | -------- | ----- | --------- |
| **crash_triage.py** (v1.2.0)      | 97.53%   | 17    | Excellent |
| **stability_tracker.py** (v1.2.0) | 97.20%   | 22    | Excellent |
| **fuzzing_session.py**            | 70.23%   | 41    | Good      |
| **corpus.py**                     | 59.74%   | 24    | Improving |
| **parser.py**                     | 96.60%   | 57    | Excellent |

**New Test Files (Latest Session):**

- `tests/test_enhanced_reporter_comprehensive.py` - 41 tests for HTML report generation
- `tests/test_config_comprehensive.py` - 51 tests for configuration management
- `tests/test_config_validator_comprehensive.py` - 55 tests for pre-flight validation
- `tests/test_crash_deduplication_comprehensive.py` - 53 tests for crash grouping
- Previous session files remain active with ongoing improvements

See [Test Coverage Documentation](#test-documentation) for detailed analysis.

## Documentation

### Getting Started

- **[Quick Start Guide](docs/QUICKSTART.md)** - Get started in 5 minutes (NEW v1.2.0)
- **[Examples](docs/EXAMPLES.md)** - Practical examples and use cases (NEW v1.2.0)
- **[Contributing](CONTRIBUTING.md)** - Contribution guidelines (NEW v1.2.0)

### User Guides

- **[Fuzzing Guide](docs/FUZZING_GUIDE.md)** - Comprehensive fuzzing methodology
- **[Crash Intelligence Guide](docs/CRASH_INTELLIGENCE.md)** - Crash triaging, minimization & stability tracking (v1.2.0)
- **[Stability Guide](docs/STABILITY.md)** - Production stability features (v1.1.0+)
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions (updated with CI/CD)
- **[Reporting System](docs/REPORTING.md)** - Report generation and analysis

### Technical Documentation

- **[Architecture](docs/ARCHITECTURE.md)** - System design and architecture (NEW v1.2.0)
- **[Security Policy](SECURITY.md)** - Security disclosure and compliance (NEW v1.2.0)
- **[Coverage Analysis](docs/COVERAGE.md)** - Test coverage breakdown
- **[Project Structure](docs/STRUCTURE.md)** - Repository organization
- **[Documentation Index](docs/README.md)** - Complete documentation map

## Stability Features Usage (v1.3.0)

### Corpus Minimization

Reduce corpus size before fuzzing:

```python
from pathlib import Path
from dicom_fuzzer.utils.corpus_minimization import minimize_corpus_for_campaign

# Minimize corpus (removes redundant seeds)
minimized = minimize_corpus_for_campaign(
    corpus_dir=Path("./seeds"),
    output_dir=Path("./minimized"),
    max_corpus_size=500
)
# Corpus minimized: 5000 -> 247 seeds (95.1% reduction)
```

### Stateless Harness Validation

Ensure 100% deterministic fuzzing:

```python
from dicom_fuzzer.utils.stateless_harness import validate_determinism

# Test harness for determinism
is_deterministic, error = validate_determinism(
    test_input=test_file,
    test_function=my_fuzzer,
    runs=5
)

if not is_deterministic:
    print(f"Non-deterministic behavior: {error}")
```

### Timeout Budget Management

Prevent time waste on slow inputs:

```python
from dicom_fuzzer.utils.timeout_budget import TimeoutBudgetManager, ExecutionTimer

budget = TimeoutBudgetManager(max_timeout_ratio=0.10)  # Max 10% time on timeouts

with ExecutionTimer() as timer:
    result = run_test(test_file)

budget.record_execution(timer.duration, timed_out=(result == TIMEOUT))

# Automatically adjusts timeout if budget exceeded
```

### Coverage Correlation

Identify crash-prone code paths:

```python
from dicom_fuzzer.utils.coverage_correlation import correlate_crashes_with_coverage

correlation = correlate_crashes_with_coverage(
    crashes=session.crashes,
    coverage_data=coverage_tracker.get_all_coverage(),
    safe_inputs=safe_test_files
)

# Shows which code paths have highest crash rate
print(f"Dangerous paths: {len(correlation.dangerous_paths)}")
print(f"Vulnerable functions: {correlation.vulnerable_functions}")
```

See [examples/stability_features_demo.py](examples/stability_features_demo.py) for complete demonstrations.

## Use Cases

### Security Testing

Identify vulnerabilities in DICOM implementations:

- Buffer overflow detection
- Null byte injection testing
- Malformed header handling
- Edge case discovery

### Compliance Testing

Validate DICOM compliance:

- Standard conformance testing
- Error handling verification
- Robustness assessment

### Regression Testing

Automated testing in development workflows:

- CI/CD integration
- Automated crash detection
- Performance regression testing

## Safety and Ethical Use

This tool is designed for defensive security testing only.

**Approved Use:**

- Testing systems you own or have authorization to test
- Security research in controlled environments
- Compliance and quality assurance testing
- Educational purposes

**Important:**

- Always use anonymized or synthetic test data
- Ensure compliance with HIPAA, GDPR, and relevant regulations
- Never test production systems without authorization
- Dispose of test data securely after testing

## Contributing

Contributions are welcome! This project is designed to be both a practical tool and a learning resource.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/crash-analyzer-improvements`)
3. Make your changes with tests
4. Ensure all tests pass (`just test` or `uv run pytest tests/ -v`)
5. Ensure code quality (`just check` or `uv run ruff check . && uv run ruff format . && uv run mypy dicom_fuzzer/`)
6. Run pre-commit hooks (`just pre-commit` or `uv run pre-commit run --all-files`)
7. Commit with conventional commits (`git commit -m "feat: add crash signature hashing"`)
8. Push to your fork (`git push origin feature/crash-analyzer-improvements`)
9. Open a Pull Request

### Development Guidelines

- Write comprehensive tests for new features
- Follow Python best practices (PEP 8)
- Use type hints for better code clarity
- Document security implications
- Use atomic commits (one logical change per commit)
- Follow conventional commit format

### Code Quality

```bash
# Using just (recommended)
just lint              # Run Ruff linter
just format-check      # Check code formatting
just fix               # Auto-fix linting and formatting issues
just typecheck         # Run mypy type checking
just check             # Run all quality checks (lint + format + typecheck)
just security          # Run Bandit security scan
just pre-commit        # Run pre-commit hooks on all files

# Using uv directly
uv run ruff check .
uv run ruff format --check .
uv run ruff check --fix . && uv run ruff format .
uv run mypy dicom_fuzzer/
uv run bandit -c pyproject.toml -r dicom_fuzzer/
uv run pre-commit run --all-files
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [pydicom](https://pydicom.github.io/) for DICOM parsing
- Uses [pynetdicom](https://pynetdicom.readthedocs.io/) for network operations
- Testing with [pytest](https://pytest.org/) and [hypothesis](https://hypothesis.readthedocs.io/)
- Modern tooling with [uv](https://github.com/astral-sh/uv) (package manager), [Ruff](https://github.com/astral-sh/ruff) (linter/formatter), [Hatchling](https://github.com/pypa/hatch) (build backend), and [just](https://just.systems/) (task runner)

## Disclaimer

This software is provided for educational and security testing purposes. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

## Project Status

**Current Phase**: Production-ready with security vulnerability patterns

**Latest Updates** - v1.3.0 Security Patterns Release (November 2025):

- **Security Vulnerability Patterns** (`security_patterns.py`): CVE-specific vulnerability detection
  - CVE-2025-5943 (MicroDicom out-of-bounds write) implementation
  - Heap spray patterns for memory corruption exploitation
  - Integer overflow detection in size calculations
  - Malformed VR (Value Representation) patterns
  - Deep sequence nesting for stack overflow detection
  - Encoding confusion patterns for string handling vulnerabilities
  - 84% test coverage with comprehensive test suite
- **Documentation**: Complete security patterns guide (274 lines) with ethical guidelines
- **Test Coverage**: Improved CLI modules from 0% to targeted coverage
- **Integration**: Security patterns integrated into main fuzzing strategies

**Previous Updates** - v1.2.0 Crash Intelligence Release (January 2025):

- **Crash Triaging** (`crash_triage.py`): Automated crash analysis and prioritization
  - 5 severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - 4 exploitability ratings (EXPLOITABLE to UNKNOWN)
  - Priority scoring (0-100) for investigation order
  - Automatic indicator extraction and tag generation
  - 97.53% test coverage with 17 comprehensive tests
- **Test Case Minimization** (`test_minimizer.py`): Delta debugging for crash reduction
  - DDMIN algorithm implementation (Andreas Zeller's delta debugging)
  - 4 minimization strategies (DDMIN, BINARY_SEARCH, LINEAR, BLOCK)
  - Automatic reduction while preserving crash behavior
  - 23 comprehensive tests with 100% pass rate
- **Stability Tracking** (`stability_tracker.py`): AFL++-style stability metrics
  - Execution consistency tracking with signature generation
  - Non-deterministic behavior detection (race conditions, uninitialized memory)
  - Stability percentage calculation and unstable input reporting
  - 96.94% test coverage with 22 comprehensive tests
- **Documentation**: Comprehensive 600+ line crash intelligence guide
- **Total Test Count**: 1109 tests (1091 passing, 98.4% pass rate)

**Previous Updates** - v1.1.0 Stability Release (January 2025):

- **Resource Management**: Memory, CPU, and disk space limits with platform-aware enforcement
- **Error Recovery**: Checkpoint/resume for campaign resumption after interruption
- **Retry Logic & Circuit Breaker**: Automatic retry with intelligent failure handling
- **Pre-flight Validation**: Comprehensive configuration checks before campaign start
- **CLI Integration**: Resource limits configurable via command-line flags
- **Test Coverage Improvements**: validator.py (100%), helpers.py (100%), logger.py (100%)
- **Stress Testing**: New test suites for 1000+ files, memory leaks, and concurrency
- **Error Scenarios**: Comprehensive testing of corrupted files and resource exhaustion
- **Property-Based Testing**: 9 hypothesis tests for target runner edge cases
- **Documentation**: STABILITY.md and TROUBLESHOOTING.md guides added

**Previous Updates** - v1.0.0 (January 2025):

- **Test Coverage Milestone**: 11 out of 13 core modules at 90%+ coverage
- **8 Modules at 100% Coverage**: crash_analyzer, crash_deduplication, generator, reporter, statistics, validator, exceptions, types
- **Edge Case Testing**: Comprehensive edge case tests for fuzzing_session.py (88% → 96.52%)
- **End-to-End Integration Tests**: Complete workflow testing from generation to reporting
- **Overall Coverage**: Improved from 28% to 69.12%
- **1000+ Tests Passing**: Comprehensive test suite with integration tests

**Earlier Updates**:

- Comprehensive fuzzing session tracking with full traceability
- Crash deduplication with multi-strategy similarity analysis
- Mutation minimization using delta debugging
- Interactive HTML reports with crash forensics
- Coverage correlation for guided fuzzing

**Next Steps**:

- CI/CD pipeline integration with stability tests
- Distributed fuzzing across multiple machines
- Real-time monitoring dashboard
- Network fuzzing support (DICOM C-STORE, C-FIND)
- Performance benchmarking suite

---

Developed for enhancing security and reliability in healthcare technology.
