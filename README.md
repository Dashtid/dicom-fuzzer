# DICOM Fuzzer

A specialized security testing tool for fuzzing DICOM (Digital Imaging and Communications in Medicine) implementations. Designed to identify vulnerabilities in medical imaging systems, PACS servers, and medical device software through automated security testing.

[![CI/CD Pipeline](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/DICOM-Fuzzer/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Dashtid/DICOM-Fuzzer/branch/main/graph/badge.svg)](https://codecov.io/gh/Dashtid/DICOM-Fuzzer)
[![Tests](https://img.shields.io/badge/tests-1000%2B%20passing-brightgreen)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-69%25-green)](docs/COVERAGE.md)
[![Core Modules](https://img.shields.io/badge/core%20modules-11%2F13%20%40%2090%25%2B-brightgreen)](#test-coverage)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://python.org)
[![Code Style](https://img.shields.io/badge/code%20style-ruff-black)](https://github.com/astral-sh/ruff)
[![Security](https://img.shields.io/badge/security-bandit-yellow)](https://github.com/PyCQA/bandit)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

DICOM-Fuzzer is a comprehensive fuzzing framework for testing the security and robustness of DICOM-based medical imaging systems. It combines mutation-based fuzzing, grammar-aware fuzzing, and crash analysis to help identify vulnerabilities before they can be exploited.

**Target Use Cases:**

- Security testing of PACS (Picture Archiving and Communication Systems)
- Vulnerability assessment of medical imaging viewers
- Robustness testing of DICOM parsers and validators
- Compliance testing for medical device software
- Automated regression testing in CI/CD pipelines

## Key Features

### Fuzzing Capabilities

- **Mutation-Based Fuzzing**: Intelligent mutations of DICOM metadata, headers, and pixel data
- **Grammar-Based Fuzzing**: DICOM-aware mutations that understand protocol structure
- **Coverage-Guided Fuzzing**: Track code coverage to guide mutation strategies
- **Batch Processing**: Generate and test thousands of fuzzed files efficiently

### Crash Analysis & Reporting

- **Automatic Crash Detection**: Monitor target applications for crashes, hangs, and errors
- **Crash Deduplication**: Group similar crashes to identify unique vulnerabilities
- **Mutation Minimization**: Automatically find the minimal mutation set that triggers a crash
- **Comprehensive Reports**: Interactive HTML reports with full crash forensics

### Mutation Tracking

- **Complete Traceability**: Track every mutation from source file to crash
- **Session Management**: Organize fuzzing campaigns with detailed session logs
- **Artifact Preservation**: Automatically save crash samples and reproduction commands
- **DICOM Metadata Snapshots**: Compare original vs. fuzzed file metadata

## Project Structure

```
DICOM-Fuzzer/
├── dicom_fuzzer/              # Main package
│   ├── __init__.py            # Package exports
│   ├── __main__.py            # CLI entry point
│   ├── core/                  # Core fuzzing engine
│   │   ├── config.py          # Configuration management
│   │   ├── parser.py          # DICOM parsing
│   │   ├── generator.py       # Test case generation
│   │   ├── mutator.py         # Mutation engine
│   │   ├── validator.py       # DICOM validation
│   │   ├── fuzzing_session.py # Session tracking
│   │   ├── crash_analyzer.py  # Crash analysis
│   │   ├── crash_deduplication.py # Crash grouping
│   │   ├── reporter.py        # Report generation
│   │   ├── statistics.py      # Statistics tracking
│   │   ├── coverage_tracker.py # Code coverage
│   │   └── exceptions.py      # Exception hierarchy
│   ├── strategies/            # Mutation strategies
│   │   ├── header_fuzzer.py   # Header mutations
│   │   ├── metadata_fuzzer.py # Metadata mutations
│   │   └── pixel_fuzzer.py    # Pixel data mutations
│   ├── utils/                 # Utilities
│   │   ├── helpers.py         # Helper functions
│   │   ├── logger.py          # Logging utilities
│   │   └── dicom_dictionaries.py # DICOM dictionaries
│   └── cli/                   # CLI tools
│       ├── main.py            # Main CLI
│       ├── generate_report.py # Report generation
│       └── realtime_monitor.py # Live dashboard
├── tests/                     # Test suite (930+ tests)
├── examples/                  # Example scripts
│   ├── demo_fuzzing.py        # Basic fuzzing demo
│   ├── fuzz_dicom_viewer.py   # Viewer fuzzing example
│   └── coverage_guided_fuzzing_demo.py
├── demo/                      # Demonstration scripts
│   ├── README.md              # Demo documentation
│   ├── demo_simple.py         # Simple workflow demo
│   └── demo_workflow.py       # Full framework demo
├── artifacts/                 # Fuzzing outputs (gitignored)
│   ├── crashes/               # Crash files
│   ├── fuzzed/                # Fuzzed DICOM files
│   ├── corpus/                # Test corpus
│   └── reports/               # Generated reports
├── data/                      # Seed files & dictionaries
│   ├── seeds/                 # Seed DICOM files
│   └── dictionaries/          # Fuzzing dictionaries
├── docs/                      # Documentation
│   ├── COVERAGE.md            # Test coverage analysis
│   ├── FUZZING_GUIDE.md       # Fuzzing methodology
│   ├── TESTING.md             # Testing guide
│   └── REPORTING.md           # Reporting system
├── config/                    # Configuration
│   ├── local_paths.example.py # Path template
│   └── local_paths.py         # Local paths (gitignored)
├── scripts/                   # Build/deployment scripts
├── pyproject.toml             # Project configuration
├── requirements.txt           # Dependencies
├── CHANGELOG.md               # Version history
├── LICENSE                    # MIT License
└── README.md                  # This file
```

## Installation

### Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/DICOM-Fuzzer.git
cd DICOM-Fuzzer

# Install with uv (recommended)
uv venv
uv sync

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate
```

### Development Setup

```bash
# Install development dependencies
uv sync --dev

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=dicom_fuzzer --cov-report=html
```

## Usage

### Basic Fuzzing

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
# Reports saved to: ./reports/html/
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

## Configuration

### Local Paths (Not Tracked in Git)

Create `config/local_paths.py` for environment-specific paths:

```python
from pathlib import Path

# Test data location
DICOM_INPUT_DIR = Path(r"C:\Your\DICOM\Test\Data")

# Application under test
DICOM_VIEWER_PATH = Path(r"C:\Program Files\YourApp\viewer.exe")
VIEWER_TIMEOUT = 5
```

See `config/local_paths.example.py` for template.

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
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=dicom_fuzzer --cov-report=html

# Run specific test module
pytest tests/test_fuzzing_session.py -v

# View coverage report
start reports/coverage/htmlcov/index.html  # Windows
open reports/coverage/htmlcov/index.html   # macOS
```

### Test Coverage

**Overall Statistics:**

- **Total Tests**: 930+
- **Pass Rate**: 100%
- **Overall Coverage**: 69.12%
- **Core Modules at 90%+**: 11 out of 13

**Module Coverage:**

| Module                     | Coverage | Tests | Status       |
| -------------------------- | -------- | ----- | ------------ |
| **crash_deduplication.py** | 100%     | 29    | ✅ Perfect   |
| **crash_analyzer.py**      | 100%     | 26    | ✅ Perfect   |
| **generator.py**           | 100%     | 41    | ✅ Perfect   |
| **reporter.py**            | 100%     | 24    | ✅ Perfect   |
| **statistics.py**          | 100%     | 24    | ✅ Perfect   |
| **validator.py**           | 100%     | 59    | ✅ Perfect   |
| **exceptions.py**          | 100%     | -     | ✅ Perfect   |
| **types.py**               | 100%     | 8     | ✅ Perfect   |
| **fuzzing_session.py**     | 96.52%   | 41    | ✅ Excellent |
| **parser.py**              | 96.60%   | 57    | ✅ Excellent |
| **mutator.py**             | 94.67%   | 50    | ✅ Excellent |
| **corpus.py**              | 91.03%   | 24    | ✅ Excellent |

**New Test Files:**

- `tests/test_fuzzing_session_edge_cases.py` - 9 comprehensive edge case tests
- `tests/test_end_to_end_fuzzing.py` - 4 integration workflow tests

See [Test Coverage Documentation](#test-documentation) for detailed analysis.

## Documentation

- **[Fuzzing Guide](docs/FUZZING_GUIDE.md)** - Comprehensive fuzzing methodology
- **[Reporting System](docs/REPORTING.md)** - Report generation and analysis
- **[Coverage Analysis](docs/COVERAGE.md)** - Test coverage breakdown
- **[Project Structure](docs/STRUCTURE.md)** - Repository organization

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
4. Ensure all tests pass (`pytest tests/ -v`)
5. Ensure code quality (`black . && isort . && flake8`)
6. Commit with conventional commits (`git commit -m "feat: add crash signature hashing"`)
7. Push to your fork (`git push origin feature/crash-analyzer-improvements`)
8. Open a Pull Request

### Development Guidelines

- Write comprehensive tests for new features
- Follow Python best practices (PEP 8)
- Use type hints for better code clarity
- Document security implications
- Use atomic commits (one logical change per commit)
- Follow conventional commit format

See [.claude/CLAUDE.md](.claude/CLAUDE.md) for detailed development guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [pydicom](https://pydicom.github.io/) for DICOM parsing
- Uses [pynetdicom](https://pynetdicom.readthedocs.io/) for network operations
- Testing with [pytest](https://pytest.org/) and [hypothesis](https://hypothesis.readthedocs.io/)
- Code quality with [black](https://github.com/psf/black), [isort](https://pycqa.github.io/isort/), and [flake8](https://flake8.pycqa.org/)

## Disclaimer

This software is provided for educational and security testing purposes. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

## Project Status

**Current Phase**: Production-ready with comprehensive test coverage

**Recent Updates** (January 2025):

- ✅ **Test Coverage Milestone**: 11 out of 13 core modules at 90%+ coverage
- ✅ **8 Modules at 100% Coverage**: crash_analyzer, crash_deduplication, generator, reporter, statistics, validator, exceptions, types
- ✅ **Edge Case Testing**: Added comprehensive edge case tests for fuzzing_session.py (88% → 96.52%)
- ✅ **End-to-End Integration Tests**: Complete workflow testing from generation to reporting
- ✅ **Overall Coverage**: Improved from 28% to 69.12%
- ✅ **930+ Tests Passing**: Comprehensive test suite with integration tests

**Previous Updates**:

- Comprehensive fuzzing session tracking with full traceability
- Crash deduplication with multi-strategy similarity analysis
- Mutation minimization using delta debugging
- Interactive HTML reports with crash forensics
- Coverage correlation for guided fuzzing

**Next Steps**:

- Performance optimization and benchmarking
- Additional end-to-end workflow examples
- Documentation expansion with tutorials
- CI/CD pipeline enhancements

---

Developed for enhancing security and reliability in healthcare technology.
