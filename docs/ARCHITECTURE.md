# DICOM Fuzzer Architecture

## Overview

Modular security testing framework for DICOM implementations using mutation-based, coverage-guided, and protocol-aware fuzzing.

**Design Goals:** Modularity, Extensibility, Performance, Safety, Observability

**Stack:** Python 3.11+, pydicom, structlog, pytest/Hypothesis

## Module Organization

```text
dicom-fuzzer/
├── dicom_fuzzer/           # Main package
│   ├── cli/                # Command-line interfaces
│   ├── core/               # Core fuzzing logic (57 modules)
│   ├── strategies/         # Mutation strategy implementations
│   ├── analytics/          # Campaign analytics
│   └── utils/              # Utility functions
├── tests/                  # Test suite (2,500+ tests, 89% coverage)
├── tools/                  # Scripts, examples, generators
├── configs/                # Docker, targets, seeds
└── docs/                   # Documentation
```

## Core Components

| Component      | File                            | Purpose                                     |
| -------------- | ------------------------------- | ------------------------------------------- |
| Parser         | `core/parser.py`                | DICOM parsing, metadata extraction          |
| Mutator        | `core/mutator.py`               | Strategy registration, mutation application |
| Generator      | `core/generator.py`             | Batch fuzzed file generation                |
| Validator      | `core/validator.py`             | DICOM compliance, security validation       |
| Crash Analyzer | `core/crash_analyzer.py`        | Crash detection, stack analysis, triage     |
| Crash Dedup    | `core/crash_deduplication.py`   | Hash-based crash deduplication              |
| Minimizer      | `core/mutation_minimization.py` | Delta debugging for test cases              |
| Coverage       | `core/coverage_tracker.py`      | Coverage-guided mutation selection          |
| Session        | `core/fuzzing_session.py`       | Campaign lifecycle, statistics              |
| Reporter       | `core/enhanced_reporter.py`     | HTML/JSON report generation                 |
| Network        | `core/network_fuzzer.py`        | DICOM protocol fuzzing (C-STORE, C-ECHO)    |
| Security       | `core/security_fuzzer.py`       | CVE patterns, exploit payloads              |
| GUI Monitor    | `core/gui_monitor.py`           | Process monitoring, crash screenshots       |

## Data Flow

```text
Input (DICOM + Config)
    ↓
Parsing (DicomParser)
    ↓
Mutation (Strategy Selection → Apply)
    ↓
Generation (Batch Write)
    ↓
Validation (Security + Compliance)
    ↓
Reporting (HTML/JSON)
```

### Coverage-Guided Flow

```text
Corpus → Mutate → Execute Target → Track Coverage → Detect Crashes
                        ↓
              New path? → Add to corpus
                        ↓
              Crash? → Deduplicate → Minimize → Triage
```

## Strategy Architecture

Strategies implement the `MutationStrategy` abstract base class:

```python
class MutationStrategy(ABC):
    @abstractmethod
    def mutate(self, dataset: Dataset) -> Dataset:
        pass
```

**Built-in strategies:** metadata, pixel, header, structure, transfer_syntax, sequence, series, study, calibration, cve_patterns

Register custom strategies:

```python
mutator = Mutator()
mutator.register_strategy(CustomMutator())
```

## Security Layers

```text
Layer 1: Input Validation (size limits, path sanitization)
Layer 2: Attack Detection (null bytes, buffer overflow, DoS)
Layer 3: Data Protection (PHI redaction, secure logging)
Layer 4: Sandboxing (containers/VMs recommended)
```

## Extending

1. Subclass `MutationStrategy`
2. Implement `mutate()` method
3. Register with mutator

See [strategies/](../dicom_fuzzer/strategies/) for examples.
