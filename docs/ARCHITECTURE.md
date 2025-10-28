# DICOM Fuzzer Architecture

Technical architecture and design documentation for DICOM Fuzzer.

## Table of Contents

- [System Overview](#system-overview)
- [Architecture Principles](#architecture-principles)
- [Module Organization](#module-organization)
- [Core Components](#core-components)
- [Data Flow](#data-flow)
- [Testing Architecture](#testing-architecture)
- [Performance Considerations](#performance-considerations)
- [Extensibility](#extensibility)
- [Future Roadmap](#future-roadmap)

---

## System Overview

DICOM Fuzzer is a modular, extensible security testing framework designed specifically for DICOM (Digital Imaging and Communications in Medicine) implementations. The system employs multiple fuzzing strategies, crash intelligence, and coverage-guided techniques to identify vulnerabilities in medical imaging software.

### Design Goals

1. **Modularity**: Loosely coupled components with clear interfaces
2. **Extensibility**: Easy addition of new mutation strategies and features
3. **Performance**: Efficient fuzzing with minimal overhead
4. **Safety**: Built-in protections for PHI and system resources
5. **Observability**: Comprehensive logging and reporting

### Technology Stack

- **Language**: Python 3.11+
- **Core Libraries**:
  - **pydicom**: DICOM file parsing and manipulation
  - **structlog**: Structured logging
  - **pytest**: Testing framework with Hypothesis for property-based testing
- **Development Tools**:
  - **uv**: Modern package manager
  - **Ruff**: Fast linting and formatting
  - **mypy**: Static type checking
  - **Bandit**: Security vulnerability scanning

---

## Architecture Principles

### 1. Separation of Concerns

Each module has a single, well-defined responsibility:

```
[Parser] → [Mutator] → [Generator] → [Validator] → [Reporter]
   ↓           ↓            ↓             ↓            ↓
 Read DICOM  Transform   Create Files  Validate    Generate Reports
```

### 2. Dependency Inversion

High-level modules depend on abstractions, not concrete implementations:

```python
# Abstract base class
class MutationStrategy(ABC):
    @abstractmethod
    def mutate(self, dataset: Dataset) -> Dataset:
        pass

# Concrete implementations
class MetadataMutator(MutationStrategy): ...
class PixelMutator(MutationStrategy): ...
```

### 3. Composition Over Inheritance

Favor composition for flexibility:

```python
class Mutator:
    def __init__(self):
        self.strategies: list[MutationStrategy] = []

    def register_strategy(self, strategy: MutationStrategy):
        self.strategies.append(strategy)
```

### 4. Fail-Safe Defaults

Security-conscious defaults throughout:

```python
DEFAULT_FILE_SIZE_LIMIT = 100 * 1024 * 1024  # 100MB
DEFAULT_VALIDATION_MODE = ValidationMode.STRICT
DEFAULT_PHI_REDACTION = True
```

---

## Module Organization

### Directory Structure

```
dicom-fuzzer/
├── dicom_fuzzer/           # Main package
│   ├── analytics/          # Campaign analytics and visualization
│   ├── cli/                # Command-line interfaces
│   ├── core/               # Core fuzzing logic (57 modules)
│   ├── harness/            # Test harness and execution
│   ├── strategies/         # Mutation strategy implementations
│   └── utils/              # Utility functions and helpers
├── tests/                  # Test suite (118 test files, 2,591 tests)
├── examples/               # Example scripts and demos
├── docs/                   # Documentation
└── reports/                # Generated reports (gitignored)
```

### Module Count

- **Total Source Files**: 70 Python modules (~24,000 LOC)
- **Core Modules**: 57 files (largest subsystem)
- **Test Files**: 118 files (~15,000 LOC)
- **Test Coverage**: 56.10% overall (excellent for fuzzing tool)

---

## Core Components

### 1. Parser Module (`core/parser.py`)

**Responsibility**: DICOM file parsing and metadata extraction

**Key Features**:

- Pydicom integration for DICOM reading
- Metadata extraction (patient, study, series, equipment)
- Pixel data handling
- Transfer syntax detection
- Security validation (file size limits, path validation)

**Example**:

```python
parser = DicomParser(max_file_size_mb=100)
dataset = parser.parse_file(Path("sample.dcm"))
metadata = parser.extract_metadata(dataset)
```

### 2. Mutator Module (`core/mutator.py`)

**Responsibility**: Apply fuzzing mutations to DICOM datasets

**Key Features**:

- Strategy registration and management
- Mutation severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Session lifecycle management
- Mutation tracking and recording
- Safety checks and validation

**Architecture**:

```
Mutator
├── MutationStrategy (ABC)
│   ├── MetadataMutator
│   ├── PixelMutator
│   ├── HeaderMutator
│   ├── StructureMutator
│   └── [Custom Strategies...]
└── MutationSession
    └── MutationRecord[]
```

### 3. Generator Module (`core/generator.py`)

**Responsibility**: Generate fuzzed DICOM files in batch

**Key Features**:

- Batch file generation
- Unique filename generation (`fuzzed_<hex>.dcm`)
- Directory management
- Integration with mutator

### 4. Validator Module (`core/validator.py`)

**Responsibility**: Validate DICOM compliance and security

**Key Features**:

- DICOM standard compliance checking
- Security validation (null bytes, buffer overflow, DoS detection)
- Required tags validation
- Structure validation
- Batch validation with fail-fast/continue options

**Validation Layers**:

```
[Security Validation]
    ↓
[DICOM Compliance]
    ↓
[Structure Validation]
    ↓
[Custom Rules]
```

### 5. Crash Analyzer (`core/crash_analyzer.py`)

**Responsibility**: Analyze and triage crashes

**Key Features**:

- Crash detection and collection
- Stack trace analysis
- Crash type classification
- Severity assessment

### 6. Crash Deduplication (`core/crash_deduplication.py`)

**Responsibility**: Deduplicate crash reports

**Key Features**:

- Stack hash-based deduplication
- Crash fingerprinting
- Unique crash identification

### 7. Mutation Minimization (`core/mutation_minimization.py`)

**Responsibility**: Minimize crash-inducing test cases

**Key Features**:

- Delta debugging algorithm
- Binary search minimization
- Crash reproduction verification

### 8. Coverage Tracker (`core/coverage_tracker.py`)

**Responsibility**: Track code coverage during fuzzing

**Key Features**:

- Coverage instrumentation
- Path discovery
- Coverage-guided mutation selection

### 9. Fuzzing Session (`core/fuzzing_session.py`)

**Responsibility**: Manage fuzzing campaign lifecycle

**Key Features**:

- Session state management
- Artifact preservation
- Statistics collection
- Progress tracking

### 10. Enhanced Reporter (`core/enhanced_reporter.py`)

**Responsibility**: Generate comprehensive HTML reports

**Key Features**:

- HTML report generation
- Campaign statistics
- Crash summaries
- Coverage visualization

---

## Data Flow

### Basic Fuzzing Workflow

```
1. Input
   ├── DICOM File (*.dcm)
   └── Configuration (strategies, count, severity)
        ↓
2. Parsing
   ├── DicomParser.parse_file()
   └── Metadata extraction
        ↓
3. Mutation
   ├── Mutator.mutate()
   ├── Strategy selection
   └── Apply mutations
        ↓
4. Generation
   ├── Generator.generate_batch()
   └── Save fuzzed files
        ↓
5. Validation
   ├── Validator.validate()
   └── Security checks
        ↓
6. Reporting
   ├── Reporter.generate_report()
   └── HTML/JSON output
```

### Coverage-Guided Fuzzing Workflow

```
1. Initialize
   ├── Load corpus
   └── Instrument target binary
        ↓
2. Fuzz Loop
   ├── Select input from corpus
   ├── Mutate input
   ├── Execute target
   ├── Track coverage
   ├── Detect crashes
   └── Update corpus (if new path found)
        ↓
3. Crash Analysis
   ├── Deduplicate crashes
   ├── Minimize test cases
   └── Triage by severity
        ↓
4. Report Generation
   ├── Coverage statistics
   ├── Crash summaries
   └── Corpus insights
```

### 3D Series Fuzzing Workflow

```
1. Series Detection
   ├── SeriesDetector.detect_series()
   └── Group slices by SeriesInstanceUID
        ↓
2. Series Validation
   ├── Validate slice ordering
   └── Check slice spacing
        ↓
3. Series Mutation
   ├── Apply 3D-specific mutations
   │   ├── Slice order manipulation
   │   ├── Slice spacing modification
   │   └── Orientation changes
   └── Maintain series integrity
        ↓
4. Output Generation
   └── Write fuzzed series to directory
```

---

## Testing Architecture

### Test Organization

```
tests/
├── analytics/          # Analytics module tests
├── cli/                # CLI tests
├── core/               # Core module tests
├── integration/        # Integration tests
├── strategies/         # Strategy tests
├── utils/              # Utility tests
├── conftest.py         # Shared fixtures
└── test_helpers.py     # Test utilities
```

### Test Categories

1. **Unit Tests** (~2,400 tests)
   - Test individual functions and classes
   - Mock external dependencies
   - Fast execution (<1s per test)

2. **Integration Tests** (~100 tests)
   - Test end-to-end workflows
   - Use real DICOM files
   - Test cross-module interactions

3. **Property-Based Tests** (Hypothesis)
   - Generate hundreds of test cases automatically
   - Test invariants and properties
   - Find edge cases

4. **Security Tests**
   - Test attack vector detection
   - Verify PHI redaction
   - Validate input sanitization

### Testing Patterns

**Fixture Pattern**:

```python
@pytest.fixture
def sample_dicom_file(tmp_path):
    """Provide a valid DICOM file for testing."""
    file_path = tmp_path / "sample.dcm"
    # Create minimal DICOM
    return file_path

def test_parser(sample_dicom_file):
    parser = DicomParser()
    dataset = parser.parse_file(sample_dicom_file)
    assert dataset is not None
```

**Mock Pattern**:

```python
def test_mutator_with_mock():
    mock_strategy = Mock(spec=MutationStrategy)
    mock_strategy.mutate.return_value = Mock()

    mutator = Mutator()
    mutator.register_strategy(mock_strategy)

    mutator.mutate(dataset)
    mock_strategy.mutate.assert_called_once()
```

---

## Performance Considerations

### Optimization Strategies

1. **Lazy Loading**: Load heavy modules on-demand

   ```python
   # dicom_fuzzer/core/lazy_loader.py
   def lazy_import(module_name):
       return importlib.import_module(module_name)
   ```

2. **Caching**: Cache parsed DICOM datasets

   ```python
   @lru_cache(maxsize=128)
   def parse_cached(file_path):
       return pydicom.dcmread(file_path)
   ```

3. **Batch Processing**: Process multiple files in parallel

   ```python
   with ThreadPoolExecutor(max_workers=4) as executor:
       results = executor.map(fuzz_file, input_files)
   ```

4. **Resource Limits**: Prevent resource exhaustion

   ```python
   # File size limits
   MAX_FILE_SIZE = 100 * 1024 * 1024

   # Memory limits
   resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
   ```

### Performance Metrics

| Operation         | Throughput            | Notes                         |
| ----------------- | --------------------- | ----------------------------- |
| Parse DICOM       | ~500 files/sec        | Small files (<1MB)            |
| Metadata Mutation | ~1000 mutations/sec   | Lightweight                   |
| Pixel Mutation    | ~50-100 mutations/sec | Heavy (depends on image size) |
| File Generation   | ~200 files/sec        | I/O bound                     |

---

## Extensibility

### Adding Custom Mutation Strategies

1. **Create Strategy Class**:

   ```python
   from dicom_fuzzer.core.mutator import MutationStrategy

   class CustomMutator(MutationStrategy):
       name = "custom"
       severity = MutationSeverity.MEDIUM

       def mutate(self, dataset):
           # Custom mutation logic
           return dataset
   ```

2. **Register Strategy**:
   ```python
   mutator = Mutator()
   mutator.register_strategy(CustomMutator())
   ```

### Plugin Architecture (Future)

Planned plugin system for extensibility:

```python
# plugins/my_plugin.py
from dicom_fuzzer.plugin import Plugin

class MyPlugin(Plugin):
    def on_session_start(self, session):
        pass

    def on_mutation(self, dataset):
        pass

    def on_crash(self, crash_info):
        pass
```

---

## Future Roadmap

### Phase 4: Advanced Features (Planned)

1. **Distributed Fuzzing**
   - Multi-node fuzzing architecture
   - Centralized corpus management
   - Distributed crash collection

2. **Machine Learning Integration**
   - ML-guided mutation selection
   - Predictive crash detection
   - Coverage prediction

3. **Real-Time Dashboard**
   - Live fuzzing campaign monitoring
   - WebSocket-based updates
   - Interactive crash analysis

4. **Advanced Grammar Fuzzing**
   - DICOM grammar extraction
   - Context-free grammar fuzzing
   - Structure-aware mutations

### Phase 5: Enterprise Features (Planned)

1. **Multi-User Support**
   - User authentication
   - Role-based access control
   - Campaign sharing

2. **API Server**
   - RESTful API
   - Fuzzing-as-a-Service
   - Remote campaign management

3. **Compliance Reporting**
   - HIPAA compliance reports
   - FDA cybersecurity guidance alignment
   - EU MDR compliance documentation

---

## Design Patterns Used

### Creational Patterns

- **Factory Pattern**: Strategy creation
- **Builder Pattern**: Complex object construction (reports, sessions)
- **Singleton Pattern**: Global configuration

### Structural Patterns

- **Adapter Pattern**: External tool integration
- **Facade Pattern**: Simplified API for complex subsystems
- **Composite Pattern**: Nested sequence handling

### Behavioral Patterns

- **Strategy Pattern**: Mutation strategies
- **Observer Pattern**: Event notification (crashes, coverage)
- **Command Pattern**: CLI commands

---

## Security Architecture

### Defense in Depth

```
Layer 1: Input Validation
    ├── File size limits
    ├── Path sanitization
    └── DICOM structure validation
         ↓
Layer 2: Attack Detection
    ├── Null byte detection
    ├── Buffer overflow detection
    └── DoS pattern detection
         ↓
Layer 3: Data Protection
    ├── PHI redaction
    ├── Sensitive data masking
    └── Secure logging
         ↓
Layer 4: Sandboxing (Recommended)
    ├── Virtual machines
    ├── Containers
    └── Isolated networks
```

### Security Design Principles

1. **Principle of Least Privilege**: Minimal permissions required
2. **Defense in Depth**: Multiple security layers
3. **Fail Secure**: Fail closed on errors
4. **Secure by Default**: Security-conscious defaults
5. **Privacy by Design**: PHI protection built-in

---

## Dependencies

### Core Dependencies

```toml
[project.dependencies]
python = "^3.11"
pydicom = "^2.4.0"          # DICOM file handling
structlog = "^24.1.0"        # Structured logging
numpy = "^1.26.0"            # Numerical operations
click = "^8.1.0"             # CLI framework
```

### Development Dependencies

```toml
[project.optional-dependencies]
dev = [
    "pytest ^8.0.0",          # Testing framework
    "pytest-cov ^5.0.0",      # Coverage reporting
    "hypothesis ^6.98.0",     # Property-based testing
    "ruff ^0.3.0",            # Linting and formatting
    "mypy ^1.9.0",            # Type checking
    "bandit ^1.7.0",          # Security scanning
    "pre-commit ^3.6.0",      # Git hooks
]
```

---

## Contributing to Architecture

When proposing architectural changes:

1. **Document Design Decisions**: Use ADRs (Architecture Decision Records)
2. **Maintain Modularity**: Keep components loosely coupled
3. **Update Documentation**: Keep this document current
4. **Add Tests**: Include tests for new components
5. **Consider Backwards Compatibility**: Minimize breaking changes

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

---

## References

- **DICOM Standard**: https://www.dicomstandard.org/
- **Fuzzing Techniques**: https://lcamtuf.coredump.cx/afl/
- **Python Design Patterns**: https://refactoring.guru/design-patterns/python

---

**Last Updated**: October 27, 2025
**Version**: 1.2.0

For questions about architecture, open a GitHub issue or discussion.
