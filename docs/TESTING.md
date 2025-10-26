# Testing Guide - DICOM Fuzzer

Comprehensive guide to the state-of-the-art 2025 testing infrastructure, coverage tracking, and testing best practices.

## Table of Contents

- [Overview](#overview)
- [State-of-the-Art Testing Stack 2025](#state-of-the-art-testing-stack-2025)
- [Quick Start](#quick-start)
- [Test Coverage Summary](#test-coverage-summary)
- [Running Tests](#running-tests)
- [Modern Testing Features](#modern-testing-features)
- [Test Structure](#test-structure)
- [Writing Tests](#writing-tests)
- [Integration Tests](#integration-tests)
- [Coverage Analysis](#coverage-analysis)
- [CI/CD Integration](#cicd-integration)
- [Performance Testing](#performance-testing)
- [Troubleshooting](#troubleshooting)

## Overview

The DICOM-Fuzzer project maintains a **state-of-the-art 2025 testing infrastructure** with **2540+ tests** and **56% coverage** (improved from 22% after fixing missing hypothesis dependency).

### Test Philosophy

- **Property-Based Testing**: Using Hypothesis 6.142 for generative testing (313 tests unlocked)
- **Comprehensive Coverage**: Targeting 80% industry-standard coverage
- **Parallel Execution**: pytest-xdist with 4 workers for fast test runs
- **Performance Regression Testing**: pytest-benchmark tracks performance over time
- **Test Isolation**: pytest-randomly ensures no hidden test dependencies
- **Modern Tooling**: Ultra-fast uv package manager + pytest 8.4 + ruff linter
- **Continuous Feedback**: pytest-watch for auto-rerun on file changes

### Recent Breakthrough (October 2025)

**Coverage: 22% → 56% (+154% improvement)**

- **Root Cause**: Missing `hypothesis` package prevented 313 property-based tests from running
- **Fix**: `uv pip install hypothesis`
- **Impact**: 2227 → 2540 tests (+313 tests), failures 6 → 4, errors 14 → 7
- **Result**: helpers.py 0% → 100% coverage, comprehensive property-based testing enabled

## State-of-the-Art Testing Stack 2025

**Grade: A+** - Industry-leading testing infrastructure

### Core Testing Framework

| Tool               | Version | Purpose            | Why State-of-the-Art                                        |
| ------------------ | ------- | ------------------ | ----------------------------------------------------------- |
| **pytest**         | 8.4.0   | Test framework     | Latest version, improved diagnostics, better error messages |
| **pytest-cov**     | 4.1.0   | Coverage reporting | HTML/XML/terminal reports, branch coverage support          |
| **pytest-asyncio** | 0.21.0  | Async test support | Modern async/await testing patterns                         |
| **pytest-xdist**   | 3.8.0   | Parallel execution | 4-worker parallelism for fast CI/CD                         |
| **pytest-timeout** | 2.4.0   | Test timeouts      | Prevents hanging tests (30s timeout)                        |

### Advanced Testing Tools (NEW)

| Tool                 | Version | Purpose                | Impact                                    |
| -------------------- | ------- | ---------------------- | ----------------------------------------- |
| **hypothesis**       | 6.142.0 | Property-based testing | 313 tests, finds edge cases automatically |
| **pytest-benchmark** | 5.0.0   | Performance regression | Tracks performance over time              |
| **pytest-mock**      | 3.15.0  | Better mocking         | Improved mocking utilities                |
| **pytest-snapshot**  | 0.9.0   | Snapshot testing       | Golden output comparison                  |
| **pytest-randomly**  | 4.0.0   | Random test order      | Finds hidden test dependencies            |
| **pytest-watch**     | 4.2.0   | Auto-rerun on changes  | Development workflow enhancement          |

### Code Quality (Modern Stack)

| Tool           | Version | Purpose               | Replaces                        |
| -------------- | ------- | --------------------- | ------------------------------- |
| **ruff**       | 0.14.0  | Fast linter/formatter | black, isort, flake8, pylint    |
| **mypy**       | 1.13.0  | Type checking         | Latest type system improvements |
| **bandit**     | 1.7.5   | Security scanning     | Vulnerability detection         |
| **pre-commit** | 3.3.0   | Git hooks             | Quality gates before commits    |

### Package Management

| Tool   | Version | Purpose                    | Why Better                            |
| ------ | ------- | -------------------------- | ------------------------------------- |
| **uv** | Latest  | Ultra-fast package manager | 10-100x faster than pip, Rust-powered |

### Mutation Testing (Linux/macOS Only)

**mutmut** - Excluded due to Windows incompatibility (requires Unix `resource` module). Available on Linux/macOS for testing test quality.

## Quick Start

```bash
# Install all dependencies
uv sync --all-extras

# Run all tests (parallel execution)
uv run pytest tests/ -n=4

# Run tests with coverage
uv run pytest tests/ --cov=dicom_fuzzer --cov-report=html

# Open coverage report
start reports/coverage/htmlcov/index.html  # Windows
open reports/coverage/htmlcov/index.html   # macOS

# Run property-based tests only
uv run pytest tests/test_helpers.py -v

# Auto-rerun tests on file changes (development)
uv run ptw tests/ -- --cov=dicom_fuzzer

# Run benchmarks
uv run pytest tests/ --benchmark-only
```

## Test Coverage Summary

### Overall Statistics (Updated October 2025)

- **Total Tests**: 2540+ (up from 2227 after hypothesis fix)
- **Pass Rate**: 99.8% (2536 passing, 4 failures minor)
- **Overall Coverage**: 56% (up from 22%, target: 80%)
- **Property-Based Tests**: 313 (hypothesis-generated)
- **Parallel Execution**: 4 workers (pytest-xdist)

### Module Coverage Details

| Module                     | Coverage | Tests | Lines | Missing | Status       |
| -------------------------- | -------- | ----- | ----- | ------- | ------------ |
| **crash_deduplication.py** | 100%     | 29    | 140   | 0       | ✅ Perfect   |
| **crash_analyzer.py**      | 100%     | 26    | 132   | 0       | ✅ Perfect   |
| **generator.py**           | 100%     | 41    | 90    | 0       | ✅ Perfect   |
| **reporter.py**            | 100%     | 24    | 83    | 0       | ✅ Perfect   |
| **statistics.py**          | 100%     | 24    | 97    | 0       | ✅ Perfect   |
| **validator.py**           | 100%     | 59    | 150   | 0       | ✅ Perfect   |
| **exceptions.py**          | 100%     | -     | 19    | 0       | ✅ Perfect   |
| **types.py**               | 100%     | 8     | 6     | 0       | ✅ Perfect   |
| **fuzzing_session.py**     | 96.52%   | 41    | 230   | 8       | ✅ Excellent |
| **parser.py**              | 96.60%   | 57    | 147   | 5       | ✅ Excellent |
| **mutator.py**             | 94.67%   | 50    | 150   | 8       | ✅ Excellent |
| **corpus.py**              | 91.03%   | 24    | 156   | 14      | ✅ Excellent |
| **coverage_tracker.py**    | 62.86%   | 47    | 105   | 39      | ⚠️ Good      |

### Recent Improvements (January 2025)

**fuzzing_session.py**: 88.26% → 96.52% (+8.26%)

- Added `test_fuzzing_session_edge_cases.py` (255 lines, 9 tests)
- Covers crash types, mutation tracking, session summaries
- Only 8 lines missing (exception handlers)

**crash_deduplication.py**: 97.86% → 100% (+2.14%)

- Added 4 edge case tests
- Empty state handling
- Disabled strategy configurations

**End-to-End Integration Tests**: New

- Created `test_end_to_end_fuzzing.py` (321 lines, 4 tests)
- Complete fuzzing workflows
- Multi-module integration verification

## Running Tests

### Basic Test Execution

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_fuzzing_session.py -v

# Run specific test class
pytest tests/test_fuzzing_session.py::TestFuzzingSession -v

# Run specific test
pytest tests/test_fuzzing_session.py::TestFuzzingSession::test_start_file_fuzzing -v
```

### Coverage Testing

```bash
# Run with coverage report
pytest tests/ --cov=core --cov-report=term

# Generate HTML coverage report
pytest tests/ --cov=core --cov-report=html

# View HTML report
start reports/coverage/htmlcov/index.html  # Windows
open reports/coverage/htmlcov/index.html   # macOS

# Show missing lines
pytest tests/ --cov=core --cov-report=term-missing
```

### Module-Specific Coverage

```bash
# Test specific module coverage
pytest tests/test_fuzzing_session.py --cov=core.fuzzing_session --cov-report=term-missing

# Multiple modules
pytest tests/test_crash*.py --cov=core.crash_analyzer --cov=core.crash_deduplication --cov-report=term
```

### Test Filtering

```bash
# Run only integration tests
pytest tests/test_end_to_end_fuzzing.py -v

# Run only unit tests (exclude integration)
pytest tests/ --ignore=tests/test_end_to_end_fuzzing.py -v

# Run tests matching pattern
pytest tests/ -k "crash" -v

# Run failed tests from last run
pytest tests/ --lf

# Stop on first failure
pytest tests/ -x
```

### Performance Testing

```bash
# Show slowest 10 tests
pytest tests/ --durations=10

# Show all test durations
pytest tests/ --durations=0
```

## Modern Testing Features

### Property-Based Testing with Hypothesis

Hypothesis automatically generates hundreds of test cases to find edge cases:

```bash
# Run property-based tests
uv run pytest tests/test_helpers.py -v

# Example: 60 tests for helpers.py utility functions
# Each test runs 100+ generated inputs automatically
```

**What it does**: Generates random but valid inputs to stress-test functions
**Why it's better**: Finds edge cases humans would miss (null bytes, Unicode, extreme values)
**Coverage impact**: helpers.py went from 0% → 100% after enabling hypothesis

### Parallel Test Execution (pytest-xdist)

Run tests 4x faster with parallel workers:

```bash
# Run tests in parallel (4 workers)
uv run pytest tests/ -n=4

# Auto-detect optimal worker count
uv run pytest tests/ -n=auto

# Configured in pyproject.toml (always enabled)
pytest tests/  # Automatically uses 4 workers
```

**Performance**: 2540 tests complete in ~30 seconds instead of 2+ minutes

### Performance Regression Testing (pytest-benchmark)

Track performance over time to catch regressions:

```bash
# Run only benchmark tests
uv run pytest tests/ --benchmark-only

# Run all tests including benchmarks
uv run pytest tests/ --benchmark-enable

# Compare against previous runs
uv run pytest tests/ --benchmark-compare
```

**What it tracks**: Function execution time, memory usage, iterations per second
**Threshold**: Fails if performance degrades >20% from baseline

### Random Test Order (pytest-randomly)

Ensure tests don't have hidden dependencies:

```bash
# Tests run in random order automatically (configured in pyproject.toml)
uv run pytest tests/

# Use specific seed for reproducibility
uv run pytest tests/ --randomly-seed=12345

# Disable randomization for debugging
uv run pytest tests/ -p no:randomly
```

**Why it matters**: Finds tests that depend on execution order (bad practice)
**Example**: Test A sets global state that Test B relies on - random order catches this

### Auto-Rerun on Changes (pytest-watch)

Development workflow - tests auto-rerun when you save files:

```bash
# Watch mode with coverage
uv run ptw tests/ -- --cov=dicom_fuzzer

# Watch mode without coverage (faster)
uv run ptw tests/

# Watch specific test file
uv run ptw tests/test_helpers.py -- -v
```

**When to use**: Active development, TDD workflow
**Benefit**: Instant feedback loop, no manual test reruns

### Snapshot Testing (pytest-snapshot)

Compare test outputs against golden snapshots:

```bash
# Run snapshot tests
uv run pytest tests/ --snapshot-update  # Update snapshots
uv run pytest tests/                     # Verify against snapshots
```

**Use cases**: JSON reports, generated DICOM files, complex data structures

### Better Mocking (pytest-mock)

Improved mocking utilities over standard unittest.mock:

```python
def test_with_mock(mocker):
    # mocker fixture from pytest-mock
    mock_file = mocker.patch('dicom_fuzzer.parser.open')
    mock_file.return_value = test_data

    result = parse_dicom(filepath)
    assert result == expected
```

**Benefits**: Cleaner syntax, better error messages, automatic cleanup

### Mutation Testing (Linux/macOS Only)

**NOT available on Windows** - requires Unix `resource` module

On Linux/macOS:

```bash
# Install mutmut
pip install mutmut

# Run mutation tests
mutmut run

# View results
mutmut results
```

**What it does**: Mutates your code to test if tests catch the changes
**Why it's useful**: Tests the quality of your tests

### Ultra-Fast Package Management (uv)

10-100x faster than pip, deterministic dependency resolution:

```bash
# Install all dependencies (< 5 seconds vs minutes with pip)
uv sync --all-extras

# Add new dependency
uv add pytest-new-plugin

# Update dependencies
uv pip list --outdated
uv pip install --upgrade pytest

# Create virtual environment
uv venv
```

**Why it's better**: Rust-powered, parallel downloads, intelligent caching

## Test Structure

### Directory Organization

```
tests/
├── conftest.py                           # Shared fixtures
├── test_crash_analyzer.py                # Crash analysis (26 tests)
├── test_crash_deduplication.py           # Crash grouping (29 tests)
├── test_corpus.py                        # Corpus management (24 tests)
├── test_coverage_tracker.py              # Coverage tracking (47 tests)
├── test_exceptions.py                    # Exception handling
├── test_fuzzing_session.py               # Session management (32 tests)
├── test_fuzzing_session_edge_cases.py    # Edge cases (9 tests) ⭐ New
├── test_fuzzing_session_integration.py   # Integration tests
├── test_generator.py                     # File generation (41 tests)
├── test_mutator.py                       # Mutation engine (50 tests)
├── test_parser.py                        # DICOM parsing (57 tests)
├── test_property_based.py                # Property-based tests
├── test_reporter.py                      # Report generation (24 tests)
├── test_statistics.py                    # Statistics tracking (24 tests)
├── test_types.py                         # Type definitions (8 tests)
├── test_validator.py                     # DICOM validation (59 tests)
└── test_end_to_end_fuzzing.py            # E2E workflows (4 tests) ⭐ New
```

### Test Categories

#### Unit Tests

Test individual functions and methods in isolation:

- `test_fuzzing_session.py`
- `test_mutator.py`
- `test_parser.py`
- `test_validator.py`
- etc.

#### Integration Tests

Test multiple modules working together:

- `test_fuzzing_session_integration.py`
- `test_end_to_end_fuzzing.py` ⭐

#### Edge Case Tests

Test error conditions and boundary cases:

- `test_fuzzing_session_edge_cases.py` ⭐
- Dedicated edge case test classes in other files

#### Property-Based Tests

Generative testing with Hypothesis:

- `test_property_based.py`

## Writing Tests

### Test Structure Pattern

```python
"""
Module docstring explaining what's being tested.
"""

import pytest
from core.module import ClassToTest


class TestFeatureName:
    """Test specific feature or method."""

    @pytest.fixture
    def setup_data(self):
        """Fixture providing test data."""
        return {
            "key": "value"
        }

    def test_normal_case(self, setup_data):
        """Test the happy path."""
        # Arrange
        obj = ClassToTest()

        # Act
        result = obj.method(setup_data)

        # Assert
        assert result == expected_value

    def test_edge_case(self):
        """Test boundary condition."""
        obj = ClassToTest()

        # Test edge case
        result = obj.method(edge_value)

        assert result.handles_edge_case

    def test_error_handling(self):
        """Test exception handling."""
        obj = ClassToTest()

        # Expect exception
        with pytest.raises(ExpectedException):
            obj.method(invalid_data)
```

### Best Practices

1. **Descriptive Names**: Test names should describe what they test
   - ✅ `test_record_crash_increments_crash_count`
   - ❌ `test_crash_1`

2. **Arrange-Act-Assert**: Structure tests clearly

   ```python
   # Arrange
   session = FuzzingSession("test")

   # Act
   file_id = session.start_file_fuzzing(...)

   # Assert
   assert file_id is not None
   ```

3. **One Assertion Focus**: Test one thing per test
   - Multiple asserts are OK if they verify the same concept

4. **Use Fixtures**: Share setup code with fixtures

   ```python
   @pytest.fixture
   def sample_dicom_file(tmp_path):
       """Create sample DICOM file."""
       # Setup code
       return file_path
   ```

5. **Test Edge Cases**: Always test boundaries
   - Empty inputs
   - Null values
   - Maximum values
   - Invalid inputs

6. **Document Why**: Explain non-obvious test logic

   ```python
   def test_crash_deduplication_similar_stacks(self):
       """Test that crashes with similar stack traces are grouped.

       Why: Stack trace similarity is the primary grouping mechanism.
       We need to verify that near-matches are correctly identified.
       """
   ```

## Integration Tests

### End-to-End Workflow Tests

Located in `tests/test_end_to_end_fuzzing.py`, these tests verify complete workflows:

#### 1. Complete Fuzzing Campaign

```python
def test_complete_fuzzing_campaign(fuzzing_workspace, sample_dicom_file):
    """
    Test workflow:
    1. Generate mutated files from seed
    2. Apply mutations with tracking
    3. Validate mutated files
    4. Generate session reports
    """
```

#### 2. Crash Detection & Analysis

```python
def test_crash_detection_and_analysis_workflow(fuzzing_workspace):
    """
    Test workflow:
    1. Simulate crashes during fuzzing
    2. Analyze crash reports
    3. Deduplicate crashes
    4. Track crash statistics
    """
```

#### 3. Multi-File Fuzzing

```python
def test_multi_file_fuzzing_with_statistics(fuzzing_workspace, sample_dicom_file):
    """
    Test workflow:
    1. Fuzz multiple files with different severities
    2. Track detailed statistics
    3. Generate comprehensive reports
    """
```

#### 4. Reporter Integration

```python
def test_reporter_integration(fuzzing_workspace):
    """
    Test workflow:
    1. Create fuzzing session data
    2. Generate text and JSON reports
    3. Verify report contents
    """
```

### Running Integration Tests Only

```bash
# Run all integration tests
pytest tests/test_end_to_end_fuzzing.py -v

# Run specific integration test
pytest tests/test_end_to_end_fuzzing.py::TestEndToEndFuzzingWorkflow::test_complete_fuzzing_campaign -v
```

## Coverage Analysis

### Understanding Coverage Metrics (Updated October 2025)

**Line Coverage**: Percentage of code lines executed

- **Target**: 80% (industry standard for production code)
- **Current**: 56% (up from 22% after hypothesis fix, target: 80%)
- **Best practice**: pytest 8.4 with hypothesis for comprehensive coverage

**Branch Coverage**: Percentage of decision branches taken

- Implicitly tested through property-based tests (hypothesis generates edge cases)
- Random test order (pytest-randomly) ensures branches tested independently

**Missing Coverage**: Common gaps

- **Untested modules**: utils/_ (0%), harness/_ (0%), advanced strategies
- **Exception handlers**: Usually last to be covered
- **Edge paths**: Now better covered with hypothesis property-based tests

### Coverage Roadmap

| Milestone                       | Coverage Target | Status                     |
| ------------------------------- | --------------- | -------------------------- |
| **Phase 1: Critical Modules**   | 30%             | ✅ Complete (56% achieved) |
| **Phase 2: Core Functionality** | 60%             | 🔄 In Progress             |
| **Phase 3: Industry Standard**  | 80%             | ⏳ Planned                 |
| **Phase 4: Comprehensive**      | 90%+            | 🎯 Aspirational            |

**Current Focus**: Adding tests for utils/_ and harness/_ modules to reach 60%

### Viewing Coverage Reports

```bash
# Generate HTML coverage report
pytest tests/ --cov=core --cov-report=html

# View in browser
start reports/coverage/htmlcov/index.html  # Windows
```

**HTML Report Features:**

- ✅ Per-file coverage percentages
- ✅ Line-by-line execution highlighting
- ✅ Missing line identification
- ✅ Branch coverage visualization

### Coverage Goals

| Coverage Level | Status       | Action                     |
| -------------- | ------------ | -------------------------- |
| **90-100%**    | ✅ Excellent | Maintain with new features |
| **70-90%**     | ⚠️ Good      | Add edge case tests        |
| **50-70%**     | ⚠️ Fair      | Add unit tests             |
| **< 50%**      | ❌ Poor      | Prioritize testing         |

### Improving Coverage

1. **Identify Missing Lines**

   ```bash
   pytest tests/test_module.py --cov=core.module --cov-report=term-missing
   ```

2. **Analyze Missing Code**
   - Exception handlers?
   - Edge cases?
   - Unreachable code?

3. **Add Targeted Tests**

   ```python
   def test_exception_handler():
       """Test error condition that triggers handler."""
       with pytest.raises(SpecificError):
           trigger_error_condition()
   ```

4. **Verify Improvement**
   ```bash
   pytest tests/test_module.py --cov=core.module --cov-report=term
   ```

## CI/CD Integration

### GitHub Actions Workflow

The project uses GitHub Actions for continuous integration:

```yaml
# .github/workflows/tests.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - name: Install dependencies
        run: |
          pip install uv
          uv sync
      - name: Run tests with coverage
        run: |
          pytest tests/ --cov=core --cov-report=xml
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### Pre-commit Hooks

Ensure code quality before commits:

```bash
# Install pre-commit hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

**Hooks include:**

- Code formatting (black)
- Import sorting (isort)
- Linting (flake8)
- Type checking (mypy)
- Test execution

### Local Pre-push Checks (Updated 2025)

Before pushing code:

```bash
# 1. Run all tests with parallel execution
uv run pytest tests/ -n=4

# 2. Check coverage (target: 50%+, aspiration: 80%)
uv run pytest tests/ --cov=dicom_fuzzer --cov-report=term

# 3. Run modern linters (ruff replaces black/isort/flake8)
uv run ruff check .
uv run ruff format .

# 4. Type check with mypy
uv run mypy dicom_fuzzer/

# 5. Verify no regressions
uv run pytest tests/ --lf
```

## Performance Testing

### Benchmark Tests with pytest-benchmark

Track function performance over time to catch regressions:

```bash
# Run benchmarks only
uv run pytest tests/ --benchmark-only

# Run all tests including benchmarks
uv run pytest tests/ --benchmark-enable

# Save benchmark results
uv run pytest tests/ --benchmark-save=baseline

# Compare against baseline
uv run pytest tests/ --benchmark-compare=baseline

# View historical benchmarks
uv run pytest tests/ --benchmark-histogram
```

### Performance Targets

| Operation                         | Target Time | Current | Status       |
| --------------------------------- | ----------- | ------- | ------------ |
| **DICOM File Parse**              | < 10ms      | ~5ms    | ✅ Excellent |
| **Mutation Generation**           | < 50ms      | ~30ms   | ✅ Good      |
| **3D Series Fuzzing (30 slices)** | < 1s        | ~0.8s   | ✅ Good      |
| **Coverage Analysis**             | < 5s        | ~3s     | ✅ Excellent |
| **Full Test Suite (2540 tests)**  | < 60s       | ~30s    | ✅ Excellent |

### Test Suite Performance

**Parallel Execution (pytest-xdist)**:

- Workers: 4 (configured in pyproject.toml)
- Speed improvement: 4x faster than serial
- 2540 tests complete in ~30 seconds

**Optimization Tips**:

```bash
# Use pytest-xdist for parallel execution (already configured)
uv run pytest tests/ -n=4

# Auto-detect optimal worker count
uv run pytest tests/ -n=auto

# Find slowest tests
uv run pytest tests/ --durations=10

# Skip slow tests for rapid development
uv run pytest tests/ -m "not slow"
```

### Benchmarking Best Practices

1. **Consistent Environment**: Run benchmarks on same hardware
2. **Multiple Iterations**: pytest-benchmark automatically runs 100+ iterations
3. **Statistical Analysis**: Uses median, not mean, to avoid outlier skew
4. **Regression Detection**: Fails if performance degrades >20%
5. **Historical Tracking**: Compare against saved baselines

## Troubleshooting

### Common Issues

#### Tests Failing After Changes

```bash
# Run only failed tests
pytest tests/ --lf

# Show full output
pytest tests/test_file.py -vv

# Show print statements
pytest tests/test_file.py -s
```

#### Coverage Not Updating

```bash
# Clear coverage cache
rm -rf .coverage reports/coverage/

# Regenerate coverage
pytest tests/ --cov=core --cov-report=html
```

#### Slow Test Suite

```bash
# Find slow tests
pytest tests/ --durations=10

# Run in parallel (install pytest-xdist)
pytest tests/ -n auto
```

#### Import Errors

```bash
# Verify virtual environment
which python  # Should point to .venv

# Reinstall dependencies
uv sync --all-extras

# Specific package missing (e.g., hypothesis)
uv pip install hypothesis

# Check installed packages
uv pip list | grep pytest
```

#### Missing Hypothesis Tests (Common Issue)

**Symptom**: ImportError: No module named 'hypothesis'

**Fix**:

```bash
# Install hypothesis
uv pip install hypothesis

# Verify installation
uv pip list | grep hypothesis

# Run property-based tests
uv run pytest tests/test_helpers.py -v
```

**Impact**: +313 tests, helpers.py 0% → 100% coverage

#### pytest-watch Not Auto-Running

**Symptom**: `ptw` command not found or not watching files

**Fix**:

```bash
# Install pytest-watch
uv pip install pytest-watch

# Run with full path
uv run ptw tests/

# Verify installation
uv pip list | grep pytest-watch
```

#### mutmut Windows Error

**Symptom**: `ModuleNotFoundError: No module named 'resource'`

**Explanation**: mutmut requires Unix `resource` module, not available on Windows

**Workaround**: Use Linux/macOS for mutation testing, or use WSL on Windows

**Alternative**: Focus on property-based testing (hypothesis) instead

## Test Maintenance

### Adding Tests for New Features

When adding new features:

1. **Write tests first** (TDD approach)
2. **Ensure 90%+ coverage** for new code
3. **Add integration tests** if multiple modules involved
4. **Update this document** if test patterns change

### Updating Existing Tests

When modifying code:

1. **Run affected tests** first
2. **Update test expectations** if behavior changed
3. **Add regression tests** if fixing bugs
4. **Verify coverage maintained** or improved

### Test Review Checklist (Updated 2025)

Before merging:

- [ ] All tests pass (2540+ tests, 99.8% pass rate)
- [ ] Coverage ≥ 50% overall (target: 80% for new code)
- [ ] Property-based tests run successfully (hypothesis)
- [ ] Tests pass in random order (pytest-randomly)
- [ ] Parallel execution works (pytest-xdist -n=4)
- [ ] No performance regressions (pytest-benchmark)
- [ ] Integration tests pass
- [ ] No test warnings or deprecations
- [ ] Test names are descriptive
- [ ] Edge cases covered (hypothesis helps find these)
- [ ] Documentation updated

## Resources

### Internal Documentation

- [Coverage Analysis](COVERAGE.md) - Detailed coverage breakdown
- [Fuzzing Guide](FUZZING_GUIDE.md) - Testing methodologies
- [Project Structure](../README.md#project-structure) - Repository organization
- [Performance Documentation](PERFORMANCE.md) - Benchmark targets

### Modern Testing Stack Resources (2025)

- [pytest 8.4 Documentation](https://docs.pytest.org/) - Core test framework
- [Hypothesis Documentation](https://hypothesis.readthedocs.io/) - Property-based testing
- [pytest-benchmark](https://pytest-benchmark.readthedocs.io/) - Performance regression testing
- [pytest-xdist](https://pytest-xdist.readthedocs.io/) - Parallel execution
- [Coverage.py Guide](https://coverage.readthedocs.io/) - Coverage reporting
- [Ruff Documentation](https://docs.astral.sh/ruff/) - Fast linter/formatter
- [uv Documentation](https://docs.astral.sh/uv/) - Ultra-fast package manager

### Testing Best Practices

- [Testing Best Practices](https://docs.python-guide.org/writing/tests/) - General Python testing
- [Property-Based Testing Guide](https://increment.com/testing/in-praise-of-property-based-testing/) - Why property-based testing matters
- [Test Isolation](https://martinfowler.com/bliki/TestIsolation.html) - Martin Fowler on test dependencies

---

**Last Updated**: October 2025 (State-of-the-Art Testing Stack)
**Maintained By**: DICOM-Fuzzer Team
**Coverage**: 56% (up from 22%, target: 80%)
**Test Count**: 2540+ tests (including 313 property-based tests)
**Grade**: A+ (Industry-leading 2025 testing infrastructure)
