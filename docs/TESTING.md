# Testing Guide - DICOM Fuzzer

Comprehensive guide to the test suite, coverage, and testing best practices for the DICOM-Fuzzer project.

## Table of Contents

- [Overview](#overview)
- [Test Coverage Summary](#test-coverage-summary)
- [Running Tests](#running-tests)
- [Modern Tooling](#modern-tooling)
- [Test Structure](#test-structure)
- [Writing Tests](#writing-tests)
- [Integration Tests](#integration-tests)
- [Coverage Analysis](#coverage-analysis)
- [CI/CD Integration](#cicd-integration)

## Overview

The DICOM-Fuzzer project maintains a comprehensive test suite with **930+ tests** and **69.12% overall coverage**, with **11 out of 13 core modules** achieving 90%+ coverage.

### Test Philosophy

- **Comprehensive Coverage**: Every core module has extensive test coverage
- **Edge Case Testing**: Dedicated tests for error conditions and boundary cases
- **Integration Testing**: End-to-end workflow tests ensure module integration
- **Property-Based Testing**: Using Hypothesis for generative testing
- **Regression Prevention**: Tests prevent bugs from reappearing

## Test Coverage Summary

### Overall Statistics

- **Total Tests**: 930+
- **Pass Rate**: 100%
- **Overall Coverage**: 69.12%
- **Modules at 100% Coverage**: 8
- **Modules at 90%+ Coverage**: 11 out of 13

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

## Modern Tooling

### Using Just Task Runner (Recommended)

The project now includes a `justfile` with convenient test commands:

```bash
# Install just (if not already installed)
# Windows: winget install Casey.Just
# macOS: brew install just
# Linux: cargo install just

# Run tests with just
just test                    # Run all tests
just test-cov                # Run tests with coverage report
just test-parallel           # Run tests in parallel (4 workers)
just smoke                   # Quick smoke test (non-slow tests)
just test-file tests/test_fuzzing_session.py  # Run specific file
just coverage                # Generate detailed coverage report
```

### Using uv (Modern Package Manager)

All commands can be run with `uv run` for deterministic dependency resolution:

```bash
# Run tests with uv
uv run pytest tests/ -v
uv run pytest tests/ --cov=dicom_fuzzer --cov-report=html
uv run pytest -n 4 tests/  # Parallel execution

# Use uv for faster dependency management
uv sync --all-extras  # Install all dependencies
uv pip list --outdated  # Check for updates
```

### Legacy Commands (Still Supported)

Traditional pytest commands continue to work:

```bash
pytest tests/ -v
pytest tests/ --cov=dicom_fuzzer --cov-report=html
```

**Note**: Modern tooling (uv + Ruff + Hatchling) was introduced in January 2025 to replace setuptools, black, isort, flake8, and pylint. See [README.md](../README.md#modern-tooling-2025) for full details.

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

### Understanding Coverage Metrics

**Line Coverage**: Percentage of code lines executed

- **Target**: 90%+ for core modules
- **Current**: 69.12% overall, 11/13 modules at 90%+

**Branch Coverage**: Percentage of decision branches taken

- Not currently measured but implicit in edge case testing

**Missing Coverage**: Usually exception handlers and edge paths

- Example: fuzzing_session.py missing 8 lines (all exception handlers)

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

### Local Pre-push Checks

Before pushing code:

```bash
# 1. Run all tests
pytest tests/ -v

# 2. Check coverage
pytest tests/ --cov=core --cov-report=term

# 3. Run linters
black . && isort . && flake8

# 4. Verify no regressions
pytest tests/ --lf
```

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
uv sync
```

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

### Test Review Checklist

Before merging:

- [ ] All tests pass
- [ ] Coverage ≥ 90% for changed modules
- [ ] Integration tests pass
- [ ] No test warnings or deprecations
- [ ] Test names are descriptive
- [ ] Edge cases covered
- [ ] Documentation updated

## Resources

### Internal Documentation

- [Coverage Analysis](COVERAGE.md) - Detailed coverage breakdown
- [Fuzzing Guide](FUZZING_GUIDE.md) - Testing methodologies
- [Project Structure](../README.md#project-structure) - Repository organization

### External Resources

- [pytest Documentation](https://docs.pytest.org/)
- [Coverage.py Guide](https://coverage.readthedocs.io/)
- [Hypothesis Documentation](https://hypothesis.readthedocs.io/)
- [Testing Best Practices](https://docs.python-guide.org/writing/tests/)

---

**Last Updated**: January 2025
**Maintained By**: DICOM-Fuzzer Team
