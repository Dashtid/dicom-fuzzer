# Contributing to DICOM Fuzzer

Thank you for your interest in contributing to DICOM Fuzzer! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Development Workflow](#development-workflow)
- [Testing Guidelines](#testing-guidelines)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)

## Code of Conduct

- **Be respectful**: Treat all contributors with respect
- **Be constructive**: Provide helpful feedback and suggestions
- **Be patient**: Remember that contributors have varying skill levels
- **Focus on the code**: Keep discussions technical and objective

## Getting Started

### Prerequisites

- **Python**: 3.11, 3.12, or 3.13
- **Git**: For version control
- **uv**: Modern Python package manager (recommended)
- **Operating System**: Windows, Linux, or macOS

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/dicom-fuzzer.git
   cd dicom-fuzzer
   ```

## Development Setup

### 1. Install uv (Recommended)

```bash
# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Linux/macOS
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Install Dependencies

```bash
# Install all dependencies (including dev and docs)
uv sync --all-extras

# Or use pip (traditional)
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows
pip install -e ".[dev,docs,network]"
```

### 3. Install Pre-commit Hooks

```bash
uv run pre-commit install
```

This automatically runs code quality checks before each commit.

## Development Workflow

### Branch Strategy

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

### Making Changes

1. **Write code**: Implement your feature or fix
2. **Write tests**: Add tests for your changes
3. **Run tests**: Ensure all tests pass
4. **Update docs**: Update documentation if needed
5. **Commit**: Make clear, atomic commits

### Testing Your Changes

```bash
# Run all tests
uv run pytest tests/

# Run specific test file
uv run pytest tests/test_your_module.py -v

# Run with coverage
uv run pytest --cov=dicom_fuzzer --cov-report=html

# Run tests in parallel (faster)
uv run pytest -n 4
```

## Testing Guidelines

### Writing Tests

**Location**: Place tests in `tests/` matching the module structure:
```
dicom_fuzzer/core/parser.py → tests/test_parser.py
```

**Test Structure**:
```python
"""Tests for dicom_fuzzer.core.parser module."""
import pytest
from dicom_fuzzer.core.parser import DicomParser

class TestDicomParser:
    """Test suite for DicomParser class."""

    def test_initialization(self):
        """Test parser initializes correctly."""
        parser = DicomParser()
        assert parser is not None

    def test_parse_valid_file(self, sample_dicom_file):
        """Test parsing a valid DICOM file."""
        parser = DicomParser()
        dataset = parser.parse(sample_dicom_file)
        assert dataset is not None
```

**Test Coverage Goals**:
- **New features**: Aim for 80%+ coverage
- **Bug fixes**: Add test that reproduces the bug
- **Critical modules**: Aim for 100% coverage

### Using Fixtures

Use pytest fixtures from `tests/conftest.py`:
```python
def test_with_fixture(sample_dicom_file, temp_output_dir):
    """Test using shared fixtures."""
    # sample_dicom_file is a valid DICOM file
    # temp_output_dir is a temporary directory
```

## Code Style

### Formatter and Linter

We use **Ruff** for both formatting and linting:

```bash
# Check for linting issues
uv run ruff check .

# Auto-fix linting issues
uv run ruff check --fix .

# Format code
uv run ruff format .
```

### Python Standards

- **Python Version**: Target Python 3.11+
- **Line Length**: 88 characters (Black style)
- **Imports**: Organized with isort (via Ruff)
- **Type Hints**: Use type hints for public APIs
- **Docstrings**: Use Google-style docstrings

### Example Code Style

```python
"""Module for DICOM parsing utilities."""

from pathlib import Path
from typing import Optional

import pydicom
from pydicom.dataset import Dataset


def parse_dicom_file(file_path: Path) -> Optional[Dataset]:
    """Parse a DICOM file and return the dataset.

    Args:
        file_path: Path to the DICOM file to parse

    Returns:
        Parsed DICOM dataset, or None if parsing fails

    Example:
        >>> dataset = parse_dicom_file(Path("sample.dcm"))
        >>> print(dataset.PatientName)
    """
    try:
        return pydicom.dcmread(file_path)
    except Exception:
        return None
```

### Security Considerations

- **Never use `pickle`** on untrusted data
- **Use `random.SystemRandom()`** for security-sensitive operations
- **Validate all inputs** from external sources
- **Use bandit** for security scanning (run automatically in CI)

## Commit Messages

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation only
- **style**: Code style changes (formatting, no logic change)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks (dependencies, tooling)
- **ci**: CI/CD changes

### Examples

```
feat(core): add support for 3D DICOM series fuzzing

Implement series detection, validation, and mutation capabilities
for multi-slice DICOM series (CT, MRI, etc.).

- Add SeriesDetector for automatic series grouping
- Add SeriesValidator for slice ordering validation
- Add SeriesMutator with 5 mutation strategies
- Add comprehensive test suite (100+ tests)

Closes #123
```

```
fix(ci): resolve Ruff linting failures in CI pipeline

Make Ruff linter non-blocking to allow incremental code quality
improvements without blocking releases.
```

## Pull Request Process

### Before Submitting

1. **Rebase on main**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run full test suite**:
   ```bash
   uv run pytest tests/ -v
   ```

3. **Check code quality**:
   ```bash
   uv run ruff check .
   uv run ruff format .
   uv run mypy dicom_fuzzer/
   uv run bandit -c pyproject.toml -r dicom_fuzzer/
   ```

4. **Update documentation** if needed

### Creating the PR

1. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open pull request** on GitHub

3. **Fill out PR template**:
   - Clear description of changes
   - Link to related issues
   - Screenshots (if UI changes)
   - Testing performed

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed:
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if applicable)
```

### Review Process

- **Automated checks**: CI must pass (tests, linting, security)
- **Code review**: At least one maintainer approval required
- **Discussion**: Address reviewer feedback
- **Merge**: Maintainer will merge when approved

## Documentation

### Types of Documentation

1. **Code Documentation**: Docstrings in Python modules
2. **User Documentation**: Guides in `docs/` directory
3. **API Documentation**: Generated from docstrings (Sphinx)
4. **Examples**: Practical examples in `examples/` directory

### Writing Documentation

**Markdown Files** (`docs/*.md`):
- Use clear headings and structure
- Include code examples with syntax highlighting
- Add table of contents for long documents
- Link to related documentation

**Docstrings**:
```python
def fuzz_dicom_file(
    input_file: Path,
    output_file: Path,
    strategies: list[str] = None
) -> None:
    """Fuzz a DICOM file using specified strategies.

    Args:
        input_file: Path to input DICOM file
        output_file: Path for fuzzed output file
        strategies: List of fuzzing strategies to apply
            (default: all strategies)

    Raises:
        FileNotFoundError: If input_file doesn't exist
        ValueError: If strategies contains unknown strategy

    Example:
        >>> fuzz_dicom_file(
        ...     Path("input.dcm"),
        ...     Path("output.dcm"),
        ...     strategies=["metadata", "pixel"]
        ... )
    """
```

### Building Documentation

```bash
# Build Sphinx documentation
cd docs
uv run sphinx-build -b html source _build/html

# View documentation
open _build/html/index.html  # macOS
start _build\html\index.html # Windows
```

## Questions or Issues?

- **Questions**: Open a discussion on GitHub Discussions
- **Bugs**: Open an issue with detailed reproduction steps
- **Security**: See [SECURITY.md](SECURITY.md) for responsible disclosure

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to DICOM Fuzzer! 🎉
