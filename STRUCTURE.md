# DICOM-Fuzzer Project Structure

This document describes the organization of the DICOM-Fuzzer project.

## Directory Structure

```
DICOM-Fuzzer/
├── .github/                    # GitHub-specific files
│   ├── workflows/              # GitHub Actions CI/CD workflows
│   │   ├── ci.yml             # Main CI pipeline
│   │   └── release.yml        # Release automation
│   ├── dependabot.yml         # Dependency update configuration
│   └── PULL_REQUEST_TEMPLATE.md  # PR template
│
├── core/                       # Core fuzzing engine
│   ├── crash_analyzer.py      # Crash detection and analysis
│   ├── exceptions.py          # Custom exception hierarchy
│   ├── generator.py           # Batch file generation
│   ├── grammar_fuzzer.py      # Grammar-based intelligent fuzzing
│   ├── mutator.py             # Advanced mutation engine
│   ├── parser.py              # DICOM file parsing
│   └── validator.py           # DICOM compliance validation
│
├── strategies/                 # Fuzzing strategies
│   ├── header_fuzzer.py       # DICOM header mutations
│   ├── metadata_fuzzer.py     # Patient/study metadata fuzzing
│   ├── pixel_fuzzer.py        # Pixel data corruption
│   └── structure_fuzzer.py    # File structure attacks
│
├── utils/                      # Utility modules
│   ├── config.py              # Configuration management
│   ├── helpers.py             # Helper functions
│   └── logger.py              # Structured logging
│
├── tests/                      # Test suite (414 tests)
│   ├── conftest.py            # Pytest fixtures
│   ├── test_config.py         # Configuration tests
│   ├── test_crash_analyzer.py # Crash analyzer tests
│   ├── test_exceptions.py     # Exception tests
│   ├── test_generator.py      # Generator tests
│   ├── test_grammar_fuzzer.py # Grammar fuzzer tests
│   ├── test_helpers.py        # Helper function tests
│   ├── test_integration.py    # Integration tests
│   ├── test_logger.py         # Logger tests
│   ├── test_mutator.py        # Mutator tests
│   ├── test_parser.py         # Parser tests
│   ├── test_strategies.py     # Strategy tests
│   └── test_validator.py      # Validator tests
│
├── docs/                       # Documentation
│   ├── PROJECT_PLAN.md        # 8-week implementation roadmap
│   ├── TASK_BREAKDOWN.md      # Detailed task structure
│   └── TEST_COVERAGE.md       # Test suite documentation
│
├── samples/                    # Sample DICOM files (gitignored)
│   └── .gitkeep               # Keep directory in git
│
├── main.py                     # CLI entry point
├── pyproject.toml             # Project configuration
├── uv.lock                    # Dependency lock file
├── README.md                  # Project readme
├── STRUCTURE.md               # This file
└── .gitignore                 # Git ignore rules

```

## Output Directories (Generated at Runtime)

These directories are created automatically and are gitignored:

- `fuzzed_dicoms/` - Default output for generated fuzzed files
- `test_crashes/` - Crash reports and analysis
- `output/` - Custom output directory
- `crashes/` - Crash analyzer output

## Cache & Build Directories (Gitignored)

- `.venv/` - Python virtual environment
- `__pycache__/` - Python bytecode cache
- `.pytest_cache/` - Pytest cache
- `.hypothesis/` - Hypothesis property testing cache
- `.coverage` - Coverage data
- `htmlcov/` - HTML coverage reports
- `dist/` - Distribution packages
- `build/` - Build artifacts

## Key Files

### Configuration Files

- `pyproject.toml` - Python project configuration (pytest, coverage, black, isort)
- `uv.lock` - Locked dependencies for reproducible builds
- `.gitignore` - Files to exclude from version control
- `.pre-commit-config.yaml` - Pre-commit hooks configuration
- `.claudeignore` - Files to exclude from Claude Code indexing

### Entry Points

- `main.py` - CLI interface for running fuzzing campaigns
- `__init__.py` - Package initialization

### Documentation

- `README.md` - Project overview and quick start
- `STRUCTURE.md` - This file (project structure)
- `docs/PROJECT_PLAN.md` - Detailed implementation plan
- `docs/TASK_BREAKDOWN.md` - Task organization
- `docs/TEST_COVERAGE.md` - Test documentation

## Code Organization Principles

### Core Modules (core/)

**Single Responsibility**: Each module has one clear purpose
- `parser.py` - Read and validate DICOM files
- `mutator.py` - Apply mutations to datasets
- `generator.py` - Orchestrate batch generation
- `validator.py` - Validate DICOM compliance
- `grammar_fuzzer.py` - Intelligent grammar-based mutations
- `crash_analyzer.py` - Crash detection and reporting

### Strategy Pattern (strategies/)

**Extensibility**: Easy to add new fuzzing strategies
- Each strategy is a self-contained module
- Consistent interface across all strategies
- Mix and match strategies for campaigns

### Utilities (utils/)

**Reusability**: Shared functionality
- Configuration management
- Logging framework
- Helper functions

### Tests (tests/)

**Comprehensive Coverage**: 414 tests, 100% pass rate
- Unit tests for individual components
- Integration tests for workflows
- Property-based tests for robustness
- 1.30:1 test-to-source ratio

## Naming Conventions

### Python Files
- `snake_case.py` for all Python modules
- Test files prefixed with `test_`

### Directories
- `lowercase` for directories
- No spaces or special characters

### Classes
- `PascalCase` for class names
- Descriptive names (e.g., `DicomParser`, `HeaderFuzzer`)

### Functions
- `snake_case` for functions and methods
- Action-oriented names (e.g., `parse_file`, `mutate_dataset`)

### Constants
- `UPPER_SNAKE_CASE` for constants
- Defined in `utils/config.py`

## Development Workflow

1. **Clone Repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/DICOM-Fuzzer.git
   cd DICOM-Fuzzer
   ```

2. **Setup Environment**
   ```bash
   uv venv
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate     # Windows
   uv pip install -r requirements.txt
   ```

3. **Run Tests**
   ```bash
   pytest tests/ -v
   ```

4. **Run Fuzzer**
   ```bash
   python main.py samples/input.dcm -c 100 -o output/
   ```

5. **Check Code Quality**
   ```bash
   black .
   isort .
   flake8 .
   ```

## CI/CD Pipeline

GitHub Actions automatically runs on every push/PR:

1. **Code Quality Checks** (black, isort, flake8)
2. **Security Scanning** (bandit, safety)
3. **Test Suite** (414 tests across Python 3.11, 3.12, 3.13)
4. **Coverage Reporting** (95% threshold)
5. **Multi-OS Testing** (Ubuntu, Windows)

## Adding New Features

### New Fuzzing Strategy

1. Create `strategies/new_strategy_fuzzer.py`
2. Implement strategy class with mutation methods
3. Add tests in `tests/test_strategies.py`
4. Register in `core/generator.py`
5. Update documentation

### New Core Module

1. Create module in `core/`
2. Add comprehensive docstrings
3. Create test file in `tests/`
4. Update imports in relevant files
5. Update this STRUCTURE.md

## Maintenance

### Regular Tasks

- Update dependencies weekly (automated via Dependabot)
- Run security scans (automated in CI)
- Review test coverage (maintained at 95%+)
- Clean up temp directories periodically

### Cleanup Commands

```bash
# Remove all temporary files
rm -rf fuzzed_dicoms/ test_crashes/ output/ crashes/

# Remove Python cache
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -name "*.pyc" -delete

# Remove test artifacts
rm -rf .pytest_cache/ .hypothesis/ .coverage htmlcov/
```

## File Size Management

Large binary files (DICOM files, images) are gitignored:
- Sample DICOM files should be <5MB
- Use `.gitkeep` to preserve empty directories
- Test data generated at runtime, not committed

## Security Considerations

**Never commit**:
- Real patient data (HIPAA violation)
- Credentials or API keys
- Large binary files
- Temporary test outputs
- Cache directories

All sensitive patterns are in `.gitignore`.

---

**Last Updated**: 2025-10-01
**Maintained by**: DICOM-Fuzzer Development Team
