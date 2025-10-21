# Modern task runner for dicom-fuzzer
# Install just: https://just.systems/
# Usage: just <recipe>

# List available recipes
default:
    @just --list

# Install all dependencies (including dev and docs)
install:
    uv sync --all-extras

# Install only production dependencies
install-prod:
    uv sync

# Run all tests
test *args:
    uv run pytest {{args}}

# Run tests with coverage
test-cov:
    uv run pytest --cov=dicom_fuzzer --cov-report=html --cov-report=term-missing

# Run tests in parallel (faster)
test-parallel:
    uv run pytest -n 4

# Run specific test file
test-file file:
    uv run pytest {{file}} -v

# Run linter (check only)
lint:
    uv run ruff check .

# Run formatter (check only)
format-check:
    uv run ruff format --check .

# Auto-fix linting issues
fix:
    uv run ruff check --fix .
    uv run ruff format .

# Run type checking
typecheck:
    uv run mypy dicom_fuzzer/

# Run all quality checks (lint + format + typecheck)
check: lint format-check typecheck

# Run security scan
security:
    uv run bandit -c pyproject.toml -r dicom_fuzzer/

# Build package
build:
    uv build

# Build and check package
build-check: build
    uv run twine check dist/*

# Clean cache and build artifacts
clean:
    rm -rf dist/ build/ *.egg-info/
    rm -rf .pytest_cache .ruff_cache .mypy_cache .hypothesis
    rm -rf reports/coverage/htmlcov reports/coverage/.coverage*
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete

# Run pre-commit hooks on all files
pre-commit:
    uv run pre-commit run --all-files

# Install pre-commit hooks
pre-commit-install:
    uv run pre-commit install

# Update pre-commit hooks to latest versions
pre-commit-update:
    uv run pre-commit autoupdate

# Generate coverage report
coverage:
    uv run pytest --cov=dicom_fuzzer --cov-report=html --cov-report=xml --cov-report=term
    @echo "\n[+] Coverage report generated in reports/coverage/htmlcov/index.html"

# Run benchmarks
benchmark:
    uv run pytest tests/ --benchmark-only -v

# Serve documentation locally
docs-serve:
    cd docs && uv run python -m http.server 8000

# Build documentation
docs-build:
    uv run sphinx-build -b html docs/ docs/_build/html

# Run the fuzzer CLI
run *args:
    uv run dicom-fuzzer {{args}}

# Show project info
info:
    @echo "Project: dicom-fuzzer"
    @echo "Python: $(uv run python --version)"
    @echo "uv: $(uv --version)"
    @echo ""
    @echo "Dependencies:"
    @uv tree --depth 1

# Update uv.lock without installing
lock:
    uv lock

# Sync dependencies from uv.lock
sync:
    uv sync --all-extras

# Run quick smoke test (fast subset of tests)
smoke:
    uv run pytest tests/ -m "not slow" --tb=short -q

# Watch mode for development (requires pytest-watch)
watch:
    uv run ptw -- --tb=short -q

# Show outdated dependencies
outdated:
    uv pip list --outdated
