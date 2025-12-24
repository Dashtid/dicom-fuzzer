# Contributing

## Setup

```bash
git clone https://github.com/Dashtid/dicom-fuzzer.git
cd dicom-fuzzer
uv sync --all-extras
uv run pre-commit install
```

## Workflow

```bash
# Create branch
git checkout -b feature/your-feature

# Make changes, write tests
uv run pytest tests/ -v

# Check code quality
uv run ruff check . --fix
uv run ruff format .

# Commit and push
git commit -m "feat: add your feature"
git push origin feature/your-feature
```

## Testing

```bash
uv run pytest tests/                          # All tests
uv run pytest tests/test_module.py -v         # Specific file
uv run pytest --cov=dicom_fuzzer              # With coverage
uv run pytest -n 4                            # Parallel
```

**Coverage goals:** 80%+ for new features, 100% for critical modules.

## Code Style

- **Formatter/Linter:** Ruff (auto-runs via pre-commit)
- **Type hints:** Required for public APIs
- **Docstrings:** Google style
- **Line length:** 88 characters

```python
def parse_file(path: Path) -> Dataset | None:
    """Parse a DICOM file.

    Args:
        path: Path to DICOM file

    Returns:
        Parsed dataset or None if failed
    """
    try:
        return pydicom.dcmread(path)
    except Exception:
        return None
```

## Commits

Format: `<type>: <description>`

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

```text
feat: add 3D series fuzzing support
fix: resolve crash in metadata parser
docs: update CLI reference
```

## Pull Requests

1. Rebase on main: `git fetch origin && git rebase origin/main`
2. Run tests: `uv run pytest tests/ -v`
3. Check quality: `uv run ruff check . && uv run mypy dicom_fuzzer/`
4. Push and open PR

**PR checklist:**

- [ ] Tests pass
- [ ] Code quality checks pass
- [ ] Documentation updated (if needed)
- [ ] CHANGELOG updated (if applicable)

## Questions

- **Bugs:** Open an issue
- **Security:** See [SECURITY.md](SECURITY.md)

## License

Contributions are licensed under MIT.
