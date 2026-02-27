# Contributing

## Setup

```bash
git clone https://github.com/Dashtid/dicom-fuzzer.git
cd dicom-fuzzer
uv sync --all-extras
uv run pre-commit install
```

## Development Workflow

```bash
git checkout -b feature/your-feature

# Run tests and quality checks
uv run pytest tests/ -v
uv run ruff check . --fix
uv run ruff format .

git commit -m "feat: add your feature"
git push origin feature/your-feature
```

## Code Style

- **Formatter/Linter**: Ruff (enforced via pre-commit)
- **Type hints**: Required for public APIs
- **Docstrings**: Google style
- **Line length**: 88 characters

## Commits

Format: `<type>: <description>`

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

## Pull Requests

1. Rebase on main before opening
2. All CI checks must pass
3. Security issues go to [SECURITY.md](SECURITY.md), not PRs

## License

Contributions are licensed under MIT.
