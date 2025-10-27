# Migration Guide: v1.1.0 → v1.2.0

**Date**: 2025-10-27
**Breaking Changes**: None (backward compatible)
**Migration Difficulty**: Easy

## Overview

Version 1.2.0 introduces a modernized folder structure to reduce complexity and improve maintainability. This migration guide helps you transition existing fuzzing campaigns and workflows to the new structure.

## What Changed?

### Folder Structure Consolidation

**Before (v1.1.0)** - 19 top-level folders:

```
DICOM-Fuzzer/
├── dicom_fuzzer/
├── tests/
├── docs/
├── examples/
├── crashes/          # Scattered outputs
├── logs/             # Scattered outputs
├── reports/          # Scattered outputs
├── artifacts/        # Scattered outputs
├── campaigns/        # Scattered outputs
├── demo/             # Separate folder
├── config/           # Duplicate configs
├── configs/          # Duplicate configs
├── data/             # Seeds/dictionaries
├── samples/
├── scripts/
├── docker/
└── ...
```

**After (v1.2.0)** - 12 top-level folders:

```
DICOM-Fuzzer/
├── dicom_fuzzer/
├── tests/
├── docs/
├── examples/
│   └── demo/         # Merged here
├── output/           # ALL outputs consolidated
│   ├── crashes/
│   ├── logs/
│   ├── reports/
│   ├── campaigns/
│   ├── fuzzed/
│   └── corpus/
├── configs/          # Unified config
│   ├── targets/
│   ├── seeds/        # Moved from data/
│   ├── dictionaries/ # Moved from data/
│   └── viewer_profiles.yaml
├── samples/
├── scripts/
├── docker/
└── ...
```

### Key Changes

| Old Path                      | New Path                       | Notes                |
| ----------------------------- | ------------------------------ | -------------------- |
| `crashes/`                    | `output/crashes/`              | Consolidated         |
| `logs/`                       | `output/logs/`                 | Consolidated         |
| `reports/`                    | `output/reports/`              | Consolidated         |
| `artifacts/`                  | `output/`                      | Consolidated         |
| `campaigns/`                  | `output/campaigns/`            | Consolidated         |
| `demo/`                       | `examples/demo/`               | Merged               |
| `config/`                     | `configs/`                     | Deleted (duplicates) |
| `data/seeds/`                 | `configs/seeds/`               | Moved                |
| `data/dictionaries/`          | `configs/dictionaries/`        | Moved                |
| `config/viewer_profiles.yaml` | `configs/viewer_profiles.yaml` | Moved                |

## Migration Steps

### Option 1: Fresh Start (Recommended for New Users)

If you don't have existing fuzzing outputs to preserve:

```bash
# 1. Pull latest version
git pull origin main

# 2. Update dependencies
uv sync

# 3. Start fuzzing (uses new output/ directory automatically)
dicom-fuzzer fuzz --input samples/ --num-files 10
```

**Output will automatically go to**: `./output/`

### Option 2: Preserve Existing Data (Recommended for Existing Users)

If you have existing fuzzing results you want to keep:

```bash
# 1. Backup existing outputs (optional but recommended)
mkdir -p backup_$(date +%Y%m%d)
cp -r crashes logs reports campaigns backup_$(date +%Y%m%d)/

# 2. Create new output directory structure
mkdir -p output/{crashes,logs,reports,campaigns,fuzzed,corpus}

# 3. Move existing outputs to new structure
mv crashes/* output/crashes/ 2>/dev/null || true
mv logs/* output/logs/ 2>/dev/null || true
mv reports/* output/reports/ 2>/dev/null || true
mv campaigns/* output/campaigns/ 2>/dev/null || true
mv artifacts/crashes/* output/crashes/ 2>/dev/null || true
mv artifacts/fuzzed/* output/fuzzed/ 2>/dev/null || true
mv artifacts/corpus/* output/corpus/ 2>/dev/null || true

# 4. Clean up empty legacy directories (optional)
rmdir crashes logs reports campaigns artifacts 2>/dev/null || true

# 5. Update dependencies
uv sync

# 6. Verify migration
ls -la output/
```

### Option 3: Use Legacy Paths (Backward Compatible)

If you prefer to keep using old paths:

```bash
# Old paths still work! Just specify them explicitly:
dicom-fuzzer fuzz --input samples/ --output ./crashes/

# Or use environment variables
export FUZZER_OUTPUT_DIR="./crashes"
dicom-fuzzer fuzz --input samples/
```

**Note**: New fuzzing runs default to `./output/` but you can override this.

## Configuration Migration

### Update Path References

If you have scripts or configs referencing old paths, update them:

**Python Scripts**:

```python
# Before (v1.1.0)
crash_dir = Path("artifacts/crashes")
corpus_dir = Path("data/seeds")
config_file = Path("config/viewer_profiles.yaml")

# After (v1.2.0)
crash_dir = Path("output/crashes")
corpus_dir = Path("configs/seeds")
config_file = Path("configs/viewer_profiles.yaml")
```

**Bash Scripts**:

```bash
# Before (v1.1.0)
CRASH_DIR="./crashes"
LOG_DIR="./logs"
REPORT_DIR="./reports"

# After (v1.2.0)
CRASH_DIR="./output/crashes"
LOG_DIR="./output/logs"
REPORT_DIR="./output/reports"
```

### Update `.gitignore` (if customized)

If you customized `.gitignore`, update patterns:

```gitignore
# Before (v1.1.0)
/crashes/
/logs/
/reports/
/artifacts/
/campaigns/*/fuzzed/

# After (v1.2.0)
/output/
!/output/.gitkeep
!/output/*/.gitkeep
```

## CLI Changes

### Default Output Directory

The `--output` flag now defaults to `./output` instead of `./fuzzed_dicoms`:

```bash
# Before (v1.1.0) - default was ./fuzzed_dicoms
dicom-fuzzer fuzz --input samples/

# After (v1.2.0) - default is ./output
dicom-fuzzer fuzz --input samples/

# Override if needed
dicom-fuzzer fuzz --input samples/ --output ./custom_dir/
```

### Report Paths

Reports are now saved to `output/reports/` by default:

```bash
# Before (v1.1.0)
# Reports saved to: ./reports/html/

# After (v1.2.0)
# Reports saved to: ./output/reports/html/
```

## Cleanup After Migration (Recommended)

After successfully migrating, clean up development caches and temporary files:

```bash
# Clean Python cache directories (safe - regenerated automatically)
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete
find . -type f -name "*.pyo" -delete

# Clean development tool caches (optional - saves disk space)
# These will be regenerated when needed
rm -rf .mypy_cache
rm -rf .ruff_cache
rm -rf .pytest_cache
rm -rf .hypothesis
rm -rf .benchmarks

# Move orphaned log files to output/logs/ (if any)
mv *.log output/logs/ 2>/dev/null || true

# Verify cleanup
du -sh .  # Check total directory size
```

**What's Safe to Delete**:

- ✓ `__pycache__/` directories - Python bytecode cache
- ✓ `.pyc`, `.pyo` files - Compiled Python files
- ✓ `.mypy_cache/` - Type checker cache
- ✓ `.ruff_cache/` - Linter cache
- ✓ `.pytest_cache/` - Test cache
- ✓ `.hypothesis/` - Hypothesis test cache
- ✓ `.benchmarks/` - Benchmark data

**What NOT to Delete**:

- ✗ `.venv/` - Virtual environment
- ✗ `.git/` - Git repository
- ✗ `output/` - Your fuzzing results!

## Testing Your Migration

### Verify Structure

```bash
# Check new directory structure
ls -la output/
ls -la configs/
ls -la examples/demo/

# Verify output directories have .gitkeep files
find output/ -name .gitkeep

# Check no old directories remain
ls -d crashes logs reports campaigns artifacts 2>/dev/null || echo "All legacy dirs removed ✓"
```

### Run Tests

```bash
# Run test suite to verify code changes
uv run pytest tests/ -v

# Expected: 2583/2585 passing (99.92% pass rate)
```

### Test Fuzzing

```bash
# Run a quick fuzzing session
dicom-fuzzer fuzz --input samples/ --num-files 5 --output ./output

# Verify outputs land in correct locations
ls -la output/crashes/
ls -la output/logs/
ls -la output/fuzzed/
```

## Troubleshooting

### Q: My existing scripts broke!

**A**: Update hard-coded paths in your scripts:

- `crashes/` → `output/crashes/`
- `logs/` → `output/logs/`
- `config/` → `configs/`
- `data/seeds/` → `configs/seeds/`

Or use legacy paths with `--output` flag.

### Q: Where did my old crashes go?

**A**: If you didn't migrate (Option 2), they're still in the old `crashes/` directory. Move them:

```bash
mv crashes/* output/crashes/
```

### Q: Can I use both old and new structure?

**A**: Yes! Legacy paths are backward compatible:

- Old fuzzing runs in `crashes/`, `logs/`, etc. still work
- New runs default to `output/` but can be overridden

### Q: Do I need to update my CI/CD?

**A**: Only if it hard-codes paths. Update:

- `./crashes/` → `./output/crashes/`
- `./reports/` → `./output/reports/`
- `./logs/` → `./output/logs/`

### Q: What about Docker volumes?

**A**: Update `docker-compose.yml` volume mounts:

```yaml
# Before
volumes:
  - ./crashes:/crashes:rw
  - ./reports:/reports:rw

# After
volumes:
  - ./output/crashes:/crashes:rw
  - ./output/reports:/reports:rw
```

## Rollback Plan

If you need to rollback to v1.1.0:

```bash
# 1. Checkout previous version
git checkout v1.1.0

# 2. Restore dependencies
uv sync

# 3. Move outputs back (if migrated)
mv output/crashes/* crashes/ 2>/dev/null || true
mv output/logs/* logs/ 2>/dev/null || true
mv output/reports/* reports/ 2>/dev/null || true
```

## Benefits of New Structure

After migration, you'll enjoy:

1. **37% Fewer Top-Level Folders**: 19 → 12 folders
2. **Single Output Location**: All fuzzing results in `output/`
3. **Cleaner Git Status**: One `output/` instead of 5+ directories
4. **Modern Best Practices**: Aligns with 2025 Python packaging standards (PyPA, PyOpenSci)
5. **Better Organization**: Clear separation of code, config, and outputs
6. **Easier Cleanup**: Delete entire `output/` to clean all fuzzing results

## Support

If you encounter issues during migration:

1. Check [docs/STRUCTURE.md](docs/STRUCTURE.md) for detailed structure documentation
2. Review [README.md](README.md) for updated usage examples
3. Open an issue: https://github.com/Dashtid/dicom-fuzzer/issues

## Related Documentation

- [docs/STRUCTURE.md](docs/STRUCTURE.md) - Detailed folder structure documentation
- [README.md](README.md) - Updated project README
- [CHANGELOG.md](CHANGELOG.md) - Full v1.2.0 changelog
