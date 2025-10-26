# Project Directory Cleanup Analysis

## Current State

Total: 31 top-level directories consuming **~750 MB** of disk space

## Directory Breakdown

### [CRITICAL] Can Be DELETED - 635 MB (85% space savings)

| Directory               | Size   | Reason                                    | Action     |
| ----------------------- | ------ | ----------------------------------------- | ---------- |
| `crashes/`              | 566 MB | Old crash test data, gitignored           | **DELETE** |
| `test_fuzzed_series/`   | 66 MB  | Old test output, gitignored               | **DELETE** |
| `.mypy_cache/`          | 20 MB  | Build artifact, regenerates automatically | **DELETE** |
| `fuzzed_output/`        | 1.1 MB | Old test output, gitignored               | **DELETE** |
| `.hypothesis/`          | 847 KB | Property test database, regenerates       | **DELETE** |
| `dist/`                 | 857 KB | Old Python build artifacts                | **DELETE** |
| `benchmark_clean_test/` | 128 KB | Old test directory                        | **DELETE** |
| `.ruff_cache/`          | 68 KB  | Linter cache, regenerates                 | **DELETE** |
| `.pytest_cache/`        | 251 KB | Test cache, regenerates                   | **DELETE** |

**Command to delete all**:

```bash
rm -rf crashes/ test_fuzzed_series/ .mypy_cache/ fuzzed_output/ .hypothesis/ dist/ benchmark_clean_test/ .ruff_cache/ .pytest_cache/
```

### [EMPTY] Can Be DELETED - Empty Directories

| Directory        | Purpose                             | Action     |
| ---------------- | ----------------------------------- | ---------- |
| `checkpoints/`   | Empty                               | **DELETE** |
| `fuzzed_dicoms/` | Empty, redundant with campaigns/    | **DELETE** |
| `logs/`          | Empty, logs go to campaigns/\*/logs | **DELETE** |
| `output/`        | Empty, redundant with campaigns/    | **DELETE** |

**Command**:

```bash
rm -rf checkpoints/ fuzzed_dicoms/ logs/ output/
```

### [CONSOLIDATE] Redundant Configuration Directories

| Directory  | Size   | Contents            | Action                  |
| ---------- | ------ | ------------------- | ----------------------- |
| `config/`  | 368 KB | Old config system   | **MERGE into configs/** |
| `configs/` | 8 KB   | New config location | **KEEP**                |

**Issue**: Two config directories exist (`config/` and `configs/`)

**Solution**: Consolidate into single `configs/` directory

### [REVIEW] Large Active Directories

| Directory    | Size  | Purpose                  | Action                                                |
| ------------ | ----- | ------------------------ | ----------------------------------------------------- |
| `campaigns/` | 31 MB | Active fuzzing campaigns | **KEEP** (add to .gitignore selectively)              |
| `reports/`   | 25 MB | Phase 5 demo reports     | **PARTIAL DELETE** (keep structure, delete demo data) |
| `docs/`      | 19 MB | Documentation            | **KEEP**                                              |
| `tests/`     | 16 MB | Test suite               | **KEEP**                                              |

### [KEEP] Essential Directories

| Directory       | Size   | Purpose                  |
| --------------- | ------ | ------------------------ |
| `dicom_fuzzer/` | N/A    | Core source code         |
| `examples/`     | 136 KB | Example scripts          |
| `scripts/`      | 144 KB | Utility scripts          |
| `.github/`      | 60 KB  | CI/CD workflows          |
| `samples/`      | 40 KB  | Sample DICOM files       |
| `data/`         | 8 KB   | Seed data                |
| `docker/`       | 8 KB   | Docker configs           |
| `demo/`         | 40 KB  | Demo files               |
| `artifacts/`    | 4 KB   | Build artifacts          |
| `node_modules/` | 13 KB  | Node deps (for prettier) |

## Recommended Cleanup Actions

### Phase 1: Safe Deletions (Immediate - 635 MB savings)

```bash
# Delete cache directories (regenerate automatically)
rm -rf .mypy_cache/ .ruff_cache/ .pytest_cache/ .hypothesis/

# Delete old test data (566 MB!)
rm -rf crashes/ test_fuzzed_series/ fuzzed_output/

# Delete empty directories
rm -rf checkpoints/ fuzzed_dicoms/ logs/ output/

# Delete old build artifacts
rm -rf dist/ benchmark_clean_test/
```

### Phase 2: Clean Up Reports (23 MB savings)

```bash
# Keep report structure but delete phase5_demo generated files
rm -rf reports/phase5_demo/charts/
rm -rf reports/phase5_demo/*.html
rm -rf reports/phase5_demo/*.json

# Or just delete the entire demo
rm -rf reports/phase5_demo/
```

### Phase 3: Consolidate Configs

```bash
# Review and merge config/ into configs/
# (Manual review needed)
diff -r config/ configs/

# After verification, delete old config/
rm -rf config/
```

### Phase 4: Update .gitignore

Add these patterns to ensure output directories don't grow:

```gitignore
# Fuzzing output directories
crashes/
test_fuzzed_series/
fuzzed_output/
fuzzed_dicoms/
checkpoints/
logs/
output/

# Campaign data (keep structure, ignore large outputs)
campaigns/*/input/*
campaigns/*/fuzzed/*
campaigns/*/crashes/*
!campaigns/*/CAMPAIGN_RESULTS.md
!campaigns/*/*.md

# Report outputs (keep code, ignore generated files)
reports/*/charts/
reports/*/*.html
reports/*/*.json
!reports/README.md

# Python caches
__pycache__/
*.py[cod]
*$py.class
.mypy_cache/
.pytest_cache/
.ruff_cache/
.hypothesis/

# Build artifacts
dist/
build/
*.egg-info/
```

## Proposed Final Structure

```
dicom-fuzzer/
├── .github/              # CI/CD (keep)
├── campaigns/            # Active campaigns (keep, selective gitignore)
│   ├── campaign_001_initial/
│   │   ├── CAMPAIGN_RESULTS.md  # Tracked
│   │   ├── input/               # Gitignored
│   │   └── fuzzed/              # Gitignored
│   └── real_world_campaign_plan.md
├── configs/              # Consolidated config directory
├── data/                 # Seed data (keep)
├── demo/                 # Demo files (keep)
├── dicom_fuzzer/         # Core source (keep)
├── docs/                 # Documentation (keep)
├── examples/             # Example scripts (keep)
├── reports/              # Report templates (keep structure only)
├── samples/              # Sample DICOM files (keep)
├── scripts/              # Utility scripts (keep)
└── tests/                # Test suite (keep)
```

## Expected Results

- **Before**: 31 directories, ~750 MB
- **After**: 15 directories, ~90 MB
- **Savings**: 85% disk space reduction
- **Benefit**: Cleaner repository, faster git operations, easier navigation

## Risks

**LOW RISK** - All deleted items are either:

1. Cached data that regenerates automatically
2. Old test output already gitignored
3. Empty directories

**NO RISK** to:

- Source code
- Tests
- Documentation
- Active campaign data (tracked in Git)

## Execution Plan

1. **Backup first** (if paranoid):

   ```bash
   tar -czf dicom-fuzzer-backup-$(date +%Y%m%d).tar.gz crashes/ test_fuzzed_series/ .mypy_cache/
   ```

2. **Run Phase 1 cleanup** (safe deletions)

3. **Update .gitignore** to prevent future accumulation

4. **Commit changes**:

   ```bash
   git add .gitignore
   git commit -m "chore: streamline project structure and update gitignore"
   ```

5. **Run Phase 2-3 cleanup** (optional)

## Recommendation

**Execute Phase 1 immediately** - it's completely safe and recovers 85% of wasted disk space. The deleted data is all cached/temporary output that serves no purpose.
