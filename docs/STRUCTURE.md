# DICOM-Fuzzer Repository Structure

**Last Updated**: 2025-10-27 (v1.2.0 - Folder Structure Modernization)

## Overview

This document describes the modernized folder structure of DICOM-Fuzzer, optimized for clarity and maintainability following 2025 Python packaging best practices.

## Top-Level Directory Organization

```
DICOM-Fuzzer/
├── dicom_fuzzer/         # Main package (source code)
├── tests/                # Test suite (976+ tests, 99.92% pass rate)
├── docs/                 # Documentation
├── examples/             # Example scripts and demos
├── configs/              # Configuration files
├── output/               # ALL generated outputs (gitignored)
├── samples/              # Sample DICOM files
├── scripts/              # Build and utility scripts
├── docker/               # Docker configurations
├── .github/              # GitHub Actions CI/CD
├── .vscode/              # VS Code settings (shared)
├── pyproject.toml        # Modern Python packaging
├── docker-compose.yml    # Docker orchestration
└── README.md             # Project overview
```

**Key Changes from v1.1.0**:

- **Consolidated Output**: `output/` replaces scattered `crashes/`, `logs/`, `reports/`, `artifacts/`, `campaigns/`
- **Unified Config**: `configs/` replaces duplicate `config/` and `data/` folders
- **Organized Examples**: `examples/demo/` replaces separate `demo/` folder
- **Reduced Complexity**: 19 top-level folders → 12 folders (37% reduction)

## Main Package Structure

```
dicom_fuzzer/
├── __init__.py           # Package exports
├── __main__.py           # CLI entry point
├── core/                 # Core fuzzing engine (21 modules)
│   ├── config.py         # Configuration management
│   ├── parser.py         # DICOM parsing
│   ├── generator.py      # Test case generation
│   ├── mutator.py        # Mutation engine
│   ├── validator.py      # DICOM validation
│   ├── fuzzing_session.py # Session tracking
│   ├── crash_analyzer.py # Crash analysis
│   ├── crash_deduplication.py # Crash grouping
│   ├── crash_triage.py   # Crash triaging (v1.2.0)
│   ├── test_minimizer.py # Test case minimization (v1.2.0)
│   ├── stability_tracker.py # Stability tracking (v1.2.0)
│   ├── reporter.py       # Report generation
│   ├── statistics.py     # Statistics tracking
│   ├── coverage_tracker.py # Code coverage
│   ├── lazy_loader.py    # Lazy DICOM loading (Phase 4)
│   ├── series_cache.py   # LRU caching (Phase 4)
│   ├── dicom_series.py   # 3D series data structure
│   ├── series_detector.py # Series detection & grouping
│   ├── series_validator.py # Series validation
│   ├── series_writer.py  # Series writing
│   └── exceptions.py     # Exception hierarchy
├── strategies/           # Mutation strategies (4 modules)
│   ├── header_fuzzer.py  # Header mutations
│   ├── metadata_fuzzer.py # Metadata mutations
│   ├── pixel_fuzzer.py   # Pixel data mutations
│   ├── series_mutator.py # 3D series mutations (Phase 2)
│   └── parallel_mutator.py # Parallel processing (Phase 4)
├── harness/              # Test harnesses
│   └── viewer_launcher_3d.py # 3D viewer testing (Phase 3)
├── analytics/            # Analytics and visualization
│   ├── campaign_analytics.py # Campaign analysis
│   └── visualization.py  # Result visualization
├── utils/                # Utilities
│   ├── helpers.py        # Helper functions
│   ├── logger.py         # Logging utilities
│   └── dicom_dictionaries.py # DICOM dictionaries
└── cli/                  # CLI tools
    ├── main.py           # Main CLI
    ├── generate_report.py # Report generation
    └── realtime_monitor.py # Live dashboard
```

## Configuration Directory

```
configs/
├── targets/              # Target configurations
│   ├── dcmtk_dcmdump.json # DCMTK target
│   └── orthanc_api.json  # Orthanc target
├── seeds/                # Seed DICOM files (user-provided)
├── dictionaries/         # Fuzzing dictionaries
├── viewer_profiles.yaml  # Viewer configurations (Phase 3)
├── local_paths.example.py # Path template
└── local_paths.py        # Local paths (gitignored)
```

**Purpose**: All configuration files in one place

- Target configs define fuzzing targets
- Seeds provide base DICOM files for mutation
- Dictionaries guide intelligent fuzzing
- Viewer profiles configure 3D viewer testing

## Output Directory (Gitignored)

```
output/                   # ALL fuzzing results
├── crashes/              # Crash-inducing files
│   ├── by_severity/      # Organized by severity
│   ├── concurrent_0_*/   # Parallel fuzzing runs
│   └── *.dcm             # Individual crash files
├── logs/                 # Fuzzing logs
│   └── fuzzing_*.log     # Timestamped logs
├── reports/              # Generated reports
│   ├── html/             # HTML reports
│   ├── json/             # JSON reports
│   └── coverage/         # Coverage reports
├── campaigns/            # Campaign results
│   ├── campaign_001/     # Campaign directories
│   │   ├── input/        # Input files
│   │   ├── fuzzed/       # Generated files
│   │   ├── crashes/      # Crashes found
│   │   └── CAMPAIGN_RESULTS.md # Results (tracked)
│   └── ...
├── fuzzed/               # Fuzzed DICOM files
└── corpus/               # Coverage-guided corpus
```

**Key Features**:

- Single location for all generated outputs
- Legacy paths (top-level `crashes/`, `logs/`, `reports/`) still work for backward compatibility
- `.gitignore` configured to ignore content but preserve structure
- Campaign markdown files are tracked for documentation

## Examples Directory

```
examples/
├── demo/                 # Demonstration scripts
│   ├── README.md         # Demo documentation
│   ├── demo_simple.py    # Simple workflow demo
│   └── demo_workflow.py  # Full framework demo
├── production_fuzzing/   # Production examples
│   └── ...
├── demo_fuzzing.py       # Basic fuzzing demo
├── fuzz_dicom_viewer.py  # Viewer fuzzing example
├── coverage_guided_fuzzing_demo.py # Coverage-guided demo
└── stability_features_demo.py # Stability features demo
```

**Purpose**: Production-ready example code demonstrating framework usage

## Documentation Directory

```
docs/
├── README.md             # Documentation index
├── archive/              # Historical documentation
│   ├── sessions/         # Development session notes
│   └── README.md         # Archive purpose
├── STRUCTURE.md          # This file
├── FUZZING_GUIDE.md      # Fuzzing methodology
├── CRASH_INTELLIGENCE.md # Crash intelligence guide (v1.2.0)
├── STABILITY.md          # Stability features (v1.2.0)
├── TESTING.md            # Testing guide
├── COVERAGE.md           # Test coverage analysis
├── REPORTING.md          # Reporting system
├── 3D_FUZZING_ROADMAP.md # 3D fuzzing roadmap (Phase 1-4)
├── VIEWER_TESTING_3D.md  # 3D viewer testing guide (Phase 3)
├── PERFORMANCE_3D.md     # Performance optimization guide (Phase 4)
├── build/                # Sphinx build output (gitignored)
└── source/               # Sphinx source files
```

**Purpose**: Comprehensive documentation with historical archive

## Docker Directory

```
docker/
├── dcmtk/                # DCMTK Dockerfile
│   └── Dockerfile        # DCMTK with instrumentation
└── orthanc/              # Orthanc Dockerfile
    └── Dockerfile        # Orthanc PACS server
```

**Purpose**: Dockerized fuzzing targets

- `docker-compose.yml` at root orchestrates services
- Individual Dockerfiles define each service

## Test Directory

```
tests/
├── test_*.py             # 976+ test modules
├── conftest.py           # Pytest fixtures
└── __pycache__/          # Python cache (gitignored)
```

**Test Coverage**: 56.10% code coverage, 99.92% pass rate (2583/2585 tests passing)

## Scripts Directory

```
scripts/
├── benchmark_3d_fuzzing.py # Performance benchmarking (Phase 4)
└── ...                     # Other utility scripts
```

**Purpose**: Build, deployment, and maintenance scripts

## Migration from v1.1.0

If you have existing fuzzing outputs, you can either:

1. **Move to new structure** (recommended):

   ```bash
   # Move crashes
   mv crashes/* output/crashes/ 2>/dev/null || true
   mv logs/* output/logs/ 2>/dev/null || true
   mv reports/* output/reports/ 2>/dev/null || true
   mv campaigns/* output/campaigns/ 2>/dev/null || true
   ```

2. **Use legacy paths** (backward compatible):
   - Top-level `crashes/`, `logs/`, `reports/` still work
   - New fuzzing runs use `output/` by default

See [MIGRATION.md](MIGRATION.md) for complete migration guide.

## Benefits of New Structure

1. **Reduced Complexity**: 37% fewer top-level folders (19 → 12)
2. **Clearer Purpose**: Each folder has single, obvious responsibility
3. **Modern Standards**: Aligns with 2025 Python packaging best practices (PyPA, PyOpenSci)
4. **Better .gitignore**: Single `/output/` pattern instead of 5+ scattered patterns
5. **Easier Navigation**: Developers find files faster
6. **Cleaner Git Status**: Less clutter in `git status` output

## Related Documentation

- [README.md](../README.md) - Project overview and quick start
- [docs/README.md](README.md) - Documentation index
- [MIGRATION.md](MIGRATION.md) - Migration guide from v1.1.0
- [docs/FUZZING_GUIDE.md](FUZZING_GUIDE.md) - Fuzzing methodology
