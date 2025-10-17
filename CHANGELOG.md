# Changelog

All notable changes to DICOM-Fuzzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-11

### Added
- Initial release of DICOM-Fuzzer
- Core fuzzing engine with mutation-based fuzzing
- DICOM parser and generator
- Crash analysis and deduplication
- Coverage tracking capabilities
- Comprehensive test suite (930+ tests, 69% coverage)
- HTML and JSON reporting
- CLI tools for fuzzing operations
- Demo scripts and examples
- Complete documentation

### Changed
- **BREAKING**: Major project restructure for modern Python standards
  - Consolidated modules into `dicom_fuzzer` package
  - Moved `core/`, `strategies/`, `utils/` into package
  - Renamed `tools/` to `dicom_fuzzer/cli/`
  - Created unified `artifacts/` output directory
  - Added `data/` directory for seeds and dictionaries
  - Updated all imports to use `dicom_fuzzer.` prefix

### Fixed
- Import paths updated across entire codebase
- Package structure now follows Python 2024-2025 best practices
- Cleaned up 87 MB of test artifacts

### Security
- Added `.gitignore` rules for sensitive data
- Enhanced security validation in parsers
- DICOM file sanitization

## [1.1.0] - 2025-01-17 - Stability Release

### Added - Stability Features
- **Resource Management** (`resource_manager.py`): Memory, CPU, and disk space limits
  - Configurable resource limits with soft/hard thresholds
  - Platform-aware enforcement (Unix/Linux full support, Windows disk only)
  - Pre-flight resource availability checks
  - Runtime resource usage monitoring
- **Enhanced Target Runner** (`target_runner.py`): Robust crash detection
  - Automatic retry logic for transient failures (default: 2 retries)
  - Circuit breaker pattern for consistently failing targets
  - Advanced error classification (OOM, resource exhausted, crashes)
  - Retry count tracking in execution results
- **Error Recovery** (`error_recovery.py`): Campaign resumption
  - Checkpoint/resume functionality for long-running campaigns
  - Automatic progress saving (every 100 files by default)
  - Graceful signal handling (SIGINT/SIGTERM)
  - Campaign state persistence in JSON format
- **Configuration Validation** (`config_validator.py`): Pre-flight checks
  - Comprehensive validation before campaign start
  - File system, Python environment, and target validation
  - System resource availability checks
  - Clear error messages and warnings
- **New Test Suites**:
  - `test_target_runner_stability.py`: 35+ stability tests + 9 property-based tests
  - `test_cli_integration.py`: 60+ end-to-end CLI tests
  - `test_stress.py`: Comprehensive stress testing (1000+ files, memory leaks, concurrency)
  - `test_error_scenarios.py`: Error handling validation (corrupted files, resource exhaustion)

### Changed
- **target_runner.py**: Enhanced with retry logic and circuit breaker
  - New parameters: `max_retries`, `enable_circuit_breaker`, `resource_limits`
  - New `ExecutionStatus` values: `OOM`, `RESOURCE_EXHAUSTED`
  - `ExecutionResult` includes `retry_count` field
- **Core exports**: Added stability features to `dicom_fuzzer.core.__init__.py`
  - `ResourceManager`, `ResourceLimits`
  - `CampaignRecovery`, `CampaignStatus`, `SignalHandler`
  - `ConfigValidator`, `ValidationResult`
  - `TargetRunner`, `ExecutionStatus`
- **CLI Integration** (`main.py`): Resource limits now configurable via command-line
  - `--max-memory MB`: Memory soft limit (Unix/Linux/macOS)
  - `--max-memory-hard MB`: Memory hard limit (Unix/Linux/macOS)
  - `--max-cpu-time SEC`: CPU time limit (Unix/Linux/macOS)
  - `--min-disk-space MB`: Minimum free disk space (all platforms)

### Fixed
- Resource exhaustion in long-running campaigns
- Lost progress on campaign interruption
- Unclear error messages for configuration issues
- Runaway processes consuming system resources

### Documentation
- **NEW**: `docs/STABILITY.md` - Comprehensive stability guide
  - Resource management best practices
  - Error recovery patterns
  - Platform support matrix
  - Migration guide from 1.0 to 1.1
  - Performance impact analysis
- **NEW**: `docs/TROUBLESHOOTING.md` - Complete troubleshooting reference
  - Installation and setup issues
  - File generation problems
  - Target testing troubleshooting
  - Resource limit configuration
  - Performance optimization tips
  - Platform-specific solutions (Windows/macOS/Linux)
  - Error codes and log message reference

### Test Coverage
- **validator.py**: 100% coverage (was 16.67%)
- **helpers.py**: 100% coverage (was 27.61%)
- **logger.py**: 100% coverage (was 40.98%)
- Overall project coverage maintained at ~20%

## [Unreleased]

### Added
- **Python 3.14 Support**: Full compatibility with Python 3.14
  - Updated pyproject.toml classifiers and black configuration
  - Updated CI/CD workflows to test against Python 3.14
  - Updated pre-commit hooks to use Python 3.14
  - Updated documentation (installation, testing guides)

### Planned
- Enhanced coverage-guided fuzzing
- Network fuzzing support (DICOM C-STORE, C-FIND)
- Distributed fuzzing across multiple machines
- Additional mutation strategies

---

**Migration Guide for v1.0.0:**

If upgrading from pre-1.0 versions:

**Old imports:**
```python
from core.parser import DicomParser
from strategies.pixel_fuzzer import PixelFuzzer
from utils.helpers import validate_dicom
```

**New imports:**
```python
from dicom_fuzzer.core.parser import DicomParser
from dicom_fuzzer.strategies.pixel_fuzzer import PixelFuzzer
from dicom_fuzzer.utils.helpers import validate_dicom
```

**Or use package-level imports:**
```python
from dicom_fuzzer import DicomParser
```

**Output locations:**
- Old: `output/`, `crashes/`, `fuzzed_dicoms/`
- New: `artifacts/crashes/`, `artifacts/fuzzed/`, `artifacts/corpus/`
