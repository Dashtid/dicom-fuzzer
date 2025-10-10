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

## [Unreleased]

### Planned
- Enhanced coverage-guided fuzzing
- Network fuzzing support (DICOM C-STORE, C-FIND)
- Integration with CI/CD pipelines
- Performance optimizations
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
