# Changelog

All notable changes to DICOM-Fuzzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2025-12-18 - Network Fuzzing, Advanced Engines, NTIA Compliance

### Added - LLM-Enhanced Fuzzing

- **Adaptive Mutation Selection** (`llm_fuzzer.py`): RL-based mutation scheduling
  - UCB1 algorithm for Multi-Armed Bandit mutation selection (MOpt-style)
  - `AdaptiveMutationSelector` with exploration/exploitation balance
  - `MutationFeedback` and `MutationStatistics` for tracking performance
  - Automatic convergence to optimal mutation strategies
- **Semantic DICOM Fuzzer** (`llm_fuzzer.py`): Protocol-aware fuzzing
  - `SemanticDICOMFuzzer` with deep DICOM protocol understanding
  - Rule-based violations (consistency, mathematical, range, dependency)
  - Inter-element relationship fuzzing
- **LLM Seed Generator** (`llm_fuzzer.py`): AI-assisted seed corpus generation
  - Multiple backends: OpenAI, Anthropic, Ollama (local)
  - Protocol-aware seed generation based on DICOM specifications
  - `create_llm_seed_generator()` convenience function

### Added - DICOM TLS Security Fuzzer

- **TLS Security Testing** (`dicom_tls_fuzzer.py`): Comprehensive TLS vulnerability scanner
  - SSL version testing (SSLv2, SSLv3, TLS 1.0/1.1/1.2/1.3)
  - Weak cipher detection (RC4, DES, export-grade)
  - Certificate validation bypass detection
  - Hostname verification testing
- **DICOM Authentication Testing**: Auth bypass detection
  - AE title enumeration and bruteforce
  - Anonymous association testing
  - `DICOMAuthTester` with configurable wordlists
- **PACS Query Injection**: SQL/LDAP injection testing
  - Wildcard query attacks
  - SQL injection payloads for DICOM queries
  - Path traversal attempts
  - `PACSQueryInjector` with payload generation

### Added - Advanced Fuzzing Engines

- **State-Aware Protocol Fuzzer** (`state_aware_fuzzer.py`): AFLNet-style stateful fuzzing
  - `StateInferenceEngine` for automatic state machine learning
  - `StateCoverage` tracking with Jaccard similarity
  - `StateGuidedHavoc` mutations with state awareness
  - `MessageSequence` for multi-message protocol fuzzing
- **Differential Fuzzer** (`differential_fuzzer.py`): Cross-implementation testing
  - Parser wrappers for pydicom, GDCM, DCMTK
  - Automatic difference detection (parse success, tag values, VR types)
  - Bug severity classification (Critical, High, Medium, Low)
  - `DifferentialAnalyzer` for systematic comparison
- **DICOMweb REST API Fuzzer** (`dicomweb_fuzzer.py`): Web API security testing
  - WADO-RS, STOW-RS, QIDO-RS endpoint fuzzing
  - Multipart/related payload generation
  - Authentication bypass and injection testing
  - `PayloadGenerator` with attack categories
- **Persistent Mode Fuzzer** (`persistent_fuzzer.py`): AFL++ persistent mode
  - In-process fuzzing for 10-100x speedup
  - Power schedules (Fast, COE, Explore, Exploit, Quad)
  - MOpt mutation scheduling with PSO optimization
  - `CoverageMap` with bitmap tracking

### Added - Corpus Minimization & Multi-Fuzzer Sync

- **Corpus Minimizer** (`corpus_minimizer.py`): AFL-cmin style minimization
  - Greedy set-cover algorithm for minimal corpus
  - Coverage-based selection (edges/size ratio)
  - `TargetCoverageCollector` for LLVM coverage
- **Corpus Synchronizer** (`corpus_minimizer.py`): Multi-fuzzer coordination
  - Push, pull, and bidirectional sync modes
  - Deduplication with SHA256 hashing
  - `FuzzerNode` for cluster membership
  - `create_sync_node()` convenience function

### Added - Network Protocol Fuzzing

- **DICOM Network Harness** (`harness/network/dicom_network_harness.py`): AFLNet-style stateful protocol fuzzer
  - Full DICOM Upper Layer Protocol state machine (IDLE, AWAITING_AC, ASSOCIATED, etc.)
  - Support for C-STORE, C-FIND, C-GET, C-MOVE, C-ECHO operations
  - Configurable fuzzing campaigns with iteration control
  - Crash and hang detection with configurable timeouts
- **Network Seed Generator** (`harness/network/seed_generator.py`): Protocol-aware seed corpus
  - Valid PDU generation for all DICOM network operations
  - Malformed seed variants for vulnerability testing
  - Orthanc server fuzzing documentation

### Added - Continuous Fuzzing Integration

- **OSS-Fuzz Structure** (`oss-fuzz/`): Ready for OSS-Fuzz submission
  - Dockerfile, build.sh, project.yaml for ClusterFuzz integration
  - LibFuzzer and AFL++ harness support
  - Sanitizer builds (ASan, UBSan, MSan)
- **GitHub Actions CI** (`.github/workflows/continuous-fuzzing.yml`): Automated fuzzing pipeline
  - AFL++ with AddressSanitizer and fast mode
  - LibFuzzer integration
  - afl-cov coverage reporting
  - Automated crash deduplication and triage
  - GitHub issue creation for unique crashes

### Added - Enhanced Corpus Management

- **MoonLight Minimizer** (`utils/corpus_minimization.py`): Weighted set-cover corpus distillation
  - 3x-100x smaller corpora compared to afl-cmin
  - Weight by file size and execution time
  - Coverage-preserving minimization
- **Coverage-Aware Prioritizer**: Seed scheduling based on coverage contribution
  - Track coverage discovery history
  - Prioritize seeds that find new edges

### Added - FDA 2025 Compliance Updates

- **NTIA SBOM Compliance** (`reporting/sbom.py`): Full NTIA Minimum Elements support
  - All 7 required fields: Supplier Name, Component Name, Version, Unique Identifiers (CPE/PURL/SWID), Dependency Relationship, SBOM Author, Timestamp
  - Known supplier database for common PyPI packages
  - NTIA compliance validation and reporting
  - `validate_sbom_ntia_compliance()` function
- **Patch Timeline Tracking** (`reporting/patch_timeline.py`): FDA vulnerability remediation tracking
  - Severity-based remediation timelines (Critical: 15d, High: 30d, Medium: 90d)
  - Patch lifecycle status tracking
  - SLA compliance metrics
- **Cyber Device Classifier** (`reporting/cyber_device.py`): FDA Section 524B classification
  - Determine if device qualifies as "cyber device"
  - Risk tier assessment (Tier 1/Tier 2)
  - Premarket submission requirements documentation
- **New CVE Patterns** in `security_patterns.py`:
  - CVE-2025-53619: GDCM JPEGBITSCodec OOB read
  - CVE-2025-53618: GDCM JPEG decompression OOB read
  - CVE-2025-11266: GDCM encapsulated PixelData OOB write
  - CVE-2025-1001: RadiAnt certificate validation bypass

## [1.4.0] - 2025-12-17 - FDA Compliance, Response-Aware Fuzzing, CVE Updates

### Added - FDA Compliance Reporting

- **FDA Compliance Reporter** (`reporting/fda_compliance.py`): Generate FDA-compliant fuzz testing reports
  - Markdown and JSON report formats for regulatory submissions
  - Automated compliance evaluation against FDA June 2025 guidance
  - ANSI/ISA 62443-4-1 Section 9.4 alignment documentation
  - `fda-report` CLI subcommand for easy report generation

### Added - Response-Aware Network Fuzzing

- **Response-Aware Fuzzer** (`core/response_aware_fuzzer.py`): Feedback-driven network fuzzing
  - DICOM protocol response parsing (A-ASSOCIATE, A-ABORT, P-DATA-TF)
  - Anomaly detection (timing, crashes, state violations, unexpected responses)
  - Adaptive mutation selection based on response feedback
  - Server fingerprinting for baseline behavior comparison
  - Based on NetworkFuzzer (ARES 2025) research

### Added - CVE Database Updates

- **12 CVE samples** now included (up from 10):
  - CVE-2025-53619: GDCM JPEG codec information disclosure (CVSS 7.5)
  - CVE-2025-1001: RadiAnt certificate validation bypass MitM (CVSS 5.7)
  - CVE-2025-5943: MicroDicom out-of-bounds write (CVSS 8.8)
  - CVE-2025-11266: GDCM PixelData out-of-bounds write (CVSS 6.6)
  - CVE-2025-53618: GDCM JPEG codec out-of-bounds read (CVSS 7.5)

### Added - Documentation

- **CLI Reference** (`docs/CLI_REFERENCE.md`): Complete command-line documentation
- **FDA Compliance Guide** (`docs/FDA_COMPLIANCE.md`): Regulatory submission workflow
- **Example Scripts**: New examples for FDA reporting, security testing, network fuzzing

### Added - CI/CD Enhancements

- **Fuzzing Workflows** (`.github/workflows/fuzzing.yml`): Automated fuzzing in CI
  - PR smoke tests (quick validation)
  - Nightly 8-hour fuzzing campaigns
  - CVE validation on schedule

### Changed

- Updated SECURITY.md with 12 CVE samples table
- Enhanced examples directory with new practical examples
- Code coverage reporting with Codecov integration

## [1.3.0] - 2025-12-09 - Synthetic DICOM & Directory Support

### Added - Synthetic DICOM Generation

- **Synthetic Generator** (`synthetic.py`): Generate valid DICOM files with fabricated data
  - Support for 10 modalities: CT, MR, US, CR, DX, PT, NM, XA, RF, SC
  - Realistic pixel data patterns per modality (anatomical structures, gradients)
  - Series generation with consistent patient/study/series UIDs
  - No PHI concerns - all data is completely synthetic

- **Samples Subcommand** (`samples.py`): CLI for synthetic data and sample sources
  - `dicom-fuzzer samples --generate`: Generate synthetic test files
  - `dicom-fuzzer samples --list-sources`: List public DICOM sample sources
  - Options: `-m MODALITY`, `-c COUNT`, `--series`, `--rows`, `--columns`, `--seed`

### Added - Directory Input Support

- **Directory Scanning**: Accept directories as fuzzing input (not just single files)
  - `--recursive` / `-r` flag for recursive subdirectory scanning
  - Automatic DICOM detection by extension (.dcm, .dicom, .dic) and magic bytes
  - Progress tracking for batch processing with tqdm
  - Per-file mutation count with total estimation

### Added - Dashboard & Distributed Fuzzing

- **Dashboard Module** (`dicom_fuzzer/dashboard/`): Real-time monitoring
  - FastAPI WebSocket server with embedded HTML UI
  - Prometheus metrics exporter for monitoring integration
  - REST API endpoints for stats and crash information

- **Distributed Fuzzing Module** (`dicom_fuzzer/distributed/`): Scalable fuzzing
  - Redis-backed task queue with priority support and in-memory fallback
  - Master coordinator for campaign management
  - Worker nodes for distributed task execution
  - Local worker pool for single-machine parallel fuzzing

### Changed

- Remove emojis from documentation for professional formatting
- Update test coverage: network_fuzzer (97%), gui_monitor (69%)

## [1.2.0] - 2025-12-09 - PyPI Release

This release marks the first public PyPI release of DICOM-Fuzzer with comprehensive documentation, crash intelligence features, performance optimizations, and 5,400+ tests.

### Highlights

- First public PyPI release with modern packaging (Hatchling + Trusted Publishing)
- Crash intelligence with automated triage, test minimization, and stability tracking
- 3D fuzzing with performance optimizations (lazy loading, LRU caching, parallel processing)
- Comprehensive documentation (CONTRIBUTING, QUICKSTART, EXAMPLES, SECURITY, ARCHITECTURE)
- 5,403 tests with 83% coverage

### Added - Crash Intelligence

- **Crash Triaging** (`crash_triage.py`): Automated crash analysis and prioritization
  - 5 severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
  - 4 exploitability ratings with priority scoring (0-100)
  - Automatic indicator extraction (heap corruption, use-after-free, buffer overflows)
- **Test Case Minimization** (`test_minimizer.py`): Delta debugging for crash reduction
  - DDMIN algorithm with 4 minimization strategies
  - Reduces crashing inputs to smallest reproducible form
- **Stability Tracking** (`stability_tracker.py`): AFL++-style stability metrics
  - Execution consistency tracking and non-deterministic behavior detection

### Added - Performance Optimizations

- **Lazy Loading** (`lazy_loader.py`): 10-100x faster metadata-only loading
- **LRU Caching** (`series_cache.py`): 250x faster cache hits with O(1) operations
- **Parallel Processing** (`parallel_mutator.py`): 3-4x faster mutations using ProcessPoolExecutor
- **Benchmarking Infrastructure**: Performance profiling and baseline metrics (157.62 ops/sec)

### Added - Documentation

- `CONTRIBUTING.md`: Development setup, testing guidelines, code style standards
- `docs/QUICKSTART.md`: 5-minute quick start guide
- `docs/EXAMPLES.md`: 14 comprehensive examples with runnable code
- `SECURITY.md`: Vulnerability reporting and compliance guidance (HIPAA, GDPR, FDA)
- `docs/ARCHITECTURE.md`: System design and technical architecture

### Added - Production Tools

- Seed corpus management (import_seed_corpus.py, download_public_seeds.py)
- Docker infrastructure with DCMTK + Orthanc containers
- Target configurations for dcmdump and Orthanc API
- Enhanced HTML reports with crash triage data

### Changed

- **Repository Structure**: 19 folders reduced to 9 (53% complexity reduction)
- **CI/CD**: GitHub Actions with Trusted Publishing (OIDC) for PyPI
- **Test Suite**: Expanded from 930 to 5,403 tests with comprehensive coverage
- **Python Support**: Full compatibility with Python 3.11, 3.12, 3.13, 3.14

### Fixed

- Flaky tests resolved with proper test isolation
- All Ruff and MyPy linting errors fixed
- Deprecated pydicom API calls updated
- Windows path handling in tests

## [1.1.0] - 2025-01-17 - Stability Release

### Added

- **Resource Management** (`resource_manager.py`): Memory, CPU, and disk space limits
- **Enhanced Target Runner** (`target_runner.py`): Retry logic and circuit breaker pattern
- **Error Recovery** (`error_recovery.py`): Checkpoint/resume for long-running campaigns
- **Configuration Validation** (`config_validator.py`): Pre-flight checks

### Changed

- CLI resource limits: `--max-memory`, `--max-cpu-time`, `--min-disk-space`
- Core exports expanded with stability features

### Fixed

- Resource exhaustion in long-running campaigns
- Lost progress on campaign interruption

### Documentation

- `docs/STABILITY.md`: Resource management best practices
- `docs/TROUBLESHOOTING.md`: Complete troubleshooting reference

## [1.0.0] - 2025-01-11 - Initial Release

### Added

- Core fuzzing engine with mutation-based fuzzing
- DICOM parser and generator
- Crash analysis and deduplication
- Coverage tracking capabilities
- Comprehensive test suite (930+ tests, 69% coverage)
- HTML and JSON reporting
- CLI tools for fuzzing operations

### Changed

- **BREAKING**: Major project restructure for modern Python standards
  - Consolidated modules into `dicom_fuzzer` package
  - Updated all imports to use `dicom_fuzzer.` prefix

---

## Planned Features

- Additional LLM backends (Claude via SDK, local Llama models)
- Extended DICOMweb security testing (OAuth/SMART integration)
- Fuzzer cluster orchestration with Kubernetes
- Grammar-based mutation with DICOM PS3.5 conformance

---

**Migration Guide for v1.0.0:**

If upgrading from pre-1.0 versions:

```python
# Old imports:
from core.parser import DicomParser

# New imports:
from dicom_fuzzer.core.parser import DicomParser
# Or use package-level:
from dicom_fuzzer import DicomParser
```

**Output locations:**

- Old: `output/`, `crashes/`, `fuzzed_dicoms/`
- New: `artifacts/crashes/`, `artifacts/fuzzed/`, `artifacts/corpus/`
