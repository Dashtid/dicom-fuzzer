# Changelog

All notable changes to DICOM-Fuzzer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`EmptyValueFuzzer`** -- new format fuzzer targeting the .NET
  "present but empty" crash pattern. Adds nine structural attacks that
  insert target tags with zero-length values (or, for comma-decimal,
  locale-incompatible strings patched at the byte level). Each attack
  maps to a fixed fo-dicom issue: empty PixelSpacing (#2043), empty
  VOILUTFunction (#1891), empty SpecificCharacterSet (#1879), empty
  ImagePositionPatient/ImageOrientationPatient (#2067), zero/negative
  WindowWidth (#1905), comma-as-decimal DS values (#1296), empty
  SharedFunctionalGroupsSequence (#1884), and empty WindowCenter.
  Comma-decimal substitution runs in `mutate_bytes()` because pydicom
  validates DS values as floats on assignment. Registered in
  `DicomMutator` (now 20 format + 10 multiframe = 30 strategies).

- **`StructureFuzzer` binary VR corruption** -- four new binary-level
  attacks in `StructureFuzzer.mutate_bytes()` that rewrite the 2-byte
  VR field of a randomly selected short-VR element (length-preserving
  in-place byte substitution). Each attack maps to a fo-dicom VR
  detection issue: `_binary_whitespace_vr` sends `0x20 0x0A` (#1847),
  `_binary_null_vr` sends `0x00 0x00`, `_binary_dash_vr` sends `"--"`
  (#1660, parser returns `DicomReaderResult.Suspended`), and
  `_binary_vr_un_substitution` sends `"UN"` (#1941, forces the parser
  to read a 4-byte length from bytes that were originally a 2-byte
  length, causing total desync of every subsequent element). The
  binary attack pool in `StructureFuzzer.mutate_bytes` grows from 3
  to 7 attacks; the 1-2-per-call sampling window is unchanged.

- **`CompressedPixelFuzzer` binary encapsulation attacks** -- six new
  binary-level attacks in a new `CompressedPixelFuzzer.mutate_bytes()`
  override that corrupt encapsulated pixel data fragment structures
  post-serialization. Each attack targets a distinct fragment parsing
  bug that pydicom normalizes away at the Dataset level:
  `_binary_ultra_short_fragment` (CVE-2025-11266, GDCM underflow on
  fragments with 0-2 bytes), `_binary_remove_sequence_delimiter`
  (fo-dicom #1339, parser reads past EOF), `_binary_delimiter_in_fragment`
  (pydicom #1140, premature truncation on embedded delimiter bytes),
  `_binary_zero_length_final_fragment` (fo-dicom #1586, empty allocation
  crash), `_binary_orphan_delimiter_at_eof` (fo-dicom #1958, state machine
  re-entry outside sequence context), and `_binary_fragment_offset_underflow`
  (CVE-2025-11266 arithmetic, BOT entry exceeds data size causing
  unsigned underflow). A `_find_encapsulated_region()` helper locates
  the Pixel Data element in raw bytes, handling both Explicit and
  Implicit VR layouts. Strategy count unchanged (CompressedPixelFuzzer
  was already registered; this adds a `mutate_bytes()` override).

- **Overlay attacks** -- three new structural attacks in `PixelFuzzer`
  targeting DICOM overlay rendering: `_negative_overlay_origin`
  (fo-dicom #1559, negative coordinates cause IndexOutOfRange in
  overlay compositing), `_overlay_dimension_mismatch` (overlay
  dimensions vastly exceed image dimensions, causing OOM or buffer
  overread), and `_overlay_bit_position` (fo-dicom #2087, non-zero
  OverlayBitPosition with BitsAllocated=1 causes undefined bit
  extraction behavior).

- **Private SQ at EOF** -- new `_private_sq_at_eof` attack in
  `PrivateTagFuzzer` (fo-dicom #487, #220). Appends a private
  Sequence with empty items at Tag(0x7FFF,0x1001), which sorts after
  PixelData and lands at or near EOF. Parser's `IsPrivateSequence()`
  peeks past the final sequence delimiter, reading past EOF.

- **Odd-length pixel data** -- new `PixelFuzzer.mutate_bytes()` override
  with `_binary_odd_length_pixel_data` (fo-dicom #1403). Locates native
  (non-encapsulated) Pixel Data in raw bytes, subtracts 1 from the
  length field, and removes the padding byte. Violates DICOM Part 5
  Section 8 even-length requirement, triggering padding/truncation bugs.

- **CVE-to-strategy coverage matrix** -- `docs/CVE_AUDIT.md`
  mapping ~130 DICOM CVEs (2022-2026) against 30 mutation strategies.
  Identifies 16 covered trigger patterns (~81% of file-parsing CVEs)
  and 13 gaps (G1-G13) driving new backlog items across P1 and P2.
  Deep-dive research covered DCMTK (27 CVEs), GDCM (9), Sante (26+),
  MicroDicom (7), Orthanc (9), libdicom (2), MedDream (10+), OsiriX
  (3), plus ~40 fo-dicom crash issues with no formal CVEs.

- **P1 CVE quick wins (7 gaps)** -- implements G1, G4, G6, G8, G9,
  G12, G13 from the CVE audit: PALETTE COLOR + LUT overflow
  (CVE-2026-5443, CVE-2024-22391), HighBit >= BitsAllocated
  (CVE-2024-52333), Photometric YBR codec mismatch (CVE-2025-53618),
  OverlayData truncation (fo-dicom #1728), UL-as-US dimension VR
  confusion (CVE-2026-5442), non-standard VR in file meta
  (CVE-2026-3650, UNPATCHED), and format string injection
  (CVE-2024-23914). Extends PixelFuzzer (4 attacks),
  StructureFuzzer (2 binary attacks, pool 7->9), and HeaderFuzzer
  (format string payloads in 5 string VR types). Pushes CVE
  coverage from ~82% to ~95%.

- **P1 CVE medium effort (3 gaps)** -- implements G2, G7, G10:
  `_corrupt_jpegls_codestream` in CompressedPixelFuzzer adds
  JPEG-LS Lossless transfer syntax with 4 malformed codestream
  variants (DCMTK CVE-2025-2357). `_voi_lut_corruption` in
  CalibrationFuzzer adds VOI LUT Sequence with descriptor/data
  mismatches and type confusion (DCMTK CVE-2024-28130, fo-dicom
  #1062). `_binary_duplicate_meta_tag` in StructureFuzzer
  duplicates a group 0002 element to trigger UAF in parsers with
  hash-map destroy-on-collision (libdicom CVE-2024-24793/24794).

## [1.10.1] - 2026-04-09 - Unbundle seed corpus

Course-correction on the "bundled PHI-free seed corpus" feature shipped in
1.10.0. The bundled files were too downscaled to exercise realistic parser
code paths (e.g. 128x128 CT stubs where clinical data is 512x512), and
shipping sample data alongside the tool mixed concerns between "fuzzer" and
"dataset". Users should bring their own clinical seeds (sanitized with
`dicom-fuzzer sanitize`) or generate synthetic ones with `generate-seeds`.

### Removed

- **Bundled `dicom-seeds/` `.dcm` files** -- all 9 modality sample files
  deleted from version control. The directory scaffolding (modality
  subfolders, `.gitkeep` files, README) is retained as a local template.
- **`.gitignore` exception** for `/dicom-seeds/**/*.dcm` -- removed. The
  general `*.dcm` exclusion now applies everywhere, including `dicom-seeds/`,
  acting as a last-line PHI-leak defense.

### Changed

- **`dicom-seeds/README.md`** -- rewritten to reflect its new purpose as a
  local-only seed-building area. Documents sourcing guidance (public datasets,
  `generate-seeds` for synthetic, `sanitize` for in-house clinical data) and
  notes that `-c N` is per-seed-file, not total.

## [1.10.0] - 2026-04-08 - Reproducibility, Safety & CLI Expansion

Feature release focused on reproducible fuzzing campaigns, PHI handling, and
CLI surface area. Also includes a major CLI architecture refactor (SubcommandBase
ABC) and reweighted mutation dispatch to favour structural attacks.

### Added

- **`dicom-fuzzer sanitize` subcommand** -- strips PHI from seed files using the
  shared patient anonymization utility. Runs on entire directories.
- **`--safety-mode` flag** -- preserves critical DICOM tags during mutation so
  fuzzed files remain parseable enough to exercise viewer code paths.
- **`dicom-fuzzer triage` subcommand** -- exposes `CrashTriageEngine` via CLI for
  severity and exploitability scoring of captured crashes.
- **`dicom-fuzzer replay --decompose`** -- decomposes a fuzzed file into its
  individual mutations for delta debugging.
- **PHI-free DICOM seed corpus** -- bundles sanitized samples for all 9 modalities
  so users can run campaigns without providing their own data.
- **`PixelReencodingFuzzer`** -- pure-Python RLE Lossless re-encoding attack for
  pixel data transfer syntax fuzzing.
- **Seeded fuzzer engine** -- `--seed` surfaced in `FuzzingSession` JSON and
  campaign console output, making crash reproduction deterministic.
- **Pixel attacks**: `byte_flip` and `fill_pattern` raw PixelData mutations.
- **Strategy hit-rate telemetry** -- per-strategy hit counts and
  `crash_by_strategy` now appear in session reports and HTML campaign output.
- **Binary mutation tracking** -- `MutationRecord` gains a `variant` field and
  binary mutations are recorded in `mutation_map.json` for replay.

### Changed

- **Mutation dispatch reweighted** -- structural attacks now receive higher
  weight than content mutations in the default dispatch pool, improving hit
  rates on parser-layer bugs.
- **`pixel_fuzzer` strengthened** -- dropped low-value content mutations in
  favour of structural attacks; added 5 missing tag attack methods.
- **`can_mutate()` guards** -- added to all 8 multiframe strategies so
  dispatch skips incompatible datasets cleanly instead of raising.
- **Pre-flight dependency check** -- now covers all optional packages
  (`psutil`, `minidump`, `tqdm`, `rich`, `matplotlib`, `jinja2`, `pywinauto`).

### Refactored

- **`SubcommandBase` ABC** -- all 11 CLI subcommands migrated to a shared
  base class, eliminating duplicated argparse/handler boilerplate.
- **`CrashRecord` moved to `core/crash/models.py`** -- fixes a dependency
  inversion where the crash analyzer imported from the reporter.
- **Patient anonymization extracted to `utils/anonymizer.py`** -- single
  source of truth for PHI handling, shared between `sanitize` and session code.
- **`MultiFrameMutationRecord` moved to attacks layer** -- and dead sibling
  types deleted.
- **Injection payloads centralized** -- `_INJECTION_PAYLOADS` removed from
  `encapsulated_pdf_fuzzer` in favour of `dicom_dictionaries`.
- **`reports.py` CLI separated from utility library** -- report generation
  internals no longer coupled to CLI wiring.

### Fixed

- Code scanning alerts resolved.
- Flaky Python 3.13 test failures in `structure` and `pixel_fuzzer` tests.
- Metadata fuzzer test regressions caused by structural-pool changes.
- `private_tag_fuzzer` tests updated for 9-strategy dispatch pool.
- Stale test assertions across the board after main-branch changes.

## [1.9.1] - 2026-03-15 - Architecture Unification & Cleanup

Refactoring release. No new attack surface. Focuses on pipeline unification,
payload centralization, and removing stale dead code.

### Changed

- **Multiframe strategies unified** -- All 10 multiframe strategies now extend
  `MultiFrameFuzzerBase(FormatFuzzerBase)` and are registered with `DicomMutator`.
  `MultiFrameHandler`, `MutationStrategyBase`, and `create_multiframe_mutator` deleted.
  `DicomMutator` now runs 28 strategies (18 format + 10 multiframe) in one pipeline.

- **Attack payloads centralized** -- `SOP_CLASS_BY_MODALITY`, `TRANSFER_SYNTAX_BY_NAME`,
  `INVALID_PN_VALUES`, `INVALID_DATES`, and `INVALID_TIMES` moved to `dicom_dictionaries.py`.
  `ConformanceFuzzer` and `MetadataFuzzer` use aliased imports; all call sites unchanged.

- **Strategy hit-rate wired into HTML reports** -- Fixed `GenerationStats` data loss bug
  (reset on every `generate_batch()` call). Per-strategy hit counts now appear in the
  campaign HTML report.

### Removed

- **CVE module** (`dicom_fuzzer/cve/`) -- removed. CVE attack patterns are embedded in the
  format fuzzers (`attacks/format/`). The standalone `dicom-fuzzer cve` CLI command is removed.
- **Crash-timeline dead code** -- `crash_timeline` accumulator and `get_crash_timeline()`
  deleted. No production callers.
- **`test_multiframe_handler.py`** (396-line test file for deleted handler)

## [1.9.0] - 2026-03-10 - Modality Fuzzers & Codebase Hardening

Major feature release adding 6 modality-specific fuzzers, a seed-corpus generation CLI,
and systematic dead code removal across the entire codebase.

### Added - Modality Fuzzers

- **EncapsulatedPdfFuzzer** - 4 attack methods targeting PDF structure corruption and type confusion
- **SegmentationFuzzer** - 4 attack methods for SEG label/frame/algorithm manipulation
- **NuclearMedicineFuzzer** - 5 attack methods including decay correction and scan arc attacks
- **PetFuzzer** - 4 SUV/decay attack strategies with time reversal attacks
- **RTStructureSetFuzzer** - 5 contour/ROI attack strategies with invalid interpreted types
- **RTDoseFuzzer** - 5 attack methods (25 variants) including invalid DVH types

### Added - CLI & Engine

- **`generate-seeds` subcommand** - Generate mutated DICOM files to disk for AFL/WinAFL seed corpora
- **Crash timeline tracking** - `CrashAnalyzer.crash_timeline` records unique crash discovery over time
- **Cumulative strategy hit counts** - `DICOMGenerator.cumulative_strategies` accumulates across batches
- **Persistent file logging** - Auto-generated log paths for campaign runs
- **Structured logging for campaigns** - Run isolation and structured log output
- **GUI warmup phase** - Viewer warmup before fuzzing, increased timeout to 15s

### Changed - Codebase Cleanup

- Systematic review of all `core/` subpackages: dicom, mutation, engine, corpus, session, crash, harness, reporting, analytics
- Replaced f-string logging with lazy `%s` formatting throughout
- Fixed `datetime.utcnow()` deprecation with timezone-aware `datetime.now(UTC)`
- Removed ~40 dead functions, unused constants, dead re-exports, and orphan test files
- Removed `ByteMutator`, `MutationSeverity`, unused pydantic config, legacy method aliases
- Extracted shared radiopharmaceutical attacks from NM and PET fuzzers
- Removed 10 dead HTML template helpers and `SEVERITY_COLORS` dict
- Fixed cross-module HTML nesting (content div now owned by report orchestrator)
- Generator serialization robustness improved from 0.8% to 97% yield

### Changed - Tests

- Restructured test directory to mirror source tree layout
- Added cross-fuzzer contract tests for all 12 format fuzzers
- Added mutation verification tests for all fuzzers (Phases 1-4)
- Added round-trip serialization tests (39 tests)
- Added end-to-end integration tests for DICOMGenerator pipeline (15 tests)
- Total test count: ~4,975

### Fixed

- Strategy hit-count data loss across `generate_batch()` calls
- Crash detection wiring into session/report pipeline
- Ghost files and lost mutations in generation output
- pydicom deprecation warnings and log noise suppression
- Campaign log errors from 500-file fuzzing runs
- ReferenceFuzzer collecting ref_items before add_new
- Missing `super().__init__()` in 4 format fuzzers
- 37+ CodeQL code scanning alerts resolved

### Security

- Resolved all CodeQL and Semgrep security alerts
- Bumped cryptography dependency for CVE fixes
- Trimmed CI/CD pipeline and fixed CodeQL configuration

## [1.8.0] - 2026-01-13 - Phase 2 Technical Debt Reduction

Major refactoring release focused on modularization, maintainability, and test coverage.

### Changed - Module Splits

- **TLS Fuzzer** (`dicom_tls_fuzzer.py`): Split from ~1000 lines into:
  - `tls_security_tester.py` - TLS handshake and certificate testing
  - `tls_types.py` - TLS-related type definitions
  - `dicom_auth_tester.py` - DICOM authentication testing
  - `pacs_query_fuzzer.py` - PACS query fuzzing

- **Target Harness** (`target_harness.py`): Split into `harness/` subpackage:
  - `harness/harness.py` - Core harness functionality
  - `harness/monitoring.py` - Process monitoring
  - `harness/types.py` - Type definitions (TargetConfig, TestResult, etc.)

- **Stateful Fuzzer** (`stateful_fuzzer.py`): Split into `stateful/` subpackage:
  - `stateful/fuzzer.py` - Main fuzzer logic
  - `stateful/state_machine.py` - State machine implementation
  - `stateful/sequence_generator.py` - Test sequence generation
  - `stateful/timing_attacks.py` - Timing attack strategies
  - `stateful/resource_attacks.py` - Resource exhaustion attacks

- **Enhanced Reporter** (`enhanced_reporter.py`): Split into `reporting/` subpackage:
  - `reporting/formatters.py` - Output formatting
  - `reporting/analytics.py` - Statistical analysis
  - `reporting/compliance.py` - Compliance reporting
  - `reporting/enrichers.py` - Report enrichment

- **Multiframe Handler** (`multiframe_handler.py`): Split into `multiframe_strategies/`:
  - Individual strategy files for frame count, timing, dimension overflow, etc.

- **Medical Device Security** (`medical_device_security.py`): Split into `medical_device/`:
  - `medical_device/fuzzer.py` - Main fuzzer
  - `medical_device/types.py` - Type definitions

### Added

- `constants.py` - Centralized constants (CVE registry, DICOM limits, etc.)
- `coverage_types.py` - Coverage-related type definitions
- `state_coverage.py` - State-based coverage tracking
- `gui_fuzzer.py` - GUI-specific fuzzing logic
- `gui_monitor_types.py` - GUI monitoring types

### Added - Tests

- 50+ new test files covering refactored modules
- Test coverage maintained at 90%+ line coverage
- Assertion density improvements across test suite

### Fixed

- CI Coverage Comment workflow now handles missing coverage.xml gracefully
- OOM issues in test groups resolved with gc.collect() optimization
- E2E CLI tests fixed with proper async mock handling

## [1.7.2] - 2025-12-24 - CVE Mutations Enabled by Default

Security-focused release that integrates CVE-based mutations into the default fuzzing pipeline.

### Changed

- **CVE mutations now enabled by default** in `CoverageGuidedMutator`
  - 9 CVE mutation categories with 2x higher initial weight
  - Targets 12+ real DICOM vulnerabilities automatically
  - No `--security-fuzz` flag required for basic CVE coverage

### Added

- **New CVE mutation types** in coverage-guided mutator:
  - `cve_heap_overflow` - CVE-2025-5943 (MicroDicom pixel data parsing)
  - `cve_integer_overflow` - CVE-2025-5943 (dimension overflow)
  - `cve_malformed_length` - CVE-2020-29625 (DCMTK length fields)
  - `cve_path_traversal` - CVE-2021-41946 (filename path traversal)
  - `cve_deep_nesting` - CVE-2022-24193 (OsiriX DoS)
  - `cve_polyglot` - CVE-2019-11687 (PE/ELF preamble injection)
  - `cve_encapsulated_pixel` - CVE-2025-11266 (GDCM PixelData)
  - `cve_jpeg_codec` - CVE-2025-53618/53619 (GDCM JPEG codec)
  - `cve_random` - Random CVE from registry

- **CVE mutation statistics tracking** via `get_cve_mutation_stats()`
- **Generators package** (`dicom_fuzzer/generators/`) for proper imports
- **New mutator parameters**:
  - `security_aware` (default: True) - Enable/disable CVE mutations
  - `cve_mutation_probability` (default: 0.2) - CVE selection probability

### Fixed

- Broken imports in `samples.py` CLI - now uses `dicom_fuzzer.generators.*`
- Windows-only test skip for `ctypes.windll` in CI

### Documentation

- Updated README with CVE mutation feature highlight
- Updated CLI_REFERENCE.md with CVE mutation table and options

## [1.7.1] - 2025-12-24 - Test Cleanup

- Removed disabled test files (Phase 2 cleanup)
- Fixed CI coverage comment length limit
- Fixed Windows-only test decorators

## [1.7.0] - 2025-12-22 - 3D Medical Application Fuzzing

Enhanced fuzzing for 3D medical imaging applications that process patient studies.

### Added - Study-Level Framework

- **StudyMutator** (`strategies/study_mutator.py`, ~700 lines): Multi-series study coordination
  - Cross-series reference attacks (ReferencedSeriesSequence corruption)
  - FrameOfReferenceUID manipulation for registration/fusion attacks
  - Patient consistency attacks across series (conflicting demographics)
  - StudyInstanceUID mismatch injection
  - Mixed modality study injection

### Added - 3D Reconstruction Attack Vectors

- **Enhanced Series Mutations** (`strategies/series_mutator.py`, +530 lines):
  - Non-orthogonal ImageOrientationPatient vectors (invalid reconstruction basis)
  - Systematic slice gap injection (missing slice handling)
  - Slice overlap attacks (multiple slices at same Z-position)
  - Voxel aspect ratio extremes (non-isotropic spacing exploitation)
  - Frame of reference UID corruption

### Added - Measurement/Calibration Fuzzing

- **CalibrationFuzzer** (`strategies/calibration_fuzzer.py`, ~500 lines): Measurement bypass attacks
  - PixelSpacing vs ImagerPixelSpacing mismatch (7 attack types)
  - RescaleSlope/Intercept extreme values (6 attack types for HU corruption)
  - WindowCenter/WindowWidth edge cases (6 attack types)
  - SliceThickness attacks (3 attack types)

### Added - Memory & Stress Testing

- **StressTester** (`dicom_fuzzer/harness/stress_tester.py`, ~450 lines): Resource exhaustion testing
  - Large series generation (1000+ slices, configurable dimensions)
  - Memory usage estimation and monitoring
  - Incremental loading attacks (partial/interrupted series)
  - Escalating stress test campaigns

### Added - Tests

- `tests/test_strategies/test_study_mutator.py` - 15 tests
- `tests/test_strategies/test_calibration_fuzzer.py` - 26 tests
- `tests/test_harness/test_stress_tester.py` - 35 tests

## [1.6.0] - 2025-12-22 - CLI Subcommands & CVE Mutations

### Added

- **CLI Subcommands**: Advanced fuzzing accessible via command line
  - `dicom-fuzzer llm` - LLM-assisted mutation generation
  - `dicom-fuzzer tls` - TLS/authentication security testing
  - `dicom-fuzzer differential` - Cross-parser differential testing
  - `dicom-fuzzer persistent` - AFL++ persistent mode fuzzing
  - `dicom-fuzzer state` - Protocol state machine fuzzing
  - `dicom-fuzzer corpus` - Corpus management and minimization
- **CVE Mutation Strategies** (`strategies/cve_mutations.py`): Targeted vulnerability patterns
  - Heap overflow triggers (oversized buffers)
  - Integer overflow in length fields
  - Path traversal payloads
  - Polyglot file generation
- **SBOM Generation**: CycloneDX SBOM in CI security workflow
- **CLI Test Coverage**: 241 new tests for previously uncovered CLI modules
  - `test_cli_state.py` (22 tests) - state-aware fuzzing CLI
  - `test_cli_persistent.py` (19 tests) - AFL-style persistent mode CLI
  - `test_cli_tls.py` (19 tests) - TLS security testing CLI
  - `test_cli_llm.py` (20 tests) - LLM-assisted mutation CLI
  - `test_cli_differential.py` (27 tests) - cross-parser testing CLI
  - `test_cli_corpus.py` (30 tests) - corpus management CLI
  - `test_cli_samples.py` (48 tests) - synthetic sample generation CLI
  - `test_response_aware_fuzzer.py` (56 tests) - response-aware network fuzzer

### Removed

- **DICOMweb Support**: Removed DICOMweb/WADO-RS functionality (out of scope)
  - Removed `dicom_fuzzer/network/dicomweb_fuzzer.py`
  - Removed httpx dependency and related code
  - Focus remains on DICOM network protocol fuzzing

### Changed

- **Test Suite Optimization**: Reduced from 6,790 to 4,302 tests (-37%)
  - Removed 66 duplicate/coverage-gaming test files
  - Eliminated 40,494 lines of redundant test code
  - Improved test-to-code ratio from 2:1 to 1.3:1 (industry standard)
  - Maintained 72% code coverage

### Fixed

- Fixed pyproject.toml optional-dependencies configuration
  - Added proper `[project.optional-dependencies]` section
  - Resolved uv warnings about missing extras
- Corrected cyclonedx-py command syntax (`--of` instead of `--format`)
- Fixed GeneratedMutation API usage in LLM CLI module
- Resolved mypy type errors in corpus statistics

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

- **DICOM Network Harness** (`strategies/network/`): AFLNet-style stateful protocol fuzzer
  - Full DICOM Upper Layer Protocol state machine (IDLE, AWAITING_AC, ASSOCIATED, etc.)
  - Support for C-STORE, C-FIND, C-GET, C-MOVE, C-ECHO operations
  - Configurable fuzzing campaigns with iteration control
  - Crash and hang detection with configurable timeouts
- **Network Seed Generator** (`strategies/network/`): Protocol-aware seed corpus
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

## Community Contributions Welcome

- Additional CVE mutation patterns for newly disclosed vulnerabilities
- Viewer-specific profiles for untested DICOM applications
- Performance optimizations for large series processing

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
