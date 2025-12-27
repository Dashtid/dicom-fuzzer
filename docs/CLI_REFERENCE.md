# CLI Reference

Complete command-line reference for DICOM Fuzzer.

## Table of Contents

- [Overview](#overview)
- [Main Command](#main-command)
- [Subcommands](#subcommands)
  - [samples](#samples-subcommand)
  - [fda-report](#fda-report-subcommand)
- [Options Reference](#options-reference)
- [Examples](#examples)

## Overview

DICOM Fuzzer provides a comprehensive CLI for security testing of DICOM implementations:

```bash
# Standard invocation
python -m dicom_fuzzer.cli [OPTIONS] INPUT

# Using uv (recommended)
uv run python -m dicom_fuzzer.cli [OPTIONS] INPUT

# Subcommands
python -m dicom_fuzzer.cli samples [OPTIONS]
python -m dicom_fuzzer.cli fda-report [OPTIONS]
```

## Main Command

Generate fuzzed DICOM files and optionally test target applications.

```bash
python -m dicom_fuzzer.cli INPUT [OPTIONS]
```

### Required Arguments

| Argument | Description                     |
| -------- | ------------------------------- |
| `INPUT`  | Path to DICOM file or directory |

### Common Options

| Option                   | Default               | Description                                                 |
| ------------------------ | --------------------- | ----------------------------------------------------------- |
| `-c, --count N`          | 100                   | Number of fuzzed files to generate                          |
| `-o, --output DIR`       | ./artifacts/campaigns | Output directory                                            |
| `-s, --strategies STRAT` | all                   | Comma-separated strategies: metadata,header,pixel,structure |
| `-r, --recursive`        | false                 | Recursively scan input directory                            |
| `-v, --verbose`          | false                 | Enable verbose logging                                      |
| `--version`              | -                     | Show version                                                |

### Target Testing Options

| Option                | Default | Description                            |
| --------------------- | ------- | -------------------------------------- |
| `-t, --target EXE`    | -       | Path to target application             |
| `--timeout SEC`       | 5.0     | Timeout per test in seconds            |
| `--stop-on-crash`     | false   | Stop on first crash                    |
| `--gui-mode`          | false   | GUI application mode (requires psutil) |
| `--memory-limit MB`   | -       | Memory limit for GUI mode              |
| `--startup-delay SEC` | 0.0     | Delay before monitoring in GUI mode    |

### Resource Limits (Unix/Linux only)

| Option                 | Default | Description                    |
| ---------------------- | ------- | ------------------------------ |
| `--max-memory MB`      | 1024    | Maximum memory (soft limit)    |
| `--max-memory-hard MB` | 2048    | Maximum memory (hard limit)    |
| `--max-cpu-time SEC`   | 30      | Maximum CPU time per operation |
| `--min-disk-space MB`  | 1024    | Minimum required disk space    |

### Network Fuzzing Options

| Option                     | Default   | Description                                                                                                                                   |
| -------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `--network-fuzz`           | false     | Enable DICOM network protocol fuzzing                                                                                                         |
| `--host HOST`              | localhost | Target DICOM server host                                                                                                                      |
| `--port PORT`              | 11112     | Target DICOM server port                                                                                                                      |
| `--ae-title TITLE`         | FUZZ_SCU  | AE Title for network fuzzing                                                                                                                  |
| `--network-strategy STRAT` | all       | Strategy: malformed_pdu, invalid_length, buffer_overflow, integer_overflow, null_bytes, unicode_injection, protocol_state, timing_attack, all |

### Security Testing Options

**Note:** CVE-based security mutations are now **enabled by default** in the coverage-guided mutator. The fuzzer automatically applies mutations targeting real DICOM vulnerabilities during standard fuzzing.

| Option                   | Default | Description                                     |
| ------------------------ | ------- | ----------------------------------------------- |
| `--security-fuzz`        | false   | Enable extended medical device security fuzzing |
| `--target-cves CVES`     | all     | Comma-separated CVE patterns                    |
| `--vuln-classes CLASSES` | all     | Comma-separated vulnerability classes           |
| `--security-report FILE` | -       | Output file for security report (JSON)          |
| `--no-security`          | false   | Disable CVE mutations (not recommended)         |

#### CVE Mutations (Enabled by Default)

The fuzzer includes **26 mutations across 20 CVEs** applied automatically. See [CVE_REFERENCE.md](CVE_REFERENCE.md) for the complete list.

**Vulnerability classes:** oob_write, oob_read, stack_overflow, heap_overflow, integer_overflow, format_string, null_deref, dos

### Response Monitoring Options

| Option                  | Default | Description                               |
| ----------------------- | ------- | ----------------------------------------- |
| `--response-aware`      | false   | Enable response-aware fuzzing             |
| `--detect-dialogs`      | false   | Detect error dialogs (requires pywinauto) |
| `--memory-threshold MB` | 1024    | Memory threshold for spike detection      |
| `--hang-timeout SEC`    | 30.0    | Timeout for hang detection                |

## Subcommands

### study Subcommand (v1.7.0)

Study-level DICOM mutation for cross-series attacks.

```bash
python -m dicom_fuzzer.cli study [OPTIONS]
```

#### Actions

| Action              | Description                                     |
| ------------------- | ----------------------------------------------- |
| `--study DIR`       | Path to study directory containing DICOM series |
| `--list-strategies` | List available study mutation strategies        |

#### Mutation Options

| Option             | Default  | Description                                                                                |
| ------------------ | -------- | ------------------------------------------------------------------------------------------ |
| `--strategy STRAT` | all      | cross-series, frame-of-reference, patient-consistency, study-metadata, mixed-modality, all |
| `--severity LEVEL` | moderate | minimal, moderate, aggressive, extreme                                                     |
| `-c, --count N`    | 5        | Number of mutations to apply                                                               |

#### Output Options

| Option             | Default           | Description      |
| ------------------ | ----------------- | ---------------- |
| `-o, --output DIR` | ./artifacts/study | Output directory |
| `-v, --verbose`    | false             | Verbose output   |

#### Examples

```bash
# Mutate study with cross-series reference attacks
dicom-fuzzer study --study ./patient_study --strategy cross-series -o ./output

# List available strategies
dicom-fuzzer study --list-strategies

# Apply aggressive patient consistency attacks
dicom-fuzzer study --study ./study --strategy patient-consistency --severity aggressive
```

---

### study-campaign Subcommand (v1.8.0)

Study-level fuzzing campaign with target application testing. Combines study mutation with automated target execution, crash detection, and artifact collection.

```bash
python -m dicom_fuzzer.cli study-campaign [OPTIONS]
```

#### Required Arguments

| Argument       | Description                    |
| -------------- | ------------------------------ |
| `--target EXE` | Path to target application     |
| `--study DIR`  | Path to source study directory |

#### Actions

| Action              | Description                              |
| ------------------- | ---------------------------------------- |
| `--list-strategies` | List available study mutation strategies |

#### Mutation Options

| Option             | Default  | Description                                                                                |
| ------------------ | -------- | ------------------------------------------------------------------------------------------ |
| `--strategy STRAT` | all      | cross-series, frame-of-reference, patient-consistency, study-metadata, mixed-modality, all |
| `--severity LEVEL` | moderate | minimal, moderate, aggressive, extreme                                                     |
| `-c, --count N`    | 100      | Number of test iterations                                                                  |

#### Target Testing Options

| Option                | Default | Description                     |
| --------------------- | ------- | ------------------------------- |
| `--timeout SEC`       | 15.0    | Target timeout in seconds       |
| `--memory-limit MB`   | 2048    | Memory limit in MB              |
| `--startup-delay SEC` | 3.0     | Startup delay before monitoring |
| `--stop-on-crash`     | false   | Stop campaign on first crash    |

#### Adapter Options (v1.9.0)

Enable viewer-specific UI automation for advanced testing. Adapters load studies into viewer viewports and can validate rendering. Requires `pywinauto` package for Windows viewers.

| Option            | Default | Description                                  |
| ----------------- | ------- | -------------------------------------------- |
| `--adapter NAME`  | -       | Viewer adapter (e.g., 'affinity')            |
| `--series-name`   | -       | Series name to search for when using adapter |
| `--list-adapters` | -       | List available viewer adapters               |

**Available Adapters:**

| Adapter    | Viewers                  | Description                  |
| ---------- | ------------------------ | ---------------------------- |
| `affinity` | Hermes.exe, Affinity.exe | Hermes Affinity DICOM viewer |

**Requirements:** `pip install pywinauto` (Windows only)

When an adapter is used:

1. Target application is launched with study path
2. Adapter connects via pywinauto (UIA backend)
3. Study is loaded into viewport via keyboard automation:
   - Focus search (Ctrl+F)
   - Type series name
   - Click matching item + Enter to load
4. Window reference is re-acquired (title changes to study name)
5. Render success/failure is detected via error dialog checks
6. On failure: screenshot + study saved to crash artifacts

**Note:** Screenshots are only captured when crashes or render failures occur, not on every test iteration.

**Affinity Adapter Notes:**

- Window title starts as "Default", changes to study name (e.g., "PET-CT [25-Feb-2016]") after load
- Uses UIA automation IDs: SearchTextBox, Datalist
- Series items are ListItem controls containing Text elements

#### Output Options

| Option             | Default                    | Description      |
| ------------------ | -------------------------- | ---------------- |
| `-o, --output DIR` | ./artifacts/study-campaign | Output directory |
| `-v, --verbose`    | false                      | Verbose output   |

#### Output Structure

```text
artifacts/study-campaign/
├── campaign.log
├── campaign_results.json
└── crashes/
    └── crash_0001/
        ├── study/          # Copy of crashed study
        └── result.json     # Test result details
```

#### Examples

```bash
# Run study-level fuzzing campaign against a DICOM viewer
dicom-fuzzer study-campaign \
    --target "/path/to/viewer" \
    --study "./test_study" \
    --count 100 \
    -o ./artifacts/campaign

# List available strategies
dicom-fuzzer study-campaign --list-strategies

# Target specific vulnerability pattern with memory monitoring
dicom-fuzzer study-campaign \
    --target "/path/to/viewer" \
    --study "./study" \
    --strategy cross-series \
    --severity aggressive \
    --memory-limit 4096 \
    --timeout 30

# Stop on first crash for investigation
dicom-fuzzer study-campaign \
    --target "./viewer.exe" \
    --study "./study" \
    --stop-on-crash \
    -v
```

---

### corpus Subcommand (v1.8.0)

Corpus management utilities for DICOM fuzzing, including study corpus generation, deduplication, and minimization.

```bash
python -m dicom_fuzzer.cli corpus [OPTIONS]
```

#### Actions

| Action                 | Description                                         |
| ---------------------- | --------------------------------------------------- |
| `--analyze DIR`        | Analyze corpus and show statistics                  |
| `--dedup DIR`          | Deduplicate corpus by content hash                  |
| `--merge DIR...`       | Merge multiple corpora into one                     |
| `--minimize-study DIR` | Minimize a crashing study to find trigger slice(s)  |
| `--generate-study DIR` | Generate mutated study corpus from source directory |

#### Generation Options (for --generate-study)

| Option                    | Default    | Description                                |
| ------------------------- | ---------- | ------------------------------------------ |
| `-c, --count N`           | 50         | Number of mutated studies to generate      |
| `--strategy STRAT`        | all        | Mutation strategy (same as study-campaign) |
| `--severity LEVEL`        | aggressive | minimal, moderate, aggressive, extreme     |
| `--mutations-per-study N` | 5          | Number of mutations per generated study    |
| `-o, --output DIR`        | (required) | Output directory for generated corpus      |
| `-v, --verbose`           | false      | Verbose output showing each mutation       |

#### Minimization Options (for --minimize-study)

| Option               | Default | Description                     |
| -------------------- | ------- | ------------------------------- |
| `-t, --target EXE`   | -       | Target executable to test with  |
| `--timeout SEC`      | 30.0    | Timeout per test in seconds     |
| `--max-iterations N` | 100     | Maximum minimization iterations |

#### Output Options

| Option             | Default | Description               |
| ------------------ | ------- | ------------------------- |
| `-o, --output DIR` | -       | Output directory          |
| `--format FMT`     | text    | Output format: json, text |
| `-v, --verbose`    | false   | Verbose output            |

#### Corpus Structure (--generate-study)

```text
corpus_dir/
├── study_corpus_index.json   # Corpus index with metadata
└── studies/
    ├── study_abc123/         # Generated mutated study
    │   ├── series_000/
    │   │   ├── slice_0000.dcm
    │   │   └── ...
    │   └── series_001/
    └── study_def456/
        └── ...
```

#### Examples

```bash
# Generate 50 mutated studies for fuzzing
dicom-fuzzer corpus --generate-study ./source_study -o ./corpus \
    --count 50 --strategy all --severity aggressive

# Generate corpus with specific attack pattern
dicom-fuzzer corpus --generate-study ./multi_series_study -o ./corpus \
    --strategy cross-series --count 100 -v

# Analyze existing corpus
dicom-fuzzer corpus --analyze ./corpus

# Deduplicate corpus (remove content duplicates)
dicom-fuzzer corpus --dedup ./corpus -o ./corpus_unique

# Merge multiple corpora
dicom-fuzzer corpus --merge ./corpus1 ./corpus2 -o ./merged

# Minimize a crashing study
dicom-fuzzer corpus --minimize-study ./crash_study \
    --target ./viewer.exe -o ./minimized
```

---

### calibrate Subcommand (v1.7.0)

Calibration and measurement mutation for DICOM images.

```bash
python -m dicom_fuzzer.cli calibrate [OPTIONS]
```

#### Actions

| Action              | Description                           |
| ------------------- | ------------------------------------- |
| `--input FILE`      | Input DICOM file to mutate            |
| `--list-categories` | List available calibration categories |

#### Mutation Options

| Option             | Default  | Description                                                   |
| ------------------ | -------- | ------------------------------------------------------------- |
| `--category CAT`   | all      | pixel-spacing, hounsfield, window-level, slice-thickness, all |
| `-c, --count N`    | 10       | Number of mutations                                           |
| `--severity LEVEL` | moderate | minimal, moderate, aggressive, extreme                        |

#### Output Options

| Option             | Default               | Description      |
| ------------------ | --------------------- | ---------------- |
| `-o, --output DIR` | ./artifacts/calibrate | Output directory |
| `-v, --verbose`    | false                 | Verbose output   |

#### Examples

```bash
# Fuzz pixel spacing calibration
dicom-fuzzer calibrate --input image.dcm --category pixel-spacing -o ./output

# List calibration categories
dicom-fuzzer calibrate --list-categories

# Fuzz Hounsfield unit rescale parameters
dicom-fuzzer calibrate --input ct_slice.dcm --category hounsfield --severity extreme
```

---

### stress Subcommand (v1.7.0)

Memory and performance stress testing for DICOM applications.

```bash
python -m dicom_fuzzer.cli stress [OPTIONS]
```

#### Actions

| Action              | Description                                    |
| ------------------- | ---------------------------------------------- |
| `--generate-series` | Generate large DICOM series for stress testing |
| `--run-test`        | Run stress test against target                 |
| `--list-scenarios`  | List available stress test scenarios           |

#### Generation Options

| Option             | Default  | Description                  |
| ------------------ | -------- | ---------------------------- |
| `--slices N`       | 100      | Number of slices             |
| `--dimensions WxH` | 512x512  | Slice dimensions             |
| `--pattern PAT`    | gradient | gradient, random, anatomical |

#### Testing Options

| Option              | Default | Description        |
| ------------------- | ------- | ------------------ |
| `--target EXE`      | -       | Target application |
| `--series DIR`      | -       | Series directory   |
| `--memory-limit MB` | 4096    | Memory limit       |

#### Output Options

| Option             | Default            | Description      |
| ------------------ | ------------------ | ---------------- |
| `-o, --output DIR` | ./artifacts/stress | Output directory |
| `-v, --verbose`    | false              | Verbose output   |

#### Examples

```bash
# Generate 500-slice stress test series
dicom-fuzzer stress --generate-series --slices 500 -o ./large_series

# Generate with specific dimensions
dicom-fuzzer stress --generate-series --slices 200 --dimensions 1024x1024 -o ./output

# List stress test scenarios
dicom-fuzzer stress --list-scenarios
```

---

### samples Subcommand

Generate sample DICOM files for testing, including synthetic and malicious samples.

```bash
python -m dicom_fuzzer.cli samples [ACTION] [OPTIONS]
```

#### Actions (mutually exclusive)

| Action               | Description                                     |
| -------------------- | ----------------------------------------------- |
| `--generate`         | Generate synthetic DICOM files                  |
| `--list-sources`     | List public DICOM sample sources                |
| `--malicious`        | Generate all malicious sample categories        |
| `--preamble-attacks` | Generate PE/ELF polyglot files (CVE-2019-11687) |
| `--cve-samples`      | Generate CVE reproduction samples               |
| `--parser-stress`    | Generate parser stress test samples             |
| `--compliance`       | Generate compliance violation samples           |
| `--scan PATH`        | Scan files for security issues                  |
| `--sanitize PATH`    | Sanitize DICOM preamble                         |

#### Generation Options

| Option               | Default             | Description                            |
| -------------------- | ------------------- | -------------------------------------- |
| `-c, --count N`      | 10                  | Number of files to generate            |
| `-o, --output DIR`   | ./artifacts/samples | Output directory                       |
| `-m, --modality MOD` | random              | CT, MR, US, CR, DX, PT, NM, XA, RF, SC |
| `--series`           | false               | Generate as consistent series          |
| `--rows N`           | 256                 | Image rows                             |
| `--columns N`        | 256                 | Image columns                          |
| `--seed N`           | -                   | Random seed for reproducibility        |

#### Malicious Sample Options

| Option              | Default | Description                     |
| ------------------- | ------- | ------------------------------- |
| `--depth N`         | 100     | Nesting depth for parser stress |
| `--base-dicom FILE` | -       | Base DICOM file for generation  |

#### Scanning Options

| Option        | Default | Description                  |
| ------------- | ------- | ---------------------------- |
| `--json`      | false   | Output scan results as JSON  |
| `--recursive` | false   | Recursively scan directories |

### fda-report Subcommand

Generate FDA-compliant fuzz testing reports for premarket submissions.

```bash
python -m dicom_fuzzer.cli fda-report [OPTIONS]
```

#### Input Options

| Option             | Description                       |
| ------------------ | --------------------------------- |
| `-i, --input FILE` | Input fuzzing results JSON file   |
| `--sample`         | Generate a sample report template |

#### Device Information

| Option                | Default | Description            |
| --------------------- | ------- | ---------------------- |
| `--organization NAME` | -       | Organization name      |
| `--device NAME`       | -       | Device under test name |
| `--version VERSION`   | -       | Device version         |

#### Output Options

| Option              | Default       | Description                     |
| ------------------- | ------------- | ------------------------------- |
| `-o, --output FILE` | fda_report.md | Output markdown report          |
| `--json FILE`       | -             | Also output JSON report         |
| `--stdout`          | false         | Print to stdout instead of file |

## Options Reference

### Fuzzing Strategies

| Strategy    | Description                         | Use Case                         |
| ----------- | ----------------------------------- | -------------------------------- |
| `metadata`  | Mutates patient info, study details | PHI handling, patient matching   |
| `header`    | Mutates DICOM tags                  | Tag parsing, buffer overflows    |
| `pixel`     | Corrupts pixel data                 | Image rendering, memory handling |
| `structure` | Modifies file structure             | Format validation                |

### Exit Codes

| Code | Meaning                      |
| ---- | ---------------------------- |
| 0    | Success                      |
| 1    | General error                |
| 130  | Interrupted by user (Ctrl+C) |

## Examples

### Basic Fuzzing

```bash
# Fuzz a single file, generate 50 variants
python -m dicom_fuzzer.cli input.dcm -c 50 -o ./output

# Fuzz a directory of files
python -m dicom_fuzzer.cli ./dicom_folder/ -c 10 -o ./output

# Recursive scan with specific strategies
python -m dicom_fuzzer.cli ./data/ -r -c 5 -s metadata,pixel -o ./output
```

### Target Testing

```bash
# Test CLI application
python -m dicom_fuzzer.cli input.dcm -c 20 -t /path/to/viewer --timeout 5

# Test GUI application (DICOM viewer)
python -m dicom_fuzzer.cli input.dcm -c 20 \
    -t "C:\Program Files\Viewer\viewer.exe" \
    --gui-mode --timeout 10 --memory-limit 2048 \
    --startup-delay 2.0

# Stop on first crash
python -m dicom_fuzzer.cli input.dcm -c 100 -t /path/to/viewer --stop-on-crash
```

### Network Fuzzing

```bash
# Basic network fuzzing
python -m dicom_fuzzer.cli input.dcm \
    --network-fuzz --host 192.168.1.100 --port 11112

# Specific strategy
python -m dicom_fuzzer.cli input.dcm \
    --network-fuzz --host pacs.local --port 104 \
    --network-strategy buffer_overflow
```

### Security Testing

```bash
# Full security fuzzing
python -m dicom_fuzzer.cli input.dcm --security-fuzz \
    --security-report security_findings.json

# Target specific CVEs
python -m dicom_fuzzer.cli input.dcm --security-fuzz \
    --target-cves CVE-2022-2119,CVE-2022-2120

# Target specific vulnerability classes
python -m dicom_fuzzer.cli input.dcm --security-fuzz \
    --vuln-classes oob_write,heap_overflow
```

### Sample Generation

```bash
# Generate synthetic CT images
python -m dicom_fuzzer.cli samples --generate -c 10 -m CT -o ./samples

# Generate malicious/CVE samples
python -m dicom_fuzzer.cli samples --malicious -o ./malicious_samples

# Scan files for threats
python -m dicom_fuzzer.cli samples --scan ./suspicious_files --recursive --json
```

### FDA Compliance Reporting

```bash
# Generate report from fuzzing results
python -m dicom_fuzzer.cli fda-report -i fuzzing_results.json \
    --organization "Medical Corp" --device "DICOM Viewer" -o report.md

# Generate sample template
python -m dicom_fuzzer.cli fda-report --sample -o sample_report.md
```

---

For more information, see [QUICKSTART.md](QUICKSTART.md) or [CVE_REFERENCE.md](CVE_REFERENCE.md).
