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

The fuzzer includes 9 CVE mutation categories applied automatically:

| Mutation Type            | CVE(s)               | Description                       |
| ------------------------ | -------------------- | --------------------------------- |
| `cve_heap_overflow`      | CVE-2025-5943        | Pixel data parsing overflow       |
| `cve_integer_overflow`   | CVE-2025-5943        | Dimension integer overflow        |
| `cve_malformed_length`   | CVE-2020-29625       | Undefined/oversized length fields |
| `cve_path_traversal`     | CVE-2021-41946       | Path traversal in filename fields |
| `cve_deep_nesting`       | CVE-2022-24193       | Deep sequence nesting (DoS)       |
| `cve_polyglot`           | CVE-2019-11687       | PE/ELF preamble injection         |
| `cve_encapsulated_pixel` | CVE-2025-11266       | PixelData fragment underflow      |
| `cve_jpeg_codec`         | CVE-2025-53618/53619 | JPEG codec OOB read               |
| `cve_random`             | Any                  | Random CVE from registry          |

#### Available CVE Patterns (for --target-cves)

- CVE-2025-5943 (MicroDicom OOB write)
- CVE-2025-11266 (GDCM PixelData)
- CVE-2025-53618, CVE-2025-53619 (GDCM JPEG codec)
- CVE-2025-1001 (RadiAnt MitM)
- CVE-2022-2119, CVE-2022-2120 (DCMTK path traversal)
- CVE-2019-11687 (DICOM preamble executable)

Available vulnerability classes:

- oob_write, oob_read, stack_overflow, heap_overflow
- integer_overflow, format_string, null_deref, dos

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

# Generate MR series
python -m dicom_fuzzer.cli samples --generate --series -c 20 -m MR -o ./samples

# Generate all malicious samples
python -m dicom_fuzzer.cli samples --malicious -o ./malicious_samples

# Generate CVE reproduction samples
python -m dicom_fuzzer.cli samples --cve-samples -o ./cve_samples

# Scan files for threats
python -m dicom_fuzzer.cli samples --scan ./suspicious_files --recursive --json

# Sanitize a file
python -m dicom_fuzzer.cli samples --sanitize suspicious.dcm
```

### FDA Compliance Reporting

```bash
# Generate report from fuzzing results
python -m dicom_fuzzer.cli fda-report -i fuzzing_results.json -o report.md

# Generate report with device info
python -m dicom_fuzzer.cli fda-report -i results.json \
    --organization "Medical Corp" \
    --device "DICOM Viewer" \
    --version "2.0.0" \
    -o fda_report.md

# Generate sample report template
python -m dicom_fuzzer.cli fda-report --sample -o sample_report.md

# Output both markdown and JSON
python -m dicom_fuzzer.cli fda-report -i results.json \
    -o report.md --json report.json
```

---

For more information, see [QUICKSTART.md](QUICKSTART.md) or [CVE_REFERENCE.md](CVE_REFERENCE.md).
