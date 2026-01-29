# CLI Reference

## Main Command

```bash
dicom-fuzzer INPUT [OPTIONS]
```

### Common Options

| Option                   | Default               | Description                      |
| ------------------------ | --------------------- | -------------------------------- |
| `-c, --count N`          | 100                   | Number of fuzzed files           |
| `-o, --output DIR`       | ./artifacts/campaigns | Output directory                 |
| `-s, --strategies STRAT` | all                   | metadata,header,pixel,structure  |
| `-r, --recursive`        | false                 | Recursive directory scan         |
| `-v, --verbose`          | false                 | Verbose logging                  |
| `--json`                 | false                 | JSON output                      |

### Target Testing

| Option                | Default | Description              |
| --------------------- | ------- | ------------------------ |
| `-t, --target EXE`    | -       | Target application       |
| `--timeout SEC`       | 5.0     | Execution timeout        |
| `--stop-on-crash`     | false   | Stop on first crash      |
| `--gui-mode`          | false   | GUI application mode     |
| `--memory-limit MB`   | -       | Memory limit (GUI mode)  |
| `--startup-delay SEC` | 0.0     | Startup delay (GUI mode) |

### Network Fuzzing

| Option                     | Default   | Description              |
| -------------------------- | --------- | ------------------------ |
| `--network-fuzz`           | false     | Enable network fuzzing   |
| `--host HOST`              | localhost | Target host              |
| `--port PORT`              | 11112     | Target port              |
| `--ae-title TITLE`         | FUZZ_SCU  | AE Title                 |
| `--network-strategy STRAT` | all       | malformed_pdu, etc.      |

### Security Testing

| Option                   | Default | Description               |
| ------------------------ | ------- | ------------------------- |
| `--security-fuzz`        | false   | Extended security fuzzing |
| `--target-cves CVES`     | all     | Comma-separated CVEs      |
| `--vuln-classes CLASSES` | all     | Vulnerability classes     |
| `--security-report FILE` | -       | Security report (JSON)    |

---

## Subcommands

### cve

Generate CVE replication files.

```bash
dicom-fuzzer cve --list
dicom-fuzzer cve --all -t template.dcm -o ./output
dicom-fuzzer cve --cve CVE-2025-5943 -t template.dcm -o ./output
dicom-fuzzer cve --product MicroDicom -t template.dcm -o ./output
dicom-fuzzer cve --info CVE-2025-5943
```

| Option             | Description                        |
| ------------------ | ---------------------------------- |
| `--list`           | List available CVEs                |
| `--all`            | Generate all CVE files             |
| `--cve CVE-ID`     | Generate specific CVE              |
| `--product NAME`   | Filter by product                  |
| `--category CAT`   | Filter by category                 |
| `--info CVE-ID`    | Show CVE details                   |
| `-t, --template`   | Template DICOM file                |
| `-o, --output DIR` | Output directory                   |

---

### samples

Generate synthetic DICOM files.

```bash
dicom-fuzzer samples --generate -c 10 -m CT -o ./samples
dicom-fuzzer samples --malicious -o ./malicious
dicom-fuzzer samples --scan ./files --recursive
```

| Option               | Description                |
| -------------------- | -------------------------- |
| `--generate`         | Generate synthetic files   |
| `--malicious`        | Generate malicious samples |
| `--preamble-attacks` | PE/ELF polyglot files      |
| `--scan PATH`        | Scan for security issues   |
| `-c, --count N`      | Number of files            |
| `-m, --modality MOD` | CT, MR, US, etc.           |

---

### study

Study-level mutation (cross-series attacks).

```bash
dicom-fuzzer study --study ./patient_study --strategy cross-series -o ./output
dicom-fuzzer study --list-strategies
```

| Option             | Default  | Description                             |
| ------------------ | -------- | --------------------------------------- |
| `--study DIR`      | -        | Study directory                         |
| `--strategy STRAT` | all      | cross-series, patient-consistency, etc. |
| `--severity LEVEL` | moderate | minimal, moderate, aggressive           |

---

### study-campaign

Study-level fuzzing with target testing.

```bash
dicom-fuzzer study-campaign --target ./viewer.exe --study ./study -o ./output
```

| Option                | Default | Description              |
| --------------------- | ------- | ------------------------ |
| `--target EXE`        | -       | Target application       |
| `--study DIR`         | -       | Study directory          |
| `--adapter NAME`      | -       | Viewer adapter (affinity)|
| `--stop-on-crash`     | false   | Stop on first crash      |

---

### corpus

Corpus management.

```bash
dicom-fuzzer corpus --generate-study ./source -o ./corpus --count 50
dicom-fuzzer corpus --analyze ./corpus
dicom-fuzzer corpus --dedup ./corpus -o ./unique
dicom-fuzzer corpus --minimize-study ./crash --target ./viewer.exe
```

| Option                 | Description                      |
| ---------------------- | -------------------------------- |
| `--generate-study DIR` | Generate mutated study corpus    |
| `--analyze DIR`        | Show corpus statistics           |
| `--dedup DIR`          | Deduplicate by hash              |
| `--minimize-study DIR` | Minimize crashing study          |

---

### calibrate

Calibration/measurement mutation.

```bash
dicom-fuzzer calibrate --input image.dcm --category pixel-spacing -o ./output
dicom-fuzzer calibrate --list-categories
```

| Option           | Description                              |
| ---------------- | ---------------------------------------- |
| `--input FILE`   | Input DICOM file                         |
| `--category CAT` | pixel-spacing, hounsfield, window-level  |

---

### stress

Memory stress testing.

```bash
dicom-fuzzer stress --generate-series --slices 500 -o ./large_series
dicom-fuzzer stress --list-scenarios
```

| Option             | Description              |
| ------------------ | ------------------------ |
| `--generate-series`| Generate large series    |
| `--slices N`       | Number of slices         |
| `--dimensions WxH` | Slice dimensions         |

---

### fda-report

FDA-compliant reporting.

```bash
dicom-fuzzer fda-report -i results.json --organization "Corp" --device "Viewer" -o report.md
dicom-fuzzer fda-report --sample -o sample.md
```

---

## Exit Codes

| Code | Meaning         |
| ---- | --------------- |
| 0    | Success         |
| 1    | Error           |
| 130  | User interrupt  |
