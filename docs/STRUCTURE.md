# DICOM-Fuzzer Repository Structure

## Directory Organization

```
DICOM-Fuzzer/
├── core/                    # Core fuzzing engine components
├── strategies/              # Mutation and fuzzing strategies
├── utils/                   # Utility functions and helpers
├── examples/                # Example scripts and demos
├── tools/                   # Utility tools and scripts
│   ├── create_html_report.py
│   └── main.py
├── tests/                   # Comprehensive test suite
├── docs/                    # Sphinx documentation
├── scripts/                 # Build and maintenance scripts
├── samples/                 # Sample DICOM files (structure only)
├── logs/                    # Application logs
├── output/                  # Fuzzing output (organized)
│   ├── crashes/            # Crash files
│   ├── fuzzed/             # Generated fuzzed files
│   └── corpus/             # Corpus for coverage-guided fuzzing
└── reports/                 # Test reports (organized)
    ├── json/               # JSON format reports
    ├── html/               # HTML format reports
    └── logs/               # Fuzzing campaign logs
```

## Report Organization

All fuzzing reports are now organized in the `reports/` directory:

- **JSON Reports**: `reports/json/fuzzing_report_YYYYMMDD_HHMMSS.json`
- **HTML Reports**: `reports/html/fuzzing_report_YYYYMMDD_HHMMSS.html`
- **Fuzzing Logs**: `reports/logs/fuzzing_results.log`

## Output Organization

Fuzzing outputs are organized in the `output/` directory:

- **Crashes**: `output/crashes/` - Files that caused crashes
- **Fuzzed Files**: `output/fuzzed/` - Generated fuzzed DICOM files  
- **Corpus**: `output/corpus/` - Interesting inputs for coverage-guided fuzzing

## Tools Directory

Helper scripts and utilities:

- `tools/create_html_report.py` - Generate HTML reports from JSON
- `tools/main.py` - Main fuzzing entry point

## .gitignore Strategy

The repository uses `.gitignore` to:
- **Keep directory structure** using `.gitkeep` files
- **Ignore generated content** (reports, fuzzed files, crashes)
- **Never commit PHI/PII data** (real DICOM files, patient data)
- **Protect sensitive data** (credentials, API keys)

## Usage

### Generate Reports

Reports are automatically generated in the organized structure:

```bash
python examples/fuzz_dicom_viewer.py \
    --input "/path/to/dicom/files" \
    --viewer "/path/to/viewer.exe" \
    --count 50 \
    --severity aggressive
```

Reports will be saved to:
- `reports/json/fuzzing_report_<timestamp>.json`
- `reports/html/fuzzing_report_<timestamp>.html`

### Manual HTML Report Generation

```bash
python tools/create_html_report.py \
    reports/json/fuzzing_report_20251004_205010.json \
    reports/html/custom_report.html
```

## Benefits of This Structure

1. **Clean Top Level**: Fewer files at repository root
2. **Organized Reports**: Separate JSON and HTML reports
3. **Clear Output**: Distinct directories for crashes, fuzzed files, and corpus
4. **Git-Friendly**: Structure preserved, generated content ignored
5. **Scalable**: Easy to add more report types or output categories
