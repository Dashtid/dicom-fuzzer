# Enhanced Fuzzing Reporting System

## Overview

The DICOM-Fuzzer now includes a comprehensive reporting system that provides **complete traceability** from source files through mutations to crashes. When something crashes, you'll know exactly which file caused it, what mutations were applied, and how to reproduce it.

## Key Features

### 🔍 Complete Traceability

- **Every mutation is tracked** with full details (strategy, parameters, original/mutated values)
- **Crashes linked to exact files** that caused them
- **Full mutation history** preserved for forensic analysis
- **Crash artifacts preserved** with original samples

### 📊 Comprehensive Reports

- **Interactive HTML reports** with drill-down details
- **Machine-readable JSON** for automation and CI/CD
- **Crash forensics** with stack traces and reproduction commands
- **Mutation analysis** showing strategy effectiveness

### 🔐 Security-Focused

- **Crash severity classification** (critical, high, medium, low)
- **Reproducibility instructions** for each crash
- **Artifact preservation** for deeper analysis
- **Complete audit trail** for compliance

## Architecture

### Core Components

#### 1. FuzzingSession (`core/fuzzing_session.py`)

Tracks complete fuzzing campaigns with full traceability.

```python
from core.fuzzing_session import FuzzingSession

# Create session
session = FuzzingSession(
    session_name="dicom_viewer_fuzzing",
    output_dir="./output",
    reports_dir="./reports"
)

# Start fuzzing a file
file_id = session.start_file_fuzzing(
    source_file=Path("source.dcm"),
    output_file=Path("output/fuzzed.dcm"),
    severity="moderate"
)

# Record mutations
session.record_mutation(
    strategy_name="BitFlipper",
    mutation_type="flip_bits",
    target_tag="(0010,0010)",
    target_element="PatientName",
    original_value="John Doe",
    mutated_value="John\x00Doe"
)

# Finish file
session.end_file_fuzzing(Path("output/fuzzed.dcm"))

# Record crash if it occurs
session.record_crash(
    file_id=file_id,
    crash_type="crash",
    severity="high",
    return_code=-1,
    exception_message="Segmentation fault",
    viewer_path="C:/Viewer/viewer.exe"
)

# Generate reports
session.save_session_report()
```

#### 2. EnhancedReportGenerator (`core/enhanced_reporter.py`)

Generates beautiful, interactive HTML reports.

```python
from core.enhanced_reporter import EnhancedReportGenerator

# Load session data
with open("session_report.json") as f:
    session_data = json.load(f)

# Generate HTML
reporter = EnhancedReportGenerator()
html_path = reporter.generate_html_report(session_data)
```

#### 3. Unified Report Tool (`tools/generate_report.py`)

Command-line tool for report generation.

```bash
# Generate report from session JSON
python tools/generate_report.py reports/json/session_fuzzing_20241005.json

# Custom output path
python tools/generate_report.py session.json --output my_report.html
```

## Report Structure

### Directory Layout

```
reports/
├── json/                          # JSON session reports
│   └── session_fuzzing_20241005_143022.json
├── html/                          # HTML visual reports
│   └── fuzzing_report_fuzzing_20241005_143022.html
└── coverage/                      # Coverage reports

crashes/
└── fuzzing_20241005_143022/       # Crash artifacts (per session)
    ├── crash_20241005_143045.dcm  # Preserved fuzzed file
    ├── crash_20241005_143045.log  # Detailed crash log
    └── ...
```

### JSON Report Format

```json
{
  "session_info": {
    "session_id": "fuzzing_20241005_143022",
    "session_name": "dicom_viewer_fuzzing",
    "start_time": "2024-10-05T14:30:22",
    "end_time": "2024-10-05T14:45:30",
    "duration_seconds": 908
  },
  "statistics": {
    "files_fuzzed": 50,
    "mutations_applied": 150,
    "crashes": 3,
    "hangs": 2,
    "successes": 45
  },
  "fuzzed_files": {
    "fuzz_20241005_143025_001": {
      "file_id": "fuzz_20241005_143025_001",
      "source_file": "./test_data/dicom_samples/sample.dcm",
      "output_file": "./output/fuzzed_moderate_sample_001.dcm",
      "timestamp": "2024-10-05T14:30:25",
      "file_hash": "a1b2c3...",
      "severity": "moderate",
      "mutations": [
        {
          "mutation_id": "mut_1",
          "strategy_name": "BitFlipper",
          "timestamp": "2024-10-05T14:30:26",
          "target_tag": "(0010,0010)",
          "target_element": "PatientName",
          "mutation_type": "flip_bits",
          "original_value": "John Doe",
          "mutated_value": "John\x00Doe",
          "parameters": {"flip_count": 3}
        }
      ],
      "test_result": "crash",
      "crash_details": {...}
    }
  },
  "crashes": [
    {
      "crash_id": "crash_20241005_143045",
      "timestamp": "2024-10-05T14:30:45",
      "crash_type": "crash",
      "severity": "high",
      "fuzzed_file_id": "fuzz_20241005_143025_001",
      "fuzzed_file_path": "./output/fuzzed_moderate_sample_001.dcm",
      "return_code": -1,
      "exception_type": "SegmentationFault",
      "exception_message": "Segmentation fault at 0x00402a1c",
      "stack_trace": "...",
      "crash_log_path": "crashes/fuzzing_20241005_143022/crash_20241005_143045.log",
      "preserved_sample_path": "crashes/fuzzing_20241005_143022/crash_20241005_143045.dcm",
      "reproduction_command": "\"C:/Viewer/viewer.exe\" \"crashes/.../crash_20241005_143045.dcm\""
    }
  ]
}
```

## HTML Report Features

### 📊 Session Overview

- Statistics dashboard with key metrics
- Duration and timing information
- Alert banners for crashes/hangs

### 🔥 Crash Summary Table

- Quick overview of all crashes
- Sortable by severity, type, timestamp
- Links to detailed views

### 🔍 Crash Forensics

Each crash includes:

- **Complete file information**: Source file, fuzzed file, preserved sample
- **Mutation history**: Every mutation applied with before/after values
- **Exception details**: Full exception message and stack trace
- **Reproduction command**: Copy-paste ready command to reproduce
- **Crash log location**: Path to detailed text log

### 📈 Mutation Analysis

- Strategy usage statistics
- Mutation type breakdown
- Effectiveness metrics

### Interactive Features

- **Expandable sections** for mutation history and stack traces
- **Copy-to-clipboard** for reproduction commands
- **Color-coded severity** (critical=red, high=orange, etc.)
- **Responsive design** works on desktop and mobile

## Usage Examples

### Example 1: Basic Fuzzing with Session Tracking

```python
from pathlib import Path
from core.fuzzing_session import FuzzingSession
from core.enhanced_reporter import EnhancedReportGenerator
import pydicom

# Create session
session = FuzzingSession("my_fuzzing_campaign")

# Fuzz files
for source_file in Path("input").glob("*.dcm"):
    # Start tracking
    file_id = session.start_file_fuzzing(
        source_file=source_file,
        output_file=Path(f"output/fuzzed_{source_file.name}"),
        severity="moderate"
    )

    # Apply mutations (example)
    ds = pydicom.dcmread(source_file)
    original_name = ds.PatientName
    ds.PatientName = "FUZZED\x00\x00"

    # Record the mutation
    session.record_mutation(
        strategy_name="ManualFuzz",
        mutation_type="modify_value",
        target_tag="(0010,0010)",
        target_element="PatientName",
        original_value=str(original_name),
        mutated_value=str(ds.PatientName)
    )

    # Save fuzzed file
    output_path = Path(f"output/fuzzed_{source_file.name}")
    ds.save_as(output_path)

    # Finish tracking
    session.end_file_fuzzing(output_path)

    # Test with viewer (pseudocode)
    result = test_viewer(output_path)
    if result == "crash":
        session.record_crash(
            file_id=file_id,
            crash_type="crash",
            severity="high",
            exception_message="Viewer crashed"
        )

# Save reports
json_path = session.save_session_report()
print(f"Session report: {json_path}")

# Generate HTML
reporter = EnhancedReportGenerator()
with open(json_path) as f:
    import json
    data = json.load(f)
html_path = reporter.generate_html_report(data)
print(f"HTML report: {html_path}")
```

### Example 2: Analyzing Crash Details

```python
import json

# Load session report
with open("reports/json/session_fuzzing_20241005.json") as f:
    report = json.load(f)

# Find all critical crashes
critical_crashes = [
    crash for crash in report['crashes']
    if crash['severity'] == 'critical'
]

print(f"Found {len(critical_crashes)} critical crashes")

for crash in critical_crashes:
    print(f"\n{'='*60}")
    print(f"Crash ID: {crash['crash_id']}")
    print(f"File: {crash['fuzzed_file_path']}")
    print(f"Preserved: {crash['preserved_sample_path']}")

    # Get mutation history
    file_id = crash['fuzzed_file_id']
    file_record = report['fuzzed_files'][file_id]

    print(f"Mutations applied: {len(file_record['mutations'])}")
    for mut in file_record['mutations']:
        print(f"  - {mut['strategy_name']}: {mut['mutation_type']}")

    # Reproduction
    print(f"\nTo reproduce:")
    print(f"  {crash['reproduction_command']}")
```

### Example 3: CI/CD Integration

```bash
#!/bin/bash
# Automated fuzzing in CI pipeline

# Run fuzzing
python examples/fuzz_dicom_viewer.py \
    --input ./test_data \
    --output ./fuzzed_output \
    --viewer /usr/bin/dicom_viewer \
    --count 100

# Generate report
python tools/generate_report.py \
    reports/json/session_*.json \
    --output ci_report.html

# Check for crashes
CRASHES=$(jq '.statistics.crashes' reports/json/session_*.json)

if [ "$CRASHES" -gt 0 ]; then
    echo "❌ FAILED: $CRASHES crashes detected"
    cat ci_report.html >> $GITHUB_STEP_SUMMARY
    exit 1
else
    echo "✅ PASSED: No crashes detected"
    exit 0
fi
```

## Best Practices

### 1. Always Use Session Tracking

Even for quick tests, use `FuzzingSession` to maintain traceability:

```python
session = FuzzingSession("quick_test")
```

### 2. Preserve Crash Artifacts

The system automatically preserves crash artifacts. Keep these for:

- Reproduction testing
- Sharing with developers
- Regression testing

### 3. Review Mutation History

When investigating crashes, review the complete mutation history to understand:

- Which mutations contributed to the crash
- What combination of mutations triggered it
- How to create similar test cases

### 4. Use Severity Classification

Classify crashes appropriately:

- **Critical**: Memory corruption, potential code execution
- **High**: DoS, data corruption
- **Medium**: Recoverable errors
- **Low**: Minor issues

### 5. Document Reproduction Steps

The system generates reproduction commands, but add context:

- System configuration
- Required dependencies
- Environmental factors

## Troubleshooting

### Report Generation Fails

```python
# Ensure session data is valid JSON
with open("session.json") as f:
    data = json.load(f)  # Will raise JSONDecodeError if invalid
```

### Missing Crash Details

```python
# Always record test results
session.record_test_result(file_id, "crash", return_code=-1)
```

### Large Report Files

For campaigns with thousands of mutations:

```python
# Use summary mode (to be implemented)
reporter.generate_html_report(data, summary_mode=True)
```

## Future Enhancements

- [ ] Crash deduplication based on stack trace similarity
- [ ] Mutation effectiveness scoring
- [ ] Automated crash minimization
- [ ] Integration with bug tracking systems
- [ ] Real-time reporting dashboard
- [ ] Comparative analysis across sessions

## Support

For issues or questions about the reporting system:

1. Check this documentation
2. Review example code in `examples/`
3. Examine test cases in `tests/test_fuzzing_session.py`
4. Open an issue on GitHub
