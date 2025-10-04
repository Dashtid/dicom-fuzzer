# DICOM Viewer Fuzzing Guide

This guide explains how to use the DICOM Fuzzer to test DICOM viewer applications for security vulnerabilities.

## Quick Start

### 1. Generate Fuzzed Files (No Viewer Testing)

```bash
python examples/fuzz_dicom_viewer.py \
    --input "C:/Data/Kiwi - Example Data - 20210423" \
    --output "./fuzzed_output" \
    --count 100 \
    --severity moderate
```

This will:
- Load 100 real DICOM files from the input directory
- Apply intelligent mutations using dictionary-based fuzzing
- Save fuzzed files to `./fuzzed_output`

### 2. Fuzz and Test Hermes Viewer (Automated)

```bash
python examples/fuzz_dicom_viewer.py \
    --input "C:/Data/Kiwi - Example Data - 20210423" \
    --output "./fuzzed_output" \
    --viewer "C:/Hermes/Affinity/Hermes.exe" \
    --count 50 \
    --timeout 5 \
    --severity aggressive
```

This will:
- Generate 50 fuzzed files with aggressive mutations
- Automatically launch Hermes.exe with each fuzzed file
- Monitor for crashes, hangs, and errors
- Log all crashes and hangs to the output directory

### 3. Use Environment Variables

Set these environment variables for easier usage:

```bash
export DICOM_INPUT="C:/Data/Kiwi - Example Data - 20210423"
export DICOM_VIEWER="C:/Hermes/Affinity/Hermes.exe"

# Now you can run with defaults
python examples/fuzz_dicom_viewer.py --count 20
```

## Mutation Severity Levels

Choose the right severity for your testing goals:

### Minimal (--severity minimal)
- Very small changes, unlikely to crash
- Good for: Testing input validation
- Use when: You want valid-looking but slightly corrupted files

### Moderate (--severity moderate) [DEFAULT]
- Medium changes, may cause some issues
- Good for: General fuzzing, finding edge cases
- Use when: Balanced between valid and corrupt data

### Aggressive (--severity aggressive)
- Large changes, likely to break things
- Good for: Finding crash bugs, robustness testing
- Use when: You want to stress-test error handling

### Extreme (--severity extreme)
- Maximum changes, definitely will break things
- Good for: Finding critical vulnerabilities
- Use when: You want maximum chaos for security testing

## Understanding the Output

### Generated Files

Fuzzed files are named:
```
fuzzed_{severity}_{original_name}_{timestamp}.dcm
```

Example:
```
fuzzed_moderate_CT_Image_1759601826850.dcm
```

### Crash Logs

When a viewer crashes, a crash log is created:
```
crash_{filename}.txt
```

Contains:
- File path that caused the crash
- Return code
- STDOUT and STDERR output

### Hang Logs

When a viewer hangs (timeout), a hang log is created:
```
hang_{filename}.txt
```

Contains:
- File path that caused the hang
- Timeout duration

## Advanced Usage

### Manual Testing Workflow

1. Generate fuzzed files:
```bash
python examples/fuzz_dicom_viewer.py \
    --input "C:/Data/Kiwi - Example Data - 20210423" \
    --output "./fuzzed_output" \
    --count 100 \
    --severity aggressive
```

2. Manually test each file:
- Open each fuzzed file in the viewer
- Watch for crashes, hangs, or unexpected behavior
- Document any findings

3. Report vulnerabilities:
- Save crash logs
- Note reproduction steps
- Report to vendor (responsible disclosure)

### Continuous Fuzzing

For long-running fuzzing campaigns:

```bash
# Generate 1000 files with different severity levels
for severity in minimal moderate aggressive extreme; do
    python examples/fuzz_dicom_viewer.py \
        --input "C:/Data/Kiwi - Example Data - 20210423" \
        --output "./fuzzed_${severity}" \
        --count 250 \
        --severity $severity
done
```

### Fuzzing Multiple Viewers

Test different DICOM viewers:

```bash
# List of viewers to test
viewers=(
    "C:/Hermes/Affinity/Hermes.exe"
    "C:/Program Files/OsiriX/OsiriX.exe"
    "C:/Horos/Horos.exe"
)

# Test each viewer
for viewer in "${viewers[@]}"; do
    python examples/fuzz_dicom_viewer.py \
        --viewer "$viewer" \
        --count 100 \
        --severity moderate
done
```

## Safety & Ethics

### IMPORTANT: Defensive Security Only

This tool is for **DEFENSIVE** security testing:
- ✅ Test your own software
- ✅ Test software you have permission to test
- ✅ Responsible disclosure of findings
- ❌ Never test software without permission
- ❌ Never use for malicious purposes

### Data Privacy

- **NEVER commit real patient data to git**
- All `.dcm` files are in `.gitignore`
- Local data paths are excluded
- Fuzzed files may contain fragments of real data - treat as PHI

### Responsible Disclosure

If you find vulnerabilities:

1. **Do not publish** the vulnerability immediately
2. **Contact the vendor** privately
3. **Give them time** to fix (typically 90 days)
4. **Coordinate disclosure** with the vendor
5. **Document everything** for your records

## Examples

### Example 1: Basic Fuzzing

Generate 50 fuzzed files for manual testing:

```bash
python examples/fuzz_dicom_viewer.py \
    --input "C:/Data/Kiwi - Example Data - 20210423" \
    --output "./test_files" \
    --count 50
```

### Example 2: Automated Viewer Testing

Test Hermes viewer with 100 fuzzed files:

```bash
python examples/fuzz_dicom_viewer.py \
    --input "C:/Data/Kiwi - Example Data - 20210423" \
    --output "./test_output" \
    --viewer "C:/Hermes/Affinity/Hermes.exe" \
    --count 100 \
    --timeout 10 \
    --severity aggressive
```

### Example 3: Targeted Testing

Focus on specific DICOM types:

```bash
# Test only CT images
python examples/fuzz_dicom_viewer.py \
    --input "C:/Data/CT_Images" \
    --output "./ct_fuzzed" \
    --count 200 \
    --severity extreme
```

## Troubleshooting

### "No DICOM files found"
- Check the input path exists
- Verify files have `.dcm` extension
- Try using absolute paths

### "Viewer not found"
- Check the viewer path is correct
- Use absolute paths
- Verify the executable exists

### "All mutations failed to write"
- Try lower severity levels
- Some mutations may be too corrupt
- This is normal for EXTREME severity

### Files not being tested
- Check timeout is long enough
- Viewer may need more time to start
- Try increasing `--timeout`

## Next Steps

After fuzzing:

1. **Review Results**: Check crash and hang logs
2. **Analyze Crashes**: Determine root cause
3. **Reproduce**: Verify crashes are reproducible
4. **Report**: Follow responsible disclosure
5. **Fix**: Work with vendor to fix issues
6. **Re-test**: Verify fixes work

## Support

For issues or questions:
- Check the main README.md
- Review test files in `tests/test_dictionary_fuzzer.py`
- See examples in `examples/demo_dictionary_fuzzing.py`
