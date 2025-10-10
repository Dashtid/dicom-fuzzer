# DICOM Fuzzer - Demonstration Scripts

This directory contains demonstration scripts that showcase the DICOM Fuzzer's capabilities through complete, end-to-end workflows.

## Available Demos

### `demo_simple.py` - Simplified Workflow Demo

A streamlined demonstration that shows the core fuzzing workflow without requiring the full framework complexity.

**Features:**
- Finds example DICOM files automatically
- Generates fuzzed variants with simple mutations
- Visualizes both original and fuzzed DICOM images
- Simulates target application testing
- Creates comprehensive reports with statistics

**Usage:**
```bash
# From project root
python demo/demo_simple.py
```

**Output Location:** `demo/output/`
- `demo/output/images/` - PNG visualizations of DICOM files
- `demo/output/fuzzed/` - Generated fuzzed DICOM files
- `demo/output/crashes/` - Files that triggered crashes
- `demo/output/reports/` - Markdown and HTML reports

**Mutation Types:**
- Pixel modification (random pixel changes)
- Bit flipping (flip individual bits)
- Value scaling (scale pixel intensities)
- Noise injection (add random noise)
- Tag modification (modify DICOM metadata)

---

### `demo_workflow.py` - Full Framework Workflow

A complete demonstration using the full DICOM Fuzzer framework with all components.

**Features:**
- Full integration with core framework components
- Advanced mutation strategies
- Coverage tracking
- Crash analysis and deduplication
- Statistical reporting

**Usage:**
```bash
# From project root
python demo/demo_workflow.py
```

**Output Location:** `demo/output/` (same as simple demo)

**Note:** This demo requires a deeper understanding of the framework architecture and may need configuration adjustments.

---

## Prerequisites

### Required Dependencies

Install additional visualization dependencies:
```bash
pip install matplotlib structlog
```

Or from the project root:
```bash
pip install -r requirements.txt
```

### DICOM Test Data

The demo scripts look for DICOM files in:
```
C:/Data/Kiwi - Example Data - 20210423/
```

**To use your own DICOM files:**
1. Edit the demo script
2. Modify the `find_seed_files()` function
3. Update the path to your DICOM directory

---

## Quick Start

1. **Activate virtual environment:**
   ```bash
   source .venv/Scripts/activate  # Git Bash (Windows)
   # or
   .venv\Scripts\activate  # CMD (Windows)
   ```

2. **Run the simple demo:**
   ```bash
   python demo/demo_simple.py
   ```

3. **View results:**
   - Check terminal output for summary
   - Open `demo/output/reports/FUZZING_REPORT.md`
   - Browse visualizations in `demo/output/images/`

---

## Understanding the Output

### Report Contents

The generated report includes:
- **Executive Summary** - High-level statistics
- **Configuration** - Fuzzing parameters used
- **Results** - Detailed test outcomes
- **Crash Analysis** - Grouped by error type
- **Visualizations** - Embedded images showing mutations

### Interpreting Results

**Crash Rate:**
- 0% - All mutations were handled gracefully
- 1-10% - Normal for robust applications
- >10% - May indicate input validation issues

**Error Types:**
Common crash categories:
- `DimensionError` - Image size validation issues
- `PixelDataError` - Pixel data integrity problems
- `OverflowError` - Numeric overflow conditions
- `MissingTagError` - Required DICOM tags missing

---

## Customization

### Adjusting Mutation Intensity

Edit the demo script to modify mutation behavior:

```python
# In demo_simple.py

# Increase mutations per seed
variants_per_seed = 20  # Default: 10

# Make mutations more aggressive
num_modifications = random.randint(100, 1000)  # Default: 10-100
```

### Adding Custom Mutations

Add new mutation strategies in the `simple_mutate_dicom()` function:

```python
def simple_mutate_dicom(ds: pydicom.Dataset) -> pydicom.Dataset:
    # Add your custom mutation here
    mutation_type = random.choice([
        'modify_pixel',
        'your_custom_mutation',  # Add here
        # ... existing mutations
    ])

    if mutation_type == 'your_custom_mutation':
        # Implement your mutation logic
        pass
```

### Changing Output Directory

Modify the output path in the demo script:

```python
def setup_output_dirs():
    output_base = Path('my_custom_output')  # Change this
    # ...
```

---

## Troubleshooting

### "No seed files found"

**Solution:**
- Verify DICOM files exist in the configured path
- Update `find_seed_files()` with correct path
- Check file permissions

### "Failed to visualize"

**Possible causes:**
- DICOM file has no pixel data (metadata only)
- 3D/4D DICOM volumes (not 2D images)
- Corrupted DICOM file

**Solution:**
- Use 2D DICOM images (CT, MR, X-ray slices)
- Check error messages for specific issues

### "Module not found"

**Solution:**
```bash
# Install missing dependencies
pip install matplotlib structlog pydicom
```

### "Permission denied" errors

**Solution:**
- Run with appropriate permissions
- Check output directory write access
- Ensure DICOM files are readable

---

## Advanced Usage

### Integrating with Real Applications

To test against a real DICOM viewer/processor:

1. **Modify the `simulate_target()` function:**
   ```python
   def test_real_application(dicom_file: Path) -> tuple[bool, str]:
       try:
           # Call your actual DICOM application
           subprocess.run(['your_dicom_app', str(dicom_file)],
                         check=True, timeout=5)
           return True, ""
       except Exception as e:
           return False, str(e)
   ```

2. **Update the fuzzing loop to use your function:**
   ```python
   success, error = test_real_application(fuzz_file)
   ```

### Batch Processing

Process multiple seed directories:

```python
seed_directories = [
    'path/to/seeds1',
    'path/to/seeds2',
    'path/to/seeds3',
]

for seed_dir in seed_directories:
    seeds = find_seed_files(seed_dir)
    # ... run fuzzing
```

---

## Output Files Reference

### Generated Files

```
demo/output/
├── images/              # PNG visualizations
│   ├── original_1.png   # Original seed files
│   ├── original_2.png
│   ├── fuzzed_seed1_var1.png  # Fuzzed variants
│   └── ...
├── fuzzed/             # Generated DICOM files
│   ├── seed1_var1.dcm
│   ├── seed1_var2.dcm
│   └── ...
├── crashes/            # Files that caused crashes
│   └── seed2_var5.dcm
└── reports/            # Analysis reports
    └── FUZZING_REPORT.md
```

### Cleaning Up

Remove generated files:
```bash
# Remove all demo output
rm -rf demo/output/

# Or selectively
rm -rf demo/output/fuzzed/*
rm -rf demo/output/images/*
```

**Note:** The `demo/output/` directory is gitignored and safe to delete.

---

## Contributing

When adding new demo scripts:

1. **Follow naming convention:** `demo_<purpose>.py`
2. **Update this README** with demo description
3. **Use consistent output structure** (`demo/output/`)
4. **Include inline documentation** for complex logic
5. **Test on Windows and Linux** if possible

---

## Security Notice

**IMPORTANT:** Never use real patient DICOM data for demonstrations!

- Use anonymized or synthetic DICOM files only
- The demo scripts are for testing/educational purposes
- Generated reports may contain file paths and metadata
- All output files are gitignored to prevent accidental commits

---

## Support

For issues with demo scripts:

1. Check this README's Troubleshooting section
2. Review the main project [README.md](../README.md)
3. Check the [TESTING.md](../TESTING.md) guide
4. Open an issue with demo script name and error details

---

**Last Updated:** 2025-01-11
**Maintained By:** David Dashti
