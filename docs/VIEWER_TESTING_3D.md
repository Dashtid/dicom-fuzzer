# 3D DICOM Viewer Testing Guide

## Overview

The `ViewerLauncher3D` class enables automated security testing of DICOM viewer applications with complete 3D series (multi-slice volumes), not just individual 2D files. This approach tests real-world viewer behavior including 3D rendering, memory management, and series-level parsing logic.

**Key Capabilities**:

- Launch viewers with folder-based series loading
- Monitor memory usage during 3D rendering
- Detect crashes, timeouts, and hangs
- Correlate crashes to specific slices
- Support multiple viewer applications with configurable profiles

**Status**: Implemented in Phase 3 of 3D Fuzzing Roadmap
**Test Coverage**: 22/22 tests passing (100%), 84% code coverage
**Last Updated**: 2025-10-23

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Viewer Configuration](#viewer-configuration)
3. [Usage Examples](#usage-examples)
4. [Pre-Configured Viewer Profiles](#pre-configured-viewer-profiles)
5. [Custom Viewer Setup](#custom-viewer-setup)
6. [Crash Detection & Analysis](#crash-detection--analysis)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)

---

## Quick Start

### Basic Example

```python
from pathlib import Path
from dicom_fuzzer.harness import ViewerLauncher3D, ViewerConfig, ViewerType

# Create viewer configuration
config = ViewerConfig(
    viewer_type=ViewerType.GENERIC,
    executable_path=Path("C:/Program Files/DicomViewer/viewer.exe"),
    command_template="{folder_path}",
    timeout_seconds=60
)

# Initialize launcher
launcher = ViewerLauncher3D(config, monitor_memory=True)

# Test with fuzzed series
series_folder = Path("output/fuzzed_series_001/")
result = launcher.launch_with_series(series_folder)

# Check results
if result.crashed:
    print(f"CRASH DETECTED: Exit code {result.exit_code}")
    print(f"Potential crash slice: {result.crash_slice_index}")
elif result.timed_out:
    print(f"TIMEOUT: Viewer hung after {config.timeout_seconds}s")
else:
    print(f"SUCCESS: Series loaded (peak memory: {result.peak_memory_mb:.1f} MB)")
```

### Using YAML Configuration

```python
import yaml
from pathlib import Path
from dicom_fuzzer.harness import ViewerLauncher3D, ViewerConfig, ViewerType

# Load viewer profile from YAML
with open("config/viewer_profiles.yaml") as f:
    profiles = yaml.safe_load(f)

# Use MicroDicom profile
microdicom_config = profiles["microdicom"]
config = ViewerConfig(
    viewer_type=ViewerType.MICRODICOM,
    executable_path=Path(microdicom_config["executable_path"]),
    command_template=microdicom_config["command_template"],
    timeout_seconds=microdicom_config["timeout_seconds"],
    memory_limit_mb=microdicom_config.get("memory_limit_mb")
)

launcher = ViewerLauncher3D(config)
result = launcher.launch_with_series(Path("test_series/"))
```

---

## Viewer Configuration

### ViewerConfig Parameters

```python
@dataclass
class ViewerConfig:
    """Configuration for a DICOM viewer application."""

    viewer_type: ViewerType              # GENERIC, MICRODICOM, RADIANT, RUBO, CUSTOM
    executable_path: Path                # Path to viewer executable
    command_template: str                # Command with {folder_path} placeholder
    timeout_seconds: int = 60            # Max time to wait for viewer
    memory_limit_mb: Optional[int] = None  # Optional memory threshold
    expected_window_title: Optional[str] = None  # For UI automation (future)
    requires_folder_scan: bool = True    # Whether viewer scans folder
    additional_args: List[str] = field(default_factory=list)  # Extra CLI args
```

### ViewerType Enum

```python
class ViewerType(Enum):
    GENERIC = "generic"          # Any DICOM viewer (default)
    MICRODICOM = "microdicom"    # MicroDicom DICOM Viewer
    RADIANT = "radiant"          # RadiAnt DICOM Viewer
    RUBO = "rubo"                # Rubo DICOM Viewer
    CUSTOM = "custom"            # User-defined viewer
```

### Command Templates

The `command_template` string uses `{folder_path}` as a placeholder:

```python
# Example templates
"{folder_path}"                          # Most viewers
"--load-folder {folder_path}"            # Explicit flag
"-d {folder_path} --3d-mode"             # With additional options
```

The launcher will replace `{folder_path}` with the absolute path to the series folder.

---

## Usage Examples

### Example 1: Test Multiple Fuzzed Series

```python
from pathlib import Path
from dicom_fuzzer.harness import ViewerLauncher3D, create_generic_config

# Create generic viewer config
config = create_generic_config(
    executable_path=Path("C:/Tools/DicomViewer.exe"),
    timeout_seconds=30
)

launcher = ViewerLauncher3D(config, monitor_memory=True)

# Test all fuzzed series in output folder
output_dir = Path("output/")
crash_count = 0

for series_folder in output_dir.iterdir():
    if not series_folder.is_dir():
        continue

    print(f"\nTesting: {series_folder.name}")
    result = launcher.launch_with_series(series_folder)

    print(f"  Status: {result.status.value}")
    print(f"  Slices: {result.slice_count}")
    print(f"  Time: {result.execution_time:.2f}s")
    print(f"  Memory: {result.peak_memory_mb:.1f} MB")

    if result.crashed:
        crash_count += 1
        print(f"  [!] CRASH: Exit code {result.exit_code}")
        if result.crash_slice_index is not None:
            print(f"  [!] Potential crash slice: {result.crash_slice_index}")
        print(f"  [!] stderr: {result.stderr[:200]}")  # First 200 chars

print(f"\n{crash_count} crashes found in {len(list(output_dir.iterdir()))} series")
```

### Example 2: Memory-Intensive Testing

```python
from pathlib import Path
from dicom_fuzzer.harness import ViewerLauncher3D, ViewerConfig, ViewerType

# Configure with memory limit
config = ViewerConfig(
    viewer_type=ViewerType.GENERIC,
    executable_path=Path("viewer.exe"),
    command_template="{folder_path}",
    timeout_seconds=120,
    memory_limit_mb=4096  # 4GB limit
)

launcher = ViewerLauncher3D(config, monitor_memory=True, kill_on_timeout=True)

# Test large series (500+ slices)
result = launcher.launch_with_series(Path("large_series/ct_abdomen_500_slices/"))

if result.peak_memory_mb > config.memory_limit_mb:
    print(f"WARNING: Memory limit exceeded ({result.peak_memory_mb:.0f} MB > {config.memory_limit_mb} MB)")
```

### Example 3: Batch Testing with Logging

```python
import logging
from pathlib import Path
from dicom_fuzzer.harness import ViewerLauncher3D, ViewerConfig, ViewerType

# Configure logging
logging.basicConfig(level=logging.INFO)

# Create configuration
config = ViewerConfig(
    viewer_type=ViewerType.MICRODICOM,
    executable_path=Path("C:/Program Files/MicroDicom/mDicom.exe"),
    command_template="{folder_path}",
    timeout_seconds=90
)

launcher = ViewerLauncher3D(config)

# Test all series
test_folders = [
    "fuzzed_series_positions/",
    "fuzzed_series_gradient/",
    "fuzzed_series_mixed_modality/",
]

results = []
for folder in test_folders:
    result = launcher.launch_with_series(Path(folder))
    results.append((folder, result))

# Generate summary report
print("\n=== TEST SUMMARY ===")
for folder, result in results:
    status_symbol = "[X]" if result.crashed else "[!]" if result.timed_out else "[OK]"
    print(f"{status_symbol} {folder}: {result.status.value} ({result.execution_time:.1f}s)")
```

---

## Pre-Configured Viewer Profiles

### MicroDicom DICOM Viewer

**Configuration** ([config/viewer_profiles.yaml](../config/viewer_profiles.yaml)):

```yaml
microdicom:
  viewer_type: microdicom
  executable_path: "C:/Program Files/MicroDicom/mDicom.exe"
  command_template: "{folder_path}"
  timeout_seconds: 90
  memory_limit_mb: 4096
  requires_folder_scan: true
```

**Known Vulnerabilities** (2025):

- **CVE-2025-35975**: Out-of-bounds write (CVSS 8.8) - Remote code execution
- **CVE-2025-36521**: Out-of-bounds read (CVSS 8.8) - Memory disclosure
- **CVE-2025-5943**: Out-of-bounds write (CVSS 8.6) - Arbitrary code execution
- **CVE-2025-1002**: Certificate validation bypass (CVSS 5.7)

**Update Required**: MicroDicom 2025.3 or later (patches above CVEs)

**Usage**:

```python
config = ViewerConfig(
    viewer_type=ViewerType.MICRODICOM,
    executable_path=Path("C:/Program Files/MicroDicom/mDicom.exe"),
    command_template="{folder_path}",
    timeout_seconds=90
)
```

### RadiAnt DICOM Viewer

**Configuration**:

```yaml
radiant:
  viewer_type: radiant
  executable_path: "C:/Program Files/RadiAnt/RadiAntViewer.exe"
  command_template: "{folder_path}"
  timeout_seconds: 60
  memory_limit_mb: 8192
  requires_folder_scan: true
```

**Known Vulnerabilities** (2025):

- **CVE-2025-1001**: Certificate validation bypass (CVSS 5.7)

**Usage**:

```python
config = ViewerConfig(
    viewer_type=ViewerType.RADIANT,
    executable_path=Path("C:/Program Files/RadiAnt/RadiAntViewer.exe"),
    command_template="{folder_path}",
    timeout_seconds=60
)
```

### Rubo DICOM Viewer

**Configuration**:

```yaml
rubo:
  viewer_type: rubo
  executable_path: "C:/Program Files/Rubo Medical Imaging/Rubo DICOM Viewer/RuboViewer.exe"
  command_template: "{folder_path}"
  timeout_seconds: 60
  memory_limit_mb: 4096
  requires_folder_scan: true
```

**Usage**:

```python
config = ViewerConfig(
    viewer_type=ViewerType.RUBO,
    executable_path=Path("C:/Program Files/Rubo Medical Imaging/Rubo DICOM Viewer/RuboViewer.exe"),
    command_template="{folder_path}",
    timeout_seconds=60
)
```

### Sante DICOM Viewer

**Configuration**:

```yaml
sante:
  viewer_type: custom
  executable_path: "C:/Program Files/Santesoft/SanteDICOMViewer/SanteDICOMViewer.exe"
  command_template: "{folder_path}"
  timeout_seconds: 60
  memory_limit_mb: 4096
  requires_folder_scan: true
```

**Usage**:

```python
config = ViewerConfig(
    viewer_type=ViewerType.CUSTOM,
    executable_path=Path("C:/Program Files/Santesoft/SanteDICOMViewer/SanteDICOMViewer.exe"),
    command_template="{folder_path}",
    timeout_seconds=60
)
```

---

## Custom Viewer Setup

### Adding Your Own Viewer

1. **Determine Command-Line Interface**:

   ```bash
   # Test your viewer's CLI manually
   YourViewer.exe "path/to/series/folder"
   YourViewer.exe --load-folder "path/to/series/folder"
   ```

2. **Create Configuration**:

   ```python
   from dicom_fuzzer.harness import ViewerConfig, ViewerType
   from pathlib import Path

   config = ViewerConfig(
       viewer_type=ViewerType.CUSTOM,
       executable_path=Path("C:/Path/To/YourViewer.exe"),
       command_template="{folder_path}",  # Adjust as needed
       timeout_seconds=60,
       additional_args=["--no-splash", "--silent"]  # Optional flags
   )
   ```

3. **Test Configuration**:

   ```python
   launcher = ViewerLauncher3D(config)
   result = launcher.launch_with_series(Path("test_series/"))

   if result.status.name == "SUCCESS":
       print("Configuration works!")
   else:
       print(f"Issue: {result.status.name}")
       print(f"stderr: {result.stderr}")
   ```

### Adding to YAML Configuration

Edit `config/viewer_profiles.yaml`:

```yaml
your_viewer:
  viewer_type: custom
  executable_path: "C:/Path/To/YourViewer.exe"
  command_template: "{folder_path}"
  timeout_seconds: 60
  memory_limit_mb: 4096
  requires_folder_scan: true
  additional_args:
    - "--no-splash"
    - "--silent"
```

Then load in Python:

```python
import yaml
from pathlib import Path
from dicom_fuzzer.harness import ViewerConfig, ViewerType

with open("config/viewer_profiles.yaml") as f:
    profiles = yaml.safe_load(f)

your_config = profiles["your_viewer"]
config = ViewerConfig(
    viewer_type=ViewerType.CUSTOM,
    executable_path=Path(your_config["executable_path"]),
    command_template=your_config["command_template"],
    timeout_seconds=your_config["timeout_seconds"],
    additional_args=your_config.get("additional_args", [])
)
```

---

## Crash Detection & Analysis

### SeriesTestResult Structure

```python
@dataclass
class SeriesTestResult:
    """Result of testing a viewer with a 3D series."""
    status: ExecutionStatus           # SUCCESS, CRASH, HANG, ERROR
    series_folder: Path               # Path to tested series
    slice_count: int                  # Number of DICOM files
    execution_time: float             # Seconds elapsed
    peak_memory_mb: float             # Peak RSS memory usage
    crashed: bool = False             # True if viewer crashed
    timed_out: bool = False           # True if viewer hung/timed out
    exit_code: Optional[int] = None   # Process exit code (if available)
    crash_slice_index: Optional[int] = None  # Estimated crash slice
    stderr: str = ""                  # Standard error output
    stdout: str = ""                  # Standard output
    error_message: Optional[str] = None  # Error message (if crashed)
```

### Crash Correlation

The launcher attempts to identify which slice triggered the crash using heuristic pattern matching:

**Patterns Searched**:

- `slice_123.dcm` - Explicit filename references
- `slice 42` - Slice number in error messages
- `image 15` - Image index references
- `instance 8` - DICOM instance numbers

**Example**:

```python
result = launcher.launch_with_series(Path("fuzzed_series/"))

if result.crashed and result.crash_slice_index is not None:
    print(f"Crash likely caused by slice {result.crash_slice_index}")
    crash_file = list(result.series_folder.glob("*.dcm"))[result.crash_slice_index]
    print(f"Crash file: {crash_file}")
```

**Limitations**:

- Heuristic-based, not guaranteed
- Works best with verbose error output
- May return `None` if no patterns match
- First/last slice often targeted for boundary bugs

### Memory Monitoring

When `monitor_memory=True`, the launcher tracks peak memory usage using `psutil`:

```python
launcher = ViewerLauncher3D(config, monitor_memory=True)
result = launcher.launch_with_series(series_folder)

print(f"Peak memory: {result.peak_memory_mb:.1f} MB")

# Check for memory exhaustion
if result.peak_memory_mb > 8192:
    print("WARNING: Excessive memory usage detected (>8GB)")
```

**Note**: Memory monitoring adds ~1-5% overhead but provides valuable data for DoS vulnerability detection.

---

## Security Considerations

### Authorized Testing Only

**CRITICAL**: This tool is for DEFENSIVE security testing ONLY.

**Authorized Use Cases**:

- Security testing of in-house medical imaging software
- Vulnerability assessment in controlled lab environments
- Compliance testing for medical device manufacturers
- Academic research with IRB approval

**Prohibited Use**:

- Production medical systems without authorization
- Third-party systems without explicit written permission
- Malicious vulnerability exploitation
- Disruption of clinical operations

### Known Vulnerabilities (2025)

The following vulnerabilities have been publicly disclosed and should be tested:

**MicroDicom**:

- CVE-2025-35975 (CVSS 8.8): Out-of-bounds write via crafted DICOM files
- CVE-2025-36521 (CVSS 8.8): Out-of-bounds read in pixel data parsing
- CVE-2025-5943 (CVSS 8.6): Out-of-bounds write in series loading
- CVE-2025-1002 (CVSS 5.7): TLS certificate validation bypass

**RadiAnt**:

- CVE-2025-1001 (CVSS 5.7): Certificate validation weakness

**Mitigation**: Update to latest versions (MicroDicom 2025.3+, RadiAnt 2025.2+)

### Data Privacy

**HIPAA/GDPR Compliance**:

- **NEVER** use real patient data for fuzzing
- Use synthetic DICOM data or public de-identified datasets
- Sanitize all test data before committing to repositories
- Implement data retention policies for test artifacts

**Recommended Test Data Sources**:

- NEMA DICOM Standard Test Images (synthetic)
- TCIA (The Cancer Imaging Archive) - de-identified public data
- Orthanc demo datasets - synthetic test data
- Generate synthetic data using DICOMGenerator utilities

### Vulnerability Disclosure

If critical vulnerabilities are discovered:

1. **Document the finding** (type, severity, reproducibility)
2. **Create minimal PoC** with synthetic data
3. **Follow responsible disclosure**:
   - Contact vendor security team
   - Provide 90-day disclosure timeline
   - Coordinate public disclosure
4. **Do NOT** publish exploits without coordination

---

## Troubleshooting

### Viewer Doesn't Launch

**Symptoms**: `result.status == ERROR`, no crash or timeout

**Solutions**:

1. **Verify executable path**:

   ```python
   config.executable_path.exists()  # Should return True
   ```

2. **Test command manually**:

   ```bash
   "C:/Program Files/Viewer/viewer.exe" "C:/test_series"
   ```

3. **Check command template**:

   ```python
   # Debug: See actual command
   formatted_cmd = config.format_command(Path("test_series"))
   print(formatted_cmd)
   ```

4. **Check permissions**:
   - Executable must have execute permissions
   - Series folder must be readable

### Viewer Immediately Exits

**Symptoms**: `result.status == SUCCESS` but instant exit

**Possible Causes**:

- Viewer requires GUI display (not headless)
- Missing required arguments
- Series folder empty or invalid

**Solutions**:

1. **Add additional arguments**:

   ```python
   config.additional_args = ["--windowed", "--no-exit"]
   ```

2. **Check series folder**:
   ```python
   dcm_files = list(series_folder.glob("*.dcm"))
   print(f"Found {len(dcm_files)} DICOM files")
   ```

### Timeout on Every Series

**Symptoms**: All tests result in `HANG` status

**Solutions**:

1. **Increase timeout**:

   ```python
   config.timeout_seconds = 120  # 2 minutes
   ```

2. **Check if viewer waits for user input**:
   - Some viewers require dismissing dialogs
   - Consider UI automation (future feature)

3. **Disable memory monitoring** (if causing slowdown):
   ```python
   launcher = ViewerLauncher3D(config, monitor_memory=False)
   ```

### Crash Correlation Always Returns None

**Symptoms**: `result.crash_slice_index` is always `None`

**Explanation**: The heuristic crash correlation may not find patterns in the error output.

**Solutions**:

1. **Check stderr/stdout**:

   ```python
   print("STDERR:", result.stderr)
   print("STDOUT:", result.stdout)
   ```

2. **Manual analysis**: Look for file references in error messages

3. **Binary search**: Use minimization tools to narrow down crash slice:
   ```python
   # Remove half the slices, test, repeat
   # See docs/CRASH_INTELLIGENCE.md for minimization tools
   ```

### High Memory Usage on Windows

**Symptoms**: Peak memory much higher than expected

**Explanation**: Windows Task Manager shows different memory metrics than `psutil`

**Verification**:

```python
# Check what psutil reports
import psutil
process = psutil.Process()
print(f"RSS: {process.memory_info().rss / 1024**2:.1f} MB")
```

---

## API Reference

### ViewerLauncher3D

```python
class ViewerLauncher3D:
    """Launcher and harness for testing DICOM viewers with 3D series."""

    def __init__(
        self,
        config: ViewerConfig,
        monitor_memory: bool = True,
        kill_on_timeout: bool = True
    ):
        """
        Initialize viewer launcher.

        Args:
            config: Viewer configuration
            monitor_memory: Enable memory monitoring (slight overhead)
            kill_on_timeout: Kill process tree if timeout occurs

        Raises:
            ValueError: If executable doesn't exist
        """

    def launch_with_series(self, series_folder: Path) -> SeriesTestResult:
        """
        Launch viewer with series folder and monitor for crashes.

        Args:
            series_folder: Path to folder containing DICOM series

        Returns:
            SeriesTestResult with execution details

        Raises:
            FileNotFoundError: If series_folder doesn't exist
        """
```

### ViewerConfig

```python
@dataclass
class ViewerConfig:
    """Configuration for a DICOM viewer application."""

    viewer_type: ViewerType
    executable_path: Path
    command_template: str
    timeout_seconds: int = 60
    memory_limit_mb: Optional[int] = None
    expected_window_title: Optional[str] = None
    requires_folder_scan: bool = True
    additional_args: List[str] = field(default_factory=list)

    def format_command(self, series_folder: Path) -> List[str]:
        """
        Format command line with series folder path.

        Args:
            series_folder: Path to series folder

        Returns:
            List of command arguments
        """
```

### Helper Functions

```python
def create_generic_config(
    executable_path: Path,
    timeout_seconds: int = 60,
    command_template: str = "{folder_path}"
) -> ViewerConfig:
    """
    Create a generic viewer configuration.

    Args:
        executable_path: Path to viewer executable
        timeout_seconds: Max execution time
        command_template: Command template (default: "{folder_path}")

    Returns:
        ViewerConfig with GENERIC type
    """
```

---

## Related Documentation

- [3D Fuzzing Roadmap](3D_FUZZING_ROADMAP.md) - Overall 3D fuzzing strategy
- [Crash Intelligence](CRASH_INTELLIGENCE.md) - Crash analysis and triaging
- [Fuzzing Guide](FUZZING_GUIDE.md) - General fuzzing usage
- [Examples](../examples/) - Example scripts and workflows

---

## Version History

- **v1.0.0** (2025-10-23): Initial implementation
  - ViewerLauncher3D class with 22/22 tests passing
  - 84% code coverage
  - Support for 4 pre-configured viewers
  - Memory monitoring and crash correlation
  - YAML configuration support

---

**Document Owner**: David Dashti
**Review Cycle**: Quarterly or after major feature additions
**Last Updated**: 2025-10-23
