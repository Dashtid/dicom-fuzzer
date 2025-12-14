"""Local Path Configuration

CRITICAL: This file is in .gitignore and will NEVER be committed to GitHub.
Contains environment-specific paths for your local machine.
"""

from pathlib import Path

# ============================================================================
# DICOM Test Data
# ============================================================================
DICOM_INPUT_DIR = Path(r"C:\Data\test-automation\Kiwi - Example Data - 20210423")

# ============================================================================
# DICOM Viewer (Hermes Affinity - GUI application)
# ============================================================================
DICOM_VIEWER_PATH = Path(r"C:\Hermes\Affinity\Hermes.exe")
VIEWER_TIMEOUT = 10  # Seconds before killing GUI app (use --gui-mode in CLI)
VIEWER_MEMORY_LIMIT_MB = 2048  # Memory limit for GUI mode

# ============================================================================
# Output Directories
# ============================================================================
OUTPUT_DIR = Path("./fuzzed_output")
CRASHES_DIR = Path("./crashes")
REPORTS_DIR = Path("./reports")

# ============================================================================
# Fuzzing Defaults
# ============================================================================
DEFAULT_SEVERITY = "moderate"
DEFAULT_COUNT = 50
DEFAULT_MUTATIONS = 3
