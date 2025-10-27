"""Local Path Configuration

CRITICAL: This file is in .gitignore and will NEVER be committed to GitHub.
Contains environment-specific paths for your local machine.
"""

from pathlib import Path

# ============================================================================
# DICOM Test Data
# ============================================================================
DICOM_INPUT_DIR = Path(r"C:\Data\Kiwi - Example Data - 20210423")

# ============================================================================
# DICOM Viewer
# ============================================================================
DICOM_VIEWER_PATH = Path(r"C:\Hermes\Affinity\Hermes.exe")
VIEWER_TIMEOUT = 5

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
