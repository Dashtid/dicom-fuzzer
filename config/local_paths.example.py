"""
Local Path Configuration - Example

CRITICAL: Copy this file to local_paths.py and update with your paths.
The local_paths.py file is in .gitignore and will never be committed.

This centralizes all environment-specific paths so you never need to
specify them again on the command line.
"""

from pathlib import Path

# ============================================================================
# DICOM Test Data
# ============================================================================
# Your local DICOM test data directory
# This directory contains real DICOM files for fuzzing
DICOM_INPUT_DIR = Path(r"C:\Data\Kiwi - Example Data - 20210423")

# Alternative test data locations (optional)
DICOM_INPUT_DIR_SMALL = Path(r"C:\Data\Test-Small")  # For quick tests
DICOM_INPUT_DIR_LARGE = Path(r"C:\Data\Test-Large")  # For comprehensive campaigns

# ============================================================================
# DICOM Viewer
# ============================================================================
# Path to your DICOM viewer executable
DICOM_VIEWER_PATH = Path(r"C:\Hermes\Affinity\Hermes.exe")

# Timeout for viewer (seconds)
VIEWER_TIMEOUT = 5

# ============================================================================
# Output Directories
# ============================================================================
# Where to save fuzzed files
OUTPUT_DIR = Path("./fuzzed_output")

# Where to save crash artifacts
CRASHES_DIR = Path("./crashes")

# Where to save reports
REPORTS_DIR = Path("./reports")

# ============================================================================
# Fuzzing Defaults
# ============================================================================
DEFAULT_SEVERITY = "moderate"  # minimal, moderate, aggressive, extreme
DEFAULT_COUNT = 50  # Number of files to fuzz
DEFAULT_MUTATIONS = 3  # Mutations per file
