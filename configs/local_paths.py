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
# Output Directories (Centralized under artifacts/)
# ============================================================================
ARTIFACTS_DIR = Path("./artifacts")
OUTPUT_DIR = ARTIFACTS_DIR / "fuzzed"
CRASHES_DIR = ARTIFACTS_DIR / "crashes"
REPORTS_DIR = ARTIFACTS_DIR / "reports"
LOGS_DIR = ARTIFACTS_DIR / "logs"
CORPUS_DIR = ARTIFACTS_DIR / "corpus"
CAMPAIGNS_DIR = ARTIFACTS_DIR / "campaigns"

# ============================================================================
# Fuzzing Defaults
# ============================================================================
DEFAULT_SEVERITY = "moderate"
DEFAULT_COUNT = 50
DEFAULT_MUTATIONS = 3
