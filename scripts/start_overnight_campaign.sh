#!/bin/bash
# Overnight Fuzzing Campaign for Hermes.exe
# This script launches an 8-hour fuzzing campaign.
#
# Prerequisites:
#   1. Virtual environment activated: source venv/Scripts/activate
#   2. Target executable exists: C:\Hermes\Affinity\Hermes.exe
#   3. Corpus available: C:\Data\test-automation\Kiwi - Example Data - 20210423
#
# Usage:
#   ./scripts/start_overnight_campaign.sh
#   ./scripts/start_overnight_campaign.sh --duration 12
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo ""
echo "======================================================================"
echo "  DICOM Fuzzer - Overnight Campaign Launcher"
echo "======================================================================"
echo ""

# Check if venv is activated
if ! python -c "import dicom_fuzzer" 2>/dev/null; then
    echo "[!] Virtual environment not activated or dicom_fuzzer not installed."
    echo "    Run: source venv/Scripts/activate"
    exit 1
fi

# Check if target exists
if [ ! -f "/c/Hermes/Affinity/Hermes.exe" ] && [ ! -f "C:/Hermes/Affinity/Hermes.exe" ]; then
    echo "[!] Target not found: C:\\Hermes\\Affinity\\Hermes.exe"
    exit 1
fi

# Check if corpus exists
if [ ! -d "/c/Data/test-automation/Kiwi - Example Data - 20210423" ] && \
   [ ! -d "C:/Data/test-automation/Kiwi - Example Data - 20210423" ]; then
    echo "[!] Corpus not found: C:\\Data\\test-automation\\Kiwi - Example Data - 20210423"
    exit 1
fi

echo "[+] All prerequisites met. Starting campaign..."
echo ""
echo "Press Ctrl+C at any time to stop gracefully."
echo "Results will be saved to: artifacts/hermes-campaign/"
echo ""

python scripts/overnight_campaign.py "$@"

echo ""
echo "[+] Campaign finished. Check artifacts/hermes-campaign/reports/ for results."
