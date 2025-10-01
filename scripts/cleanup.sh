#!/bin/bash

# DICOM-Fuzzer Cleanup Script
# Removes temporary files, test outputs, and cache directories

echo "🧹 Cleaning up DICOM-Fuzzer project..."

# Navigate to project root
cd "$(dirname "$0")/.." || exit 1

# Remove test output directories
echo "  → Removing test output directories..."
rm -rf fuzzed_dicoms/ test_all/ test_cli/ test_cli2/ test_crashes/ test_output/ test_structure/ output/ crashes/

# Remove Python cache
echo "  → Removing Python cache files..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete 2>/dev/null
find . -name "*.pyo" -delete 2>/dev/null

# Remove test artifacts
echo "  → Removing test artifacts..."
rm -rf .pytest_cache/ .hypothesis/ htmlcov/
rm -f .coverage coverage.xml

# Remove build artifacts
echo "  → Removing build artifacts..."
rm -rf build/ dist/ *.egg-info/

# Remove temporary files
echo "  → Removing temporary files..."
rm -f nul *.png *.jpg *.jpeg *.gif *.bmp
find . -name "*.tmp" -delete 2>/dev/null
find . -name "*~" -delete 2>/dev/null
find . -name "*.bak" -delete 2>/dev/null

# Remove IDE artifacts
echo "  → Removing IDE artifacts..."
rm -rf .vscode/.history/ .idea/

echo "✅ Cleanup complete!"
echo ""
echo "📊 Project status:"
echo "  - Source files: $(find . -name "*.py" -not -path "./.venv/*" | wc -l) Python files"
echo "  - Test files: $(find tests/ -name "test_*.py" | wc -l) test modules"
echo "  - Documentation: $(find docs/ -name "*.md" | wc -l) markdown files"
