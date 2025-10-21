#!/bin/bash
# run_coverage.sh - Properly run tests and combine coverage for accurate reporting

set -e

echo "[+] Cleaning old coverage data..."
rm -f reports/coverage/.coverage*

echo "[+] Running tests with parallel coverage collection..."
.venv/Scripts/python -m pytest -n4 --cov=dicom_fuzzer --cov-report= -q

echo "[+] Combining coverage data from all workers..."
cd reports/coverage
../../.venv/Scripts/python -m coverage combine
cd ../..

echo "[+] Generating coverage reports..."
.venv/Scripts/python -m coverage report --data-file=reports/coverage/.coverage
.venv/Scripts/python -m coverage html --data-file=reports/coverage/.coverage -d reports/coverage/htmlcov
.venv/Scripts/python -m coverage xml --data-file=reports/coverage/.coverage -o reports/coverage/coverage.xml

echo "[+] Coverage analysis complete!"
echo "[+] HTML report: reports/coverage/htmlcov/index.html"
echo "[+] XML report: reports/coverage/coverage.xml"
