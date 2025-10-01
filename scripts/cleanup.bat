@echo off
REM DICOM-Fuzzer Cleanup Script (Windows)
REM Removes temporary files, test outputs, and cache directories

echo 🧹 Cleaning up DICOM-Fuzzer project...

REM Navigate to project root
cd /d "%~dp0\.."

REM Remove test output directories
echo   → Removing test output directories...
if exist "fuzzed_dicoms" rmdir /s /q "fuzzed_dicoms"
if exist "test_all" rmdir /s /q "test_all"
if exist "test_cli" rmdir /s /q "test_cli"
if exist "test_cli2" rmdir /s /q "test_cli2"
if exist "test_crashes" rmdir /s /q "test_crashes"
if exist "test_output" rmdir /s /q "test_output"
if exist "test_structure" rmdir /s /q "test_structure"
if exist "output" rmdir /s /q "output"
if exist "crashes" rmdir /s /q "crashes"

REM Remove Python cache
echo   → Removing Python cache files...
for /d /r . %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d"
del /s /q *.pyc 2>nul
del /s /q *.pyo 2>nul

REM Remove test artifacts
echo   → Removing test artifacts...
if exist ".pytest_cache" rmdir /s /q ".pytest_cache"
if exist ".hypothesis" rmdir /s /q ".hypothesis"
if exist "htmlcov" rmdir /s /q "htmlcov"
if exist ".coverage" del /q ".coverage"
if exist "coverage.xml" del /q "coverage.xml"

REM Remove build artifacts
echo   → Removing build artifacts...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
for /d %%d in (*.egg-info) do @if exist "%%d" rmdir /s /q "%%d"

REM Remove temporary files
echo   → Removing temporary files...
if exist "nul" del /q "nul"
del /q *.png 2>nul
del /q *.jpg 2>nul
del /q *.jpeg 2>nul
del /q *.gif 2>nul
del /q *.bmp 2>nul
del /s /q *.tmp 2>nul
del /s /q *.bak 2>nul

echo ✅ Cleanup complete!
echo.
echo 📊 Project status:
dir /s /b *.py | find /c /v "" >temp.txt
set /p pycount=<temp.txt
del temp.txt
echo   - Python files found
echo   - Ready for development
echo.
pause
