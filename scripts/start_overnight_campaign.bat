@echo off
REM Overnight Fuzzing Campaign for Hermes.exe
REM This script launches an 8-hour fuzzing campaign.
REM
REM Prerequisites:
REM   1. Virtual environment activated: source venv/Scripts/activate
REM   2. Target executable exists: C:\Hermes\Affinity\Hermes.exe
REM   3. Corpus available: C:\Data\test-automation\Kiwi - Example Data - 20210423
REM
REM Usage:
REM   .\scripts\start_overnight_campaign.bat
REM   .\scripts\start_overnight_campaign.bat --duration 12
REM

cd /d "%~dp0.."
echo.
echo ======================================================================
echo   DICOM Fuzzer - Overnight Campaign Launcher
echo ======================================================================
echo.

REM Check if venv is activated
python -c "import dicom_fuzzer" 2>nul
if errorlevel 1 (
    echo [!] Virtual environment not activated or dicom_fuzzer not installed.
    echo     Run: source venv/Scripts/activate  (Git Bash)
    echo          venv\Scripts\activate.bat     (cmd.exe)
    pause
    exit /b 1
)

REM Check if target exists
if not exist "C:\Hermes\Affinity\Hermes.exe" (
    echo [!] Target not found: C:\Hermes\Affinity\Hermes.exe
    pause
    exit /b 1
)

REM Check if corpus exists
if not exist "C:\Data\test-automation\Kiwi - Example Data - 20210423" (
    echo [!] Corpus not found: C:\Data\test-automation\Kiwi - Example Data - 20210423
    pause
    exit /b 1
)

echo [+] All prerequisites met. Starting campaign...
echo.
echo Press Ctrl+C at any time to stop gracefully.
echo Results will be saved to: artifacts\hermes-campaign\
echo.

python scripts\overnight_campaign.py %*

echo.
echo [+] Campaign finished. Check artifacts\hermes-campaign\reports\ for results.
pause
