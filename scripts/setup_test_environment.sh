#!/bin/bash
#
# Setup Test Environment for DICOM Fuzzer
#
# This script sets up a complete fuzzing environment including:
# - DCMTK installation (if not present)
# - Seed corpus generation
# - Directory structure
# - Quick smoke test
#
# USAGE:
#   bash scripts/setup_test_environment.sh
#   bash scripts/setup_test_environment.sh --docker-only
#   bash scripts/setup_test_environment.sh --skip-install

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SKIP_INSTALL=false
DOCKER_ONLY=false
SEED_COUNT=20

# Parse arguments
for arg in "$@"; do
    case $arg in
        --skip-install)
            SKIP_INSTALL=true
            ;;
        --docker-only)
            DOCKER_ONLY=true
            ;;
        --seed-count=*)
            SEED_COUNT="${arg#*=}"
            ;;
    esac
done

echo "================================================================================"
echo "DICOM Fuzzer - Test Environment Setup"
echo "================================================================================"
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    PACKAGE_MANAGER="apt-get"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PACKAGE_MANAGER="brew"
else
    OS="unknown"
fi

echo "[*] Detected OS: $OS"

# Function: Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function: Print status
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check Python installation
print_status "Checking Python installation..."
if ! command_exists python3; then
    print_error "Python 3 not found! Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 --version)
print_status "Found: $PYTHON_VERSION"

# Check pydicom installation
print_status "Checking pydicom..."
if ! python3 -c "import pydicom" 2>/dev/null; then
    print_warning "pydicom not installed. Installing..."
    pip3 install pydicom
fi
print_status "pydicom installed"

# Install DCMTK (if requested)
if [ "$DOCKER_ONLY" = false ] && [ "$SKIP_INSTALL" = false ]; then
    print_status "Checking DCMTK installation..."

    if command_exists dcmdump; then
        DCMTK_VERSION=$(dcmdump --version 2>&1 | head -n1)
        print_status "DCMTK already installed: $DCMTK_VERSION"
    else
        print_warning "DCMTK not found. Installing..."

        if [ "$OS" = "linux" ]; then
            sudo apt-get update
            sudo apt-get install -y dcmtk
        elif [ "$OS" = "macos" ]; then
            brew install dcmtk
        else
            print_warning "Automatic installation not supported for $OS"
            print_warning "Please install DCMTK manually from https://dicom.offis.de/dcmtk.php.en"
        fi

        if command_exists dcmdump; then
            print_status "DCMTK installed successfully"
        else
            print_error "DCMTK installation failed"
            print_warning "You can still use Docker mode with --docker flag"
        fi
    fi
fi

# Check Docker (if Docker mode requested)
if [ "$DOCKER_ONLY" = true ] || command_exists docker; then
    print_status "Checking Docker installation..."

    if command_exists docker; then
        DOCKER_VERSION=$(docker --version)
        print_status "Found: $DOCKER_VERSION"

        # Check if Docker is running
        if docker ps >/dev/null 2>&1; then
            print_status "Docker daemon is running"
        else
            print_warning "Docker is installed but not running"
            print_warning "Please start Docker daemon"
        fi

        # Check for docker-compose
        if command_exists docker-compose; then
            print_status "docker-compose is available"
        else
            print_warning "docker-compose not found (optional)"
        fi
    else
        print_warning "Docker not found"
        if [ "$DOCKER_ONLY" = true ]; then
            print_error "Docker is required for --docker-only mode"
            exit 1
        fi
    fi
fi

# Create directory structure
print_status "Creating directory structure..."
mkdir -p seeds
mkdir -p fuzzed
mkdir -p crashes
mkdir -p reports
mkdir -p fuzzing_output/{fuzzed,crashes,reports}
print_status "Directories created"

# Generate seed corpus
print_status "Generating seed corpus ($SEED_COUNT samples)..."
if python3 scripts/download_public_seeds.py --source all --count $SEED_COUNT --output ./seeds >/dev/null 2>&1; then
    print_status "Seed corpus generated successfully"
else
    print_warning "Seed generation encountered errors (check logs)"
fi

# Count seeds
SEED_COUNT_ACTUAL=$(find seeds -name "*.dcm" | wc -l)
print_status "Seed corpus: $SEED_COUNT_ACTUAL DICOM files"

# Run smoke test
print_status "Running smoke test..."

# Test 1: Download seeds script
if python3 scripts/download_public_seeds.py --source generated --count 5 --output ./test_seeds >/dev/null 2>&1; then
    print_status "  [OK] Seed download script works"
    rm -rf test_seeds
else
    print_error "  [FAIL] Seed download script failed"
fi

# Test 2: Import script (if seeds exist)
if [ -d "seeds" ] && [ "$(ls -A seeds/*.dcm 2>/dev/null)" ]; then
    if python3 scripts/import_seed_corpus.py seeds --output ./test_import --max-size 1MB >/dev/null 2>&1; then
        print_status "  [OK] Import script works"
        rm -rf test_import
    else
        print_error "  [FAIL] Import script failed"
    fi
fi

# Test 3: DCMTK (if installed)
if command_exists dcmdump && [ -f "seeds/$(ls seeds/*.dcm 2>/dev/null | head -n1)" ]; then
    FIRST_SEED=$(ls seeds/*.dcm | head -n1)
    if dcmdump "$FIRST_SEED" >/dev/null 2>&1; then
        print_status "  [OK] DCMTK can parse seed files"
    else
        print_warning "  [WARN] DCMTK failed to parse seed file (may be expected)"
    fi
fi

# Print summary
echo ""
echo "================================================================================"
echo "Setup Complete!"
echo "================================================================================"
echo ""
echo "Installed Components:"
if command_exists dcmdump; then
    echo "  [+] DCMTK (dcmdump available)"
else
    echo "  [ ] DCMTK (not installed - use --docker flag for fuzzing)"
fi

if command_exists docker; then
    echo "  [+] Docker"
else
    echo "  [ ] Docker"
fi

echo ""
echo "Environment Ready:"
echo "  - Seed corpus: $SEED_COUNT_ACTUAL files in ./seeds/"
echo "  - Output directories created"
echo "  - Scripts tested"
echo ""
echo "Next Steps:"
echo ""
echo "  1. Quick Start (5 minutes):"
echo "     python examples/production_fuzzing/fuzz_dcmtk.py --quick-start --iterations 50"
echo ""
echo "  2. Full Fuzzing Campaign (1 hour):"
echo "     python examples/production_fuzzing/fuzz_dcmtk.py --seeds ./seeds --iterations 1000"
echo ""

if command_exists docker; then
    echo "  3. Docker Mode (recommended):"
    echo "     # Build Docker image"
    echo "     docker-compose build dcmtk"
    echo ""
    echo "     # Run fuzzing in container"
    echo "     python examples/production_fuzzing/fuzz_dcmtk.py --docker --iterations 500"
    echo ""
fi

echo "  4. Import Real DICOM Files:"
echo "     python scripts/import_seed_corpus.py /path/to/dicom --strip-pixels --output ./corpus"
echo ""
echo "================================================================================"
