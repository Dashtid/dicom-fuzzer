# DCMTK Fuzzing Target Environment
#
# This Docker image provides DCMTK (DICOM Toolkit) compiled with fuzzing instrumentation.
# Includes dcmdump, dcmqrscp, and other DICOM utilities for fuzzing.
#
# BUILD:
#   docker build -t dicom-fuzzer/dcmtk:latest -f configs/docker/dcmtk/Dockerfile .
#
# RUN (dcmdump parser):
#   docker run --rm -v $(pwd)/tools/generators:/input dicom-fuzzer/dcmtk dcmdump /input/test.dcm
#
# RUN (dcmqrscp DICOM server):
#   docker run --rm -p 11112:11112 dicom-fuzzer/dcmtk dcmqrscp -c /etc/dcmtk/dcmqrscp.cfg

# Pin to specific SHA for reproducibility and security (Scorecard: PinnedDependenciesID)
FROM ubuntu:22.04@sha256:1c4cc37c10c4678fd5369d172a4e079af8a28a6e6f724647ccaa311b4801c3c9

LABEL maintainer="DICOM Fuzzer Project"
LABEL description="DCMTK compiled for fuzzing with ASAN instrumentation"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies and runtime requirements
RUN apt-get update && apt-get install -y \
    # Build tools
    build-essential \
    cmake \
    git \
    wget \
    # DCMTK dependencies
    libpng-dev \
    libtiff-dev \
    libxml2-dev \
    libssl-dev \
    zlib1g-dev \
    libwrap0-dev \
    # Sanitizer support
    clang \
    llvm \
    # Utilities
    vim \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Build arguments for fuzzing instrumentation
ARG ENABLE_ASAN=true
ARG ENABLE_UBSAN=false
ARG DCMTK_VERSION=DCMTK-3.6.8

# Download and build DCMTK
WORKDIR /build
RUN git clone --depth 1 --branch ${DCMTK_VERSION} https://github.com/DCMTK/dcmtk.git

WORKDIR /build/dcmtk

# Configure CMake with optional sanitizers
RUN if [ "$ENABLE_ASAN" = "true" ]; then \
        export CC=clang CXX=clang++ && \
        export CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g" && \
        export CXXFLAGS="-fsanitize=address -fno-omit-frame-pointer -g" && \
        export LDFLAGS="-fsanitize=address"; \
    fi && \
    cmake . \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DBUILD_APPS=ON \
        -DBUILD_SHARED_LIBS=OFF \
        -DDCMTK_WITH_OPENSSL=ON \
        -DDCMTK_WITH_PNG=ON \
        -DDCMTK_WITH_TIFF=ON \
        -DDCMTK_WITH_XML=ON \
        -DDCMTK_WITH_ZLIB=ON

# Build and install
RUN make -j$(nproc) && \
    make install && \
    ldconfig

# Create directories for DICOM operations
RUN mkdir -p /dicom/input \
             /dicom/output \
             /dicom/crashes \
             /etc/dcmtk

# Create default dcmqrscp configuration
RUN cat > /etc/dcmtk/dcmqrscp.cfg << 'EOF'
# Default dcmqrscp configuration for fuzzing

NetworkTCPPort  = 11112
MaxPDUSize      = 16384
MaxAssociations = 16

HostTable BEGIN
#
# Symbolic name     IP address         Port
#
fuzzer              = (fuzzer, ANY,    11112)
HostTable END

VendorTable BEGIN
VendorTable END

AETable BEGIN
#
# Application Entity Table
# Format: AETitle   StorageArea                  Access   Quota   Peers
#
FUZZER_SCP         /dicom/storage               RW       (10, 1024mb)   ANY
AETable END
EOF

# Create storage directory
RUN mkdir -p /dicom/storage

# Set environment for ASAN
ENV ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"
ENV UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"

# Add fuzzing helper scripts
RUN cat > /usr/local/bin/fuzz-dcmdump << 'EOF'
#!/bin/bash
# Helper script to run dcmdump on fuzzing inputs
# Usage: fuzz-dcmdump /path/to/file.dcm

set -e

INPUT_FILE="$1"

if [ -z "$INPUT_FILE" ]; then
    echo "Usage: fuzz-dcmdump <input.dcm>"
    exit 1
fi

# Run dcmdump with error detection
dcmdump "$INPUT_FILE" > /dev/null 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "[CRASH] dcmdump crashed with exit code: $EXIT_CODE"
    exit $EXIT_CODE
fi

echo "[OK] File parsed successfully"
exit 0
EOF

RUN chmod +x /usr/local/bin/fuzz-dcmdump

# Verify installation
RUN dcmdump --version && \
    dcmqrscp --version && \
    echo "DCMTK installation successful!"

# Set working directory
WORKDIR /dicom

# Default command: show help
CMD ["dcmdump", "--help"]
