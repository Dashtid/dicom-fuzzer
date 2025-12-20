# OSS-Fuzz Dockerfile for DICOM Fuzzer
#
# This Dockerfile is used by OSS-Fuzz to build the fuzzing environment.
# Reference: https://google.github.io/oss-fuzz/getting-started/new-project-guide/
#
# To test locally:
#   docker build -t dicom-fuzzer-oss-fuzz .
#   docker run -it dicom-fuzzer-oss-fuzz

FROM gcr.io/oss-fuzz-base/base-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    python3-dev \
    python3-pip \
    cmake \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . $SRC/dicom-fuzzer

# Copy build script
WORKDIR $SRC/dicom-fuzzer
COPY oss-fuzz/build.sh $SRC/
