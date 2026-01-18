# DICOM Fuzzer - Multi-stage Docker Build
# Security testing tool for medical imaging systems
#
# Build: docker build -t dicom-fuzzer .
# Run:   docker run -v ./corpus:/corpus dicom-fuzzer input.dcm -c 100 -o /output

# =============================================================================
# Build Stage
# =============================================================================
FROM python:3.11-slim@sha256:aa9aac8eacc774817e2881238f52d983a5ea13d7f5a1dee479a1a1d466047951 AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency resolution (pinned with hash for supply chain security)
RUN pip install --no-cache-dir uv==0.9.26 \
    --hash=sha256:b7e89798bd3df7dcc4b2b4ac4e2fc11d6b3ff4fe7d764aa3012d664c635e2922 \
    --hash=sha256:ea296b700d7c4c27acdfd23ffaef2b0ecdd0aa1b58d942c62ee87df3b30f06ac

# Copy project files
COPY pyproject.toml ./
COPY dicom_fuzzer/ ./dicom_fuzzer/
COPY samples/ ./samples/

# Build wheel (pinned with hash for supply chain security)
RUN pip install --no-cache-dir build==1.4.0 \
    --hash=sha256:f1b91b925aa322be454f8330c6fb48b465da993d1e7e7e6fa35027ec49f3c936 && \
    python -m build --wheel

# =============================================================================
# Runtime Stage
# =============================================================================
FROM python:3.11-slim@sha256:aa9aac8eacc774817e2881238f52d983a5ea13d7f5a1dee479a1a1d466047951 AS runtime

# Labels
LABEL org.opencontainers.image.title="DICOM Fuzzer"
LABEL org.opencontainers.image.description="Security testing tool for DICOM medical imaging systems"
LABEL org.opencontainers.image.source="https://github.com/your-org/dicom-fuzzer"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user for security
RUN groupadd --gid 1000 fuzzer && \
    useradd --uid 1000 --gid fuzzer --shell /bin/bash --create-home fuzzer

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy wheel from builder and install
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Create directories for input/output
RUN mkdir -p /corpus /output /crashes && \
    chown -R fuzzer:fuzzer /corpus /output /crashes

# Switch to non-root user
USER fuzzer

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DICOM_FUZZER_OUTPUT=/output
ENV DICOM_FUZZER_CRASHES=/crashes

# Default volume mounts
VOLUME ["/corpus", "/output", "/crashes"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import dicom_fuzzer; print('OK')" || exit 1

# Entry point
ENTRYPOINT ["dicom-fuzzer"]

# Default command (show help)
CMD ["--help"]
