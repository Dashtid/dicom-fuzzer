# Orthanc PACS Server Fuzzing Target
#
# This Docker image provides Orthanc (lightweight PACS server) for fuzzing.
# Includes REST API and DICOM network protocol endpoints.
#
# BUILD:
#   docker build -t dicom-fuzzer/orthanc:latest -f configs/docker/orthanc/Dockerfile .
#
# RUN:
#   docker run --rm -p 8042:8042 -p 4242:4242 dicom-fuzzer/orthanc
#
# ACCESS:
#   Web UI: http://localhost:8042 (username: orthanc, password: orthanc)
#   DICOM: localhost:4242 (AE Title: ORTHANC)

FROM orthancteam/orthanc:24.10.2

LABEL maintainer="DICOM Fuzzer Project"
LABEL description="Orthanc PACS server configured for fuzzing"

# Create fuzzing configuration
RUN cat > /etc/orthanc/orthanc.json << 'EOF'
{
  "Name": "Orthanc Fuzzing Target",
  "HttpPort": 8042,
  "DicomPort": 4242,
  "RemoteAccessAllowed": true,
  "AuthenticationEnabled": true,
  "RegisteredUsers": {
    "orthanc": "orthanc",
    "fuzzer": "fuzzer"
  },
  "DicomAet": "ORTHANC",
  "DicomCheckCalledAet": false,
  "DicomModalities": {
    "fuzzer": ["FUZZER", "localhost", 11113]
  },
  "DicomAlwaysAllowEcho": true,
  "DicomAlwaysAllowStore": true,
  "DicomCheckModalityHost": false,
  "HttpTimeout": 30,
  "DicomTlsEnabled": false,
  "SslEnabled": false,
  "MaximumPduLength": 16384,
  "UnknownSopClassAccepted": true,
  "DicomScuTimeout": 10,
  "SaveJobs": false,
  "OverwriteInstances": true,
  "LogLevel": "default",
  "LogFile": "/var/log/orthanc/orthanc.log",
  "Plugins": []
}
EOF

# Create log directory
RUN mkdir -p /var/log/orthanc && \
    chown orthanc:orthanc /var/log/orthanc

# Create storage directory
RUN mkdir -p /var/lib/orthanc/db && \
    chown -R orthanc:orthanc /var/lib/orthanc

# Expose ports
# 8042: REST API / Web UI
# 4242: DICOM protocol (C-STORE, C-FIND, C-MOVE, C-ECHO)
EXPOSE 8042 4242

# Health check
HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD curl -f http://localhost:8042/system || exit 1

# Run Orthanc
CMD ["Orthanc", "/etc/orthanc/"]
