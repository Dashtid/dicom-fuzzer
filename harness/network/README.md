# DICOM Network Protocol Fuzzing

AFLNet-style state-aware fuzzing for DICOM network protocols (C-STORE, C-FIND, C-GET, C-MOVE, C-ECHO).

## Quick Start

### 1. Start Target Server (Orthanc)

```bash
# Using Docker (recommended)
docker run -d --name orthanc \
  -p 4242:4242 \
  -p 8042:8042 \
  orthancteam/orthanc

# Verify it's running
curl http://localhost:8042/system
```

### 2. Generate Seed Corpus

```bash
python seed_generator.py --output ./network_seeds
```

### 3. Run Network Fuzzer

```bash
python dicom_network_harness.py \
  --host localhost \
  --port 4242 \
  --corpus ./network_seeds \
  --iterations 10000 \
  --output ./findings
```

## Files

| File                       | Description                       |
| -------------------------- | --------------------------------- |
| `dicom_network_harness.py` | Main network protocol fuzzer      |
| `seed_generator.py`        | Generates seed corpus for fuzzing |
| `aflnet_config.txt`        | AFLNet configuration for DICOM    |

## Fuzzing Strategies

### State-Aware Fuzzing

The harness implements DICOM Upper Layer Protocol state machine:

```
IDLE -> A-ASSOCIATE-RQ -> AWAITING_AC
AWAITING_AC -> A-ASSOCIATE-AC -> ASSOCIATED
ASSOCIATED -> P-DATA-TF (DIMSE) -> AWAITING_DATA
AWAITING_DATA -> P-DATA-TF (Response) -> ASSOCIATED
ASSOCIATED -> A-RELEASE-RQ -> AWAITING_RP
AWAITING_RP -> A-RELEASE-RP -> IDLE
```

### Protocol Coverage

The fuzzer targets:

- **Association Establishment**: A-ASSOCIATE-RQ/AC/RJ mutations
- **DIMSE Operations**: C-ECHO, C-STORE, C-FIND, C-GET, C-MOVE
- **Data Transfer**: P-DATA-TF with malformed PDVs
- **Release/Abort**: A-RELEASE-RQ/RP, A-ABORT

### Mutation Strategies

1. **Bit/Byte Flipping**: Random corruption of PDU bytes
2. **Length Corruption**: Invalid length fields (0, 0xFFFFFFFF, mismatched)
3. **Structure Insertion/Deletion**: Add/remove PDU segments
4. **Havoc Mode**: Multiple random mutations combined

## AFLNet Integration

For advanced stateful fuzzing with AFLNet:

### Build AFLNet

```bash
git clone https://github.com/aflnet/aflnet
cd aflnet
make clean all
```

### Create State Machine Config

```bash
# aflnet_config.txt
# Format: <response_code> <state_id>
# DICOM doesn't use text responses, use binary signatures

# After A-ASSOCIATE-AC
\x02 1
# After P-DATA-TF
\x04 2
# After A-RELEASE-RP
\x06 3
```

### Run AFLNet

```bash
# Build instrumented Orthanc (if source available)
CC=afl-clang-fast CXX=afl-clang-fast++ cmake ..
make

# Run AFLNet
./afl-fuzz -i network_seeds -o findings \
  -N tcp://localhost/4242 \
  -P DICOM \
  -D 10000 \
  -q 3 -s 3 \
  -E -K \
  ./orthanc_instrumented
```

## Orthanc Configuration

### Production-Like Setup

Create `orthanc.json`:

```json
{
  "Name": "FuzzTarget",
  "DicomPort": 4242,
  "HttpPort": 8042,
  "DicomAet": "ORTHANC",
  "DicomCheckCalledAet": false,
  "DicomAlwaysAllowStore": true,
  "DicomAlwaysAllowFind": true,
  "DicomAlwaysAllowGet": true,
  "DicomAlwaysAllowMove": true,
  "StrictAetComparison": false,
  "StorageDirectory": "/tmp/orthanc-storage",
  "IndexDirectory": "/tmp/orthanc-index",
  "MaximumStorageSize": 0,
  "MaximumPatientCount": 0,
  "HttpServerEnabled": true,
  "HttpAuthentication": false,
  "SslEnabled": false
}
```

### Run with Configuration

```bash
docker run -d --name orthanc-fuzz \
  -p 4242:4242 \
  -p 8042:8042 \
  -v $(pwd)/orthanc.json:/etc/orthanc/orthanc.json:ro \
  orthancteam/orthanc
```

### Reset Between Runs

```bash
# Clear storage to prevent state accumulation
docker exec orthanc-fuzz rm -rf /tmp/orthanc-storage/*
docker restart orthanc-fuzz
```

## Other DICOM Servers

### DCM4CHEE

```bash
docker run -d --name dcm4chee \
  -p 11112:11112 \
  -p 8080:8080 \
  dcm4che/dcm4chee-arc-psql:5.29.2

# Update harness for DCM4CHEE
python dicom_network_harness.py \
  --host localhost \
  --port 11112 \
  --called-ae DCM4CHEE
```

### Conquest DICOM

```bash
# Build from source or use Windows installer
# Default port: 5678

python dicom_network_harness.py \
  --host localhost \
  --port 5678 \
  --called-ae CONQUESTSRV1
```

## Crash Analysis

### Triage Crashes

```bash
# Review crash details
cat findings/crashes.json | jq '.[] | {phase, error, timestamp}'

# Replay specific crash
python -c "
import socket
crash_data = open('findings/interesting/interesting_000001_abc123.bin', 'rb').read()
s = socket.socket()
s.connect(('localhost', 4242))
s.send(crash_data)
print(s.recv(1024))
"
```

### Generate Crash Report

```bash
dicom-fuzzer fda-report \
  --findings ./findings \
  --target orthanc \
  --output network_fuzz_report.md
```

## Performance Tuning

### Increase Throughput

```bash
# Reduce timeout for faster iterations
python dicom_network_harness.py --timeout 1.0 --iterations 100000

# Run multiple instances
for i in {1..4}; do
  python dicom_network_harness.py \
    --iterations 25000 \
    --output ./findings_$i &
done
wait
```

### Monitor Coverage

```bash
# Track unique states over time
watch -n 5 'cat findings/coverage.json | jq ".unique_states, .unique_transitions"'
```

## Security Considerations

- Only fuzz servers you own or have permission to test
- Use isolated Docker networks to prevent accidental exposure
- Monitor server resource usage to detect DoS conditions
- Back up any production data before fuzzing

## References

- [AFLNet Paper](https://arxiv.org/abs/2003.11096) - State-aware protocol fuzzing
- [DICOM Part 8](https://dicom.nema.org/medical/dicom/current/output/html/part08.html) - Network Communication
- [DICOM Part 7](https://dicom.nema.org/medical/dicom/current/output/html/part07.html) - Message Exchange
- [Orthanc Documentation](https://book.orthanc-server.com/)
