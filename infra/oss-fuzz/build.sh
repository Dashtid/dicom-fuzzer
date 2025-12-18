#!/bin/bash -eu
# OSS-Fuzz build script for DICOM Fuzzer
#
# Environment variables provided by OSS-Fuzz:
#   CC, CXX: Compilers (e.g., clang, afl-clang-fast)
#   CFLAGS, CXXFLAGS: Compiler flags including sanitizers
#   LIB_FUZZING_ENGINE: Path to fuzzing engine library
#   OUT: Output directory for built fuzzers
#   SRC: Source directory
#   WORK: Working directory

cd $SRC/dicom-fuzzer

# Build C harnesses
echo "[+] Building AFL++ persistent mode harness"
$CC $CFLAGS -c harness/afl_persistent.c -o $WORK/afl_persistent.o
$CC $CFLAGS $LIB_FUZZING_ENGINE $WORK/afl_persistent.o -o $OUT/dicom_afl_harness

echo "[+] Building libFuzzer harness"
$CXX $CXXFLAGS -c harness/libfuzzer_harness.cpp -o $WORK/libfuzzer_harness.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $WORK/libfuzzer_harness.o -o $OUT/dicom_libfuzzer_harness

# Build custom mutator if AFL++
if [[ $CC == *"afl"* ]]; then
    echo "[+] Building DICOM custom mutator"
    $CC -shared -fPIC $CFLAGS \
        harness/custom_mutators/dicom_mutator.c \
        -o $OUT/dicom_mutator.so
fi

# Copy seed corpus
echo "[+] Preparing seed corpus"
mkdir -p $OUT/dicom_corpus

# Copy existing DICOM samples
if [ -d "samples/malicious_library" ]; then
    cp samples/malicious_library/*.dcm $OUT/dicom_corpus/ 2>/dev/null || true
fi

if [ -d "samples/cve_reproductions" ]; then
    find samples/cve_reproductions -name "*.dcm" -exec cp {} $OUT/dicom_corpus/ \;
fi

# Generate minimal seeds if corpus is empty
if [ -z "$(ls -A $OUT/dicom_corpus 2>/dev/null)" ]; then
    echo "[+] Generating minimal seed files"
    python3 -c "
import struct
import os

out_dir = os.environ.get('OUT', '.')
corpus_dir = os.path.join(out_dir, 'dicom_corpus')

# Minimal valid DICOM file
preamble = b'\x00' * 128
magic = b'DICM'

# File Meta Information Header
meta = b''
# (0002,0000) FileMetaInformationGroupLength
meta += struct.pack('<HHL', 0x0002, 0x0000, 4)
meta += struct.pack('<L', 100)
# (0002,0001) FileMetaInformationVersion
meta += struct.pack('<HHL', 0x0002, 0x0001, 2)
meta += b'\x00\x01'
# (0002,0002) MediaStorageSOPClassUID (CT Image Storage)
sop_class = b'1.2.840.10008.5.1.4.1.1.2'
meta += struct.pack('<HHL', 0x0002, 0x0002, len(sop_class))
meta += sop_class
if len(sop_class) % 2:
    meta += b'\x00'

# Write minimal seed
with open(os.path.join(corpus_dir, 'minimal_valid.dcm'), 'wb') as f:
    f.write(preamble + magic + meta)

# Edge case: empty after magic
with open(os.path.join(corpus_dir, 'empty_after_magic.dcm'), 'wb') as f:
    f.write(preamble + magic)

# Edge case: no magic
with open(os.path.join(corpus_dir, 'no_magic.dcm'), 'wb') as f:
    f.write(preamble + b'XXXX' + meta)

# Edge case: truncated preamble
with open(os.path.join(corpus_dir, 'truncated_preamble.dcm'), 'wb') as f:
    f.write(b'\x00' * 64 + magic)

print(f'Generated seed files in {corpus_dir}')
"
fi

# Create corpus zip for OSS-Fuzz
zip -j $OUT/dicom_afl_harness_seed_corpus.zip $OUT/dicom_corpus/*
zip -j $OUT/dicom_libfuzzer_harness_seed_corpus.zip $OUT/dicom_corpus/*

# Copy dictionary
echo "[+] Copying DICOM dictionary"
cp harness/dicom.dict $OUT/dicom_afl_harness.dict
cp harness/dicom.dict $OUT/dicom_libfuzzer_harness.dict

# Copy options file
echo "[+] Creating options files"
cat > $OUT/dicom_afl_harness.options << EOF
[libfuzzer]
max_len = 10485760
dict = dicom_afl_harness.dict
EOF

cat > $OUT/dicom_libfuzzer_harness.options << EOF
[libfuzzer]
max_len = 10485760
dict = dicom_libfuzzer_harness.dict
EOF

echo "[+] Build completed successfully"
ls -la $OUT/
