# fo-dicom file harness

Tiny .NET 8 console wrapper around [fo-dicom](https://github.com/fo-dicom/fo-dicom) so dicom-fuzzer can treat it as a target via `-t EXE`. Opens a single DICOM file, walks every element to force value materialisation, and exits with a distinct code depending on what fo-dicom did.

## Build

```bash
cd examples/fodicom-file-harness
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
```

Binary lands at `bin/Release/net8.0/win-x64/publish/fodicom-file-harness.exe`.

For other platforms swap the runtime ID (`-r linux-x64`, `-r osx-arm64`, etc.).

## Usage

```bash
./bin/Release/net8.0/win-x64/publish/fodicom-file-harness.exe path/to/file.dcm
```

## Exit codes

The split between **typed** (10, 12) and **untyped** (1, 11) catches lets triage
separate "library refused malformed input as designed" from "library code
raised an exception type it shouldn't have."

| Code                  | Meaning                                                                                                                           |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 0                     | Parsed, traversed, and (if PixelData present) frame 0 decoded cleanly                                                             |
| 1                     | Untyped exception during parse/traversal -- escaped fo-dicom's typed hierarchy, **candidate library bug**                         |
| 2                     | Invalid CLI args                                                                                                                  |
| 10                    | `DicomFileException` during parse (fo-dicom's designed malformation report, **expected, not a finding**)                          |
| 11                    | Untyped exception during pixel-data decode -- escaped fo-dicom's typed hierarchy, **candidate codec bug**                         |
| 12                    | Typed `DicomException` (e.g. `DicomDataException`, `DicomImagingException`) during parse or decode -- **expected, not a finding** |
| non-zero from runtime | Process killed by the runtime (e.g. `StackOverflowException`, which .NET cannot catch). **Also interesting.**                     |

Findings worth chasing: 1, 11, and runtime-terminated exits. Codes 10 and 12
mean fo-dicom did its job and rejected malformed input cleanly.

## Integration with dicom-fuzzer

```bash
dicom-fuzzer ./dicom-seeds -r -c 200 \
  -t ./examples/fodicom-file-harness/bin/Release/net8.0/win-x64/publish/fodicom-file-harness.exe \
  --timeout 10 \
  --crash-exit-codes 1,11
```

`--crash-exit-codes 1,11` tells the dicom-fuzzer target runner to record the
**untyped-escape** exit codes as crashes. Without it, rc=1 and rc=11 fall to
`ExecutionStatus.ERROR` and are silently dropped from findings -- which means
real candidate library bugs would never be reported. Codes 10 and 12 are
deliberately omitted: those are typed `DicomException` rejections (library
doing its job, not a finding). Native runtime crashes (`StackOverflowException`
etc.) are recorded automatically by the existing Windows / negative-signal
classifier and don't need to be listed.

## What the harness does NOT do

- Doesn't try to catch `StackOverflowException` (impossible in .NET; runtime handles it).
- Doesn't write output files. Malformed data that parses fine is indistinguishable from valid data as far as this harness is concerned -- that's correct: we want the existing dataset-level oracle (no crash) to be "pass."
- Doesn't render pixel data to a bitmap. `GetFrame(0)` exercises codec/decoder paths but stops short of the colour-space / windowing pipeline.
