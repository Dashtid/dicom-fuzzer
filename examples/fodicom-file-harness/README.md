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

| Code                  | Meaning                                                                                                   |
| --------------------- | --------------------------------------------------------------------------------------------------------- |
| 0                     | Parsed and traversed cleanly                                                                              |
| 1                     | Uncaught exception -- **candidate fo-dicom bug**                                                          |
| 2                     | Invalid CLI args                                                                                          |
| 10                    | `DicomFileException` (fo-dicom's designed malformation report, expected)                                  |
| non-zero from runtime | Process killed by the runtime (e.g. `StackOverflowException`, which .NET cannot catch). Also interesting. |

## Integration with dicom-fuzzer

```bash
dicom-fuzzer ./dicom-seeds -r -c 200 \
  -t ./examples/fodicom-file-harness/bin/Release/net8.0/win-x64/publish/fodicom-file-harness.exe \
  --timeout 10
```

The target runner will record non-zero exits as crashes and cluster them by signature.

## What the harness does NOT do

- Doesn't try to catch `StackOverflowException` (impossible in .NET; runtime handles it).
- Doesn't write output files. Malformed data that parses fine is indistinguishable from valid data as far as this harness is concerned -- that's correct: we want the existing dataset-level oracle (no crash) to be "pass."
- Doesn't attempt to render pixel data. Decoder-level crashes need a separate harness that calls `DicomPixelData.Create(ds).GetFrame(0)`.
