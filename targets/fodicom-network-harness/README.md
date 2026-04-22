# fo-dicom network harness

Minimal DIMSE SCP built on [fo-dicom](https://github.com/fo-dicom/fo-dicom) so dicom-fuzzer's network module has a real peer to talk to. Accepts every association unconditionally and traverses every received dataset (forcing VR conversion) on C-STORE, so parsing bugs in fo-dicom's network-side decoder surface as crashes.

Supports plain-text DIMSE and TLS.

## Build

```bash
cd targets/fodicom-network-harness
dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true
```

Binary at `bin/Release/net8.0/win-x64/publish/fodicom-network-harness.exe`.

## Generate a TLS cert (one-time)

```powershell
cd targets/fodicom-network-harness
pwsh ./gen-cert.ps1
```

Produces `fodicom-harness.pfx` in this directory. Password is `fuzz`. Cert is gitignored.

## Run

```bash
# Plain DIMSE on default port 11112
./bin/Release/net8.0/win-x64/publish/fodicom-network-harness.exe

# Custom port and AE title
./bin/Release/net8.0/win-x64/publish/fodicom-network-harness.exe --port 11113 --ae-title MY_SCP

# TLS
./bin/Release/net8.0/win-x64/publish/fodicom-network-harness.exe --tls ./fodicom-harness.pfx fuzz
```

Press Ctrl+C to stop. The harness blocks until SIGINT.

## Exit codes

| Code | Meaning                                           |
| ---- | ------------------------------------------------- |
| 0    | Clean shutdown via Ctrl+C                         |
| 1    | Unhandled exception -- **candidate fo-dicom bug** |
| 2    | Invalid CLI args                                  |

`AppDomain.UnhandledException` and `TaskScheduler.UnobservedTaskException` are both wired to `Environment.Exit(1)` so fo-dicom's internal exception handling cannot swallow a parser bug.

## Integration with dicom-fuzzer

Start the harness in one terminal:

```bash
./bin/Release/net8.0/win-x64/publish/fodicom-network-harness.exe
```

Fire the network fuzzer in another:

```bash
dicom-fuzzer path/to/seed.dcm --network-fuzz \
  --host localhost --port 11112 --ae-title FUZZ_SCU
```

For TLS, start the harness with `--tls` and use dicom-fuzzer's TLS network flags once they're wired through the CLI (currently `--network-fuzz` speaks plain DIMSE only; TLS path is tested via the `tls` subcommand and Python unit tests).

## Caveats

- The harness accepts **every** presentation context. It does not enforce SOPClass/TransferSyntax restrictions. That's intentional -- we want the fuzzer to be able to send anything and observe how fo-dicom's decoder copes.
- `OnCStoreRequestAsync` catches `DicomFileException` and `DicomDataException` as expected malformation reports. Any other exception bubbles to the AppDomain handler and kills the process.
- The server holds no state between associations. Each C-STORE is independent. If you need a persistent PACS behavior, extend the provider.
- No archiving. Received datasets are traversed then discarded.
- TLS uses a custom `PfxTlsAcceptor` rather than fo-dicom's `DefaultTlsAcceptor`, because the default one resolves its argument via the Windows certificate store before any custom `Certificate` property can be set, which doesn't fit the "self-contained PFX on disk" workflow. `PfxTlsAcceptor` accepts TLS 1.2 and 1.3 with `clientCertificateRequired: false`.
