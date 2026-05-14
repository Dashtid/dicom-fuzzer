# dump-analyzer

ClrMD-based Windows minidump analyzer for the DICOM fuzzer's crash-clustering pipeline (Phase 2 of stack-trace capture).

## What it does

Reads a Windows minidump (`.dmp`, produced by ProcDump via `--dump-tool` in the fuzzer), walks the faulting thread's call stack using [`Microsoft.Diagnostics.Runtime`](https://github.com/microsoft/clrmd) (ClrMD), and emits a single JSON document to stdout that the Python wrapper consumes.

## Why ClrMD, not just minidump parsing

Managed PE assemblies carry their own MethodDef metadata table (ECMA-335). ClrMD reads it directly from the module image inside the dump, so symbolic stack traces of **closed-source .NET targets like Hermes work without PDBs or source access**. PDBs only add source-file/line-number info, which we don't need for clustering.

The `python minidump` library, by contrast, is native-frames-only — it cannot walk managed stacks at all.

## Build

```powershell
.\build.ps1
```

Produces a self-contained single-file Windows x64 executable at:

```
bin/Release/net8.0/win-x64/publish/dump-analyzer.exe
```

Size is ~67 MB self-contained (full .NET runtime bundled). **Not checked into the repo** — re-run `build.ps1` after pulling changes to this directory.

## Usage

```
dump-analyzer.exe <path-to-dump.dmp>
```

Always exits 0 on success or graceful failure (with `error` populated in the JSON); exits 1 on truly unexpected analyzer crashes and 2 on usage errors. The Python wrapper degrades gracefully to exception-code-only clustering on any non-zero exit.

## Output schema (`schema_version: 1`)

```json
{
  "schema_version": 1,
  "dump_path": "<input path>",
  "exception": {
    "code_hex": "0x80131509",
    "name": "InvalidOperationException",
    "address_hex": "0x..."
  },
  "faulting_thread_id": 12345,
  "frames": [
    {
      "is_managed": true,
      "module": "Hermes.exe",
      "type": "Hermes.Parser.DicomReader",
      "method": "ReadSequence",
      "signature": "ReadSequence(System.IO.Stream, Int32)",
      "md_token": "0x06000123",
      "il_offset_hex": "0x4a",
      "ip_hex": "0x7ffd..."
    }
  ],
  "error": null
}
```

For pure-native crashes (no managed runtime in the dump), `frames` falls back to the loaded module list — enough to fingerprint which DLL crashed even without per-frame unwinding.

## Why a separate exe, not `dotnet-dump analyze`

- `dotnet-dump` is the SOS REPL: scriptable but output is regex-fragile across .NET versions
- A direct ClrMD program gives us stable `MethodDef` tokens, IL offsets, and module names — load-bearing inputs to the Phase 3 stack-hash clustering algorithm
- A single subprocess invocation per crash beats spinning up a managed REPL per crash

The Python wrapper falls back to `dotnet-dump analyze -c clrstack -c exit` if the published binary is missing, so the build step isn't strictly required to run the campaign — just to get the higher-fidelity signal.
