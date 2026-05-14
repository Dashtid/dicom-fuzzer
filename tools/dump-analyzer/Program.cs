// DICOM Fuzzer dump analyzer.
//
// Reads a Windows minidump (.dmp) produced by ProcDump, walks the
// faulting thread's call stack via ClrMD, and emits a single JSON
// document to stdout for the Python crash-clustering pipeline to
// consume.
//
// Key property of ClrMD that this tool relies on: managed PE assemblies
// carry their own MethodDef metadata table (ECMA-335). ClrMD reads it
// directly from the module image inside the dump, so symbolic stack
// traces of CLOSED-SOURCE .NET targets (like Hermes) work without PDBs
// or source access. PDBs only add source-file/line-number info, which
// we don't need for clustering.
//
// Output schema (single JSON object on stdout):
//   {
//     "schema_version": 1,
//     "dump_path": "<input path>",
//     "exception": { "code_hex": "0xC00000FD", "name": "STACK_OVERFLOW",
//                    "address_hex": "0x..." } | null,
//     "faulting_thread_id": <int> | null,
//     "frames": [
//       { "is_managed": true,
//         "module": "Hermes.exe",
//         "type": "Hermes.Parser.DicomReader",
//         "method": "ReadSequence",
//         "signature": "ReadSequence(System.IO.Stream, Int32)",
//         "md_token": "0x06000123",
//         "il_offset_hex": "0x4a",
//         "ip_hex": "0x7ffd..." },
//       { "is_managed": false,
//         "module": "ntdll.dll",
//         "type": null, "method": null,
//         "signature": null, "md_token": null,
//         "il_offset_hex": null,
//         "ip_hex": "0x7ffd..." }
//     ],
//     "error": null
//   }
//
// On any failure that prevents stack walking we still emit a valid JSON
// document with "error" populated; the Python wrapper then degrades
// gracefully to exception-code-only clustering.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Diagnostics.Runtime;

namespace DicomFuzzer.DumpAnalyzer;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            EmitError(dumpPath: null, message: "usage: dump-analyzer <path-to-dump>");
            return 2;
        }

        var dumpPath = args[0];
        if (!File.Exists(dumpPath))
        {
            EmitError(dumpPath, $"dump file not found: {dumpPath}");
            return 2;
        }

        try
        {
            using var target = DataTarget.LoadDump(dumpPath);

            // For .NET 8+ apps ClrMD picks the right CLR automatically.
            // Pure-native crash (no managed runtime) -> emit native
            // module list as a fallback signature source.
            var clrInfo = target.ClrVersions.FirstOrDefault();
            if (clrInfo is null)
            {
                EmitResult(
                    dumpPath,
                    exception: null,
                    faultingThreadId: null,
                    frames: NativeFallbackFrames(target));
                return 0;
            }

            using var runtime = clrInfo.CreateRuntime();
            var (faultingThreadId, frames, managedException) = WalkFaultingThread(runtime);
            EmitResult(dumpPath, managedException, faultingThreadId, frames);
            return 0;
        }
        catch (Exception ex)
        {
            EmitError(dumpPath, $"unexpected analyzer failure: {ex.GetType().Name}: {ex.Message}");
            return 1;
        }
    }

    private static (int? faultingThreadId, List<FrameInfo> frames, ExceptionInfo? exception)
        WalkFaultingThread(ClrRuntime runtime)
    {
        // Prefer the thread that has a CurrentException set -- ClrMD's
        // view of "the thread that crashed". Fall back to the first
        // thread if none has one, so we always emit SOMETHING. The
        // Python side logs the fallback as a warning.
        ClrThread? fault = runtime.Threads.FirstOrDefault(t => t.CurrentException is not null)
                           ?? runtime.Threads.FirstOrDefault();

        if (fault is null)
            return (faultingThreadId: null, frames: new List<FrameInfo>(), exception: null);

        var frames = new List<FrameInfo>(capacity: 64);
        foreach (var f in fault.EnumerateStackTrace())
        {
            var method = f.Method;
            if (method is not null)
            {
                var typeName = method.Type?.Name ?? "<no-type>";
                var moduleName = ModuleName(method.Type?.Module);
                frames.Add(new FrameInfo(
                    IsManaged: true,
                    Module: moduleName,
                    Type: typeName,
                    Method: method.Name,
                    Signature: method.Signature,
                    MdToken: $"0x{method.MetadataToken:x8}",
                    ILOffsetHex: TryFormatILOffset(f),
                    IPHex: $"0x{f.InstructionPointer:x}"
                ));
            }
            else
            {
                // Native or runtime frame interleaved in the managed
                // walk. Keep it so the Python side can include native
                // module hashes in its signature.
                frames.Add(new FrameInfo(
                    IsManaged: false,
                    Module: null,
                    Type: null,
                    Method: null,
                    Signature: null,
                    MdToken: null,
                    ILOffsetHex: null,
                    IPHex: $"0x{f.InstructionPointer:x}"
                ));
            }
        }

        ExceptionInfo? managedException = null;
        var ex = fault.CurrentException;
        if (ex is not null)
        {
            managedException = new ExceptionInfo(
                CodeHex: $"0x{ex.HResult:x8}",
                Name: ex.Type.Name ?? "<unknown>",
                AddressHex: $"0x{ex.Address:x}"
            );
        }

        return (faultingThreadId: (int)fault.OSThreadId, frames, exception: managedException);
    }

    private static List<FrameInfo> NativeFallbackFrames(DataTarget target)
    {
        // When there's no managed runtime in the dump, we still surface
        // the loaded module list so the Python side can include them in
        // its native-stack signature. We don't walk the native stack
        // ourselves -- ClrMD doesn't, and adding a separate native
        // unwinder is out of scope. (For native fo-dicom harness work,
        // this is enough: the module list pinpoints which DLL crashed
        // even without per-frame unwinding.)
        var frames = new List<FrameInfo>();
        foreach (var module in target.EnumerateModules())
        {
            frames.Add(new FrameInfo(
                IsManaged: false,
                Module: Path.GetFileName(module.FileName) ?? "<unknown>",
                Type: null,
                Method: null,
                Signature: null,
                MdToken: null,
                ILOffsetHex: null,
                IPHex: $"0x{module.ImageBase:x}"
            ));
        }
        return frames;
    }

    private static string ModuleName(ClrModule? module)
    {
        if (module is null) return "<unknown>";
        var n = module.Name ?? "";
        // ClrMD returns the full file path; the Python hasher wants the
        // short module name only (e.g. "Hermes.exe", "System.Private.CoreLib.dll").
        return Path.GetFileName(n);
    }

    private static string? TryFormatILOffset(ClrStackFrame f)
    {
        // ClrMD exposes ILOffset on some frames and not others (the
        // native portion of the runtime's interop stubs has no IL).
        // We probe via reflection because the public API surface
        // changed across ClrMD 3.x -> 4.x; safer than a hard
        // dependency on a specific property name.
        try
        {
            var prop = f.GetType().GetProperty("ILOffset");
            if (prop?.GetValue(f) is int il && il >= 0)
                return $"0x{il:x}";
        }
        catch { /* swallow -- not critical */ }
        return null;
    }

    private static void EmitResult(
        string dumpPath,
        ExceptionInfo? exception,
        int? faultingThreadId,
        List<FrameInfo> frames)
    {
        var result = new ResultDoc(
            SchemaVersion: 1,
            DumpPath: dumpPath,
            Exception: exception,
            FaultingThreadId: faultingThreadId,
            Frames: frames,
            Error: null
        );
        Console.WriteLine(JsonSerializer.Serialize(result, JsonOpts));
    }

    private static void EmitError(string? dumpPath, string message)
    {
        var result = new ResultDoc(
            SchemaVersion: 1,
            DumpPath: dumpPath,
            Exception: null,
            FaultingThreadId: null,
            Frames: new List<FrameInfo>(),
            Error: message
        );
        Console.WriteLine(JsonSerializer.Serialize(result, JsonOpts));
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };
}

internal sealed record ExceptionInfo(string CodeHex, string Name, string AddressHex);

internal sealed record FrameInfo(
    bool IsManaged,
    string? Module,
    string? Type,
    string? Method,
    string? Signature,
    string? MdToken,
    string? ILOffsetHex,
    string IPHex
);

internal sealed record ResultDoc(
    int SchemaVersion,
    string? DumpPath,
    ExceptionInfo? Exception,
    int? FaultingThreadId,
    List<FrameInfo> Frames,
    string? Error
);
