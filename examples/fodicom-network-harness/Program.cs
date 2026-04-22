// fo-dicom network harness.
//
// Spins up a DicomServer with a minimal CStoreProvider so our Python
// network fuzzer has a real DIMSE peer to talk to. The provider
// traverses every received dataset (forcing VR conversion) so parsing
// bugs in fo-dicom's network-side dataset decoder surface as crashes.
//
// The process runs until Ctrl+C or until any unhandled exception
// escapes the provider -- we hook AppDomain.UnhandledException and
// TaskScheduler.UnobservedTaskException to Environment.Exit(1) so
// fo-dicom's internal error handling cannot swallow a bug.
//
// CLI:
//   fodicom-network-harness [--port N] [--ae-title AET] [--tls CERT.pfx PASSWORD]
//
// Exit codes:
//   0  clean shutdown via Ctrl+C
//   1  unhandled exception (candidate fo-dicom bug)
//   2  invalid CLI args

using FellowOakDicom.Network;

namespace DicomFuzzer.Targets.FoDicomNetworkHarness;

internal static class Program
{
    private static int Main(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            Console.Error.WriteLine($"UNHANDLED: {e.ExceptionObject}");
            Environment.Exit(1);
        };
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            Console.Error.WriteLine($"UNOBSERVED TASK: {e.Exception}");
            e.SetObserved();
            Environment.Exit(1);
        };

        var opts = ParseArgs(args);
        if (opts is null)
        {
            return 2;
        }

        try
        {
            IDicomServer server;
            if (opts.TlsCertPath is not null)
            {
                // Custom ITlsAcceptor that loads a PFX directly. The bundled
                // DefaultTlsAcceptor insists on resolving its argument via
                // the Windows certificate store in its constructor, which
                // doesn't fit our "self-contained PFX on disk" workflow.
                var acceptor = new PfxTlsAcceptor(
                    opts.TlsCertPath,
                    opts.TlsCertPassword ?? string.Empty
                );
                server = DicomServerFactory.Create<CStoreProvider>(
                    opts.Port,
                    tlsAcceptor: acceptor
                );
            }
            else
            {
                server = DicomServerFactory.Create<CStoreProvider>(opts.Port);
            }

            Console.WriteLine(
                $"fodicom-network-harness listening on port {opts.Port} "
                + $"AE='{opts.AeTitle}' TLS={opts.TlsCertPath is not null}"
            );
            Console.WriteLine("Press Ctrl+C to stop.");

            using var waiter = new ManualResetEventSlim();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                waiter.Set();
            };
            waiter.Wait();

            server.Stop();
            server.Dispose();
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"STARTUP FAILED: {ex}");
            return 1;
        }
    }

    private sealed record Options(int Port, string AeTitle, string? TlsCertPath, string? TlsCertPassword);

    private static Options? ParseArgs(string[] args)
    {
        int port = 11112;
        string aeTitle = "FUZZ_SCP";
        string? certPath = null;
        string? certPassword = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--port":
                    if (i + 1 >= args.Length || !int.TryParse(args[++i], out port))
                    {
                        return Usage();
                    }
                    break;
                case "--ae-title":
                    if (i + 1 >= args.Length)
                    {
                        return Usage();
                    }
                    aeTitle = args[++i];
                    break;
                case "--tls":
                    if (i + 2 >= args.Length)
                    {
                        return Usage();
                    }
                    certPath = args[++i];
                    certPassword = args[++i];
                    break;
                case "-h":
                case "--help":
                    PrintUsage();
                    return null;
                default:
                    Console.Error.WriteLine($"unknown arg: {args[i]}");
                    return Usage();
            }
        }

        return new Options(port, aeTitle, certPath, certPassword);
    }

    private static Options? Usage()
    {
        PrintUsage();
        return null;
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine(
            "usage: fodicom-network-harness [--port N] [--ae-title AET] "
            + "[--tls CERT.pfx PASSWORD]"
        );
    }
}
