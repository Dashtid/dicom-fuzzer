// Minimal C-STORE SCP provider used by the network harness.
//
// Accepts every incoming association unconditionally so the fuzzer
// can drive the server through any DIMSE path. On C-STORE, the
// provider walks the received dataset iteratively (forcing VR
// conversion on every element) and responds with Success.
//
// DicomFileException, DicomNetworkException, and DicomDataException
// are caught and mapped to ProcessingFailure -- those are fo-dicom's
// designed error reports. Anything else falls through to the
// AppDomain-level handler in Program.cs, which exits the process.

using System.Text;
using FellowOakDicom;
using FellowOakDicom.Network;
using Microsoft.Extensions.Logging;

namespace DicomFuzzer.Targets.FoDicomNetworkHarness;

internal sealed class CStoreProvider
    : DicomService,
        IDicomServiceProvider,
        IDicomCStoreProvider,
        IDicomCEchoProvider
{
    public CStoreProvider(
        INetworkStream stream,
        Encoding fallbackEncoding,
        ILogger logger,
        DicomServiceDependencies deps
    )
        : base(stream, fallbackEncoding, logger, deps) { }

    public async Task OnReceiveAssociationRequestAsync(DicomAssociation association)
    {
        foreach (var pc in association.PresentationContexts)
        {
            pc.SetResult(DicomPresentationContextResult.Accept);
        }
        await SendAssociationAcceptAsync(association).ConfigureAwait(false);
    }

    public Task OnReceiveAssociationReleaseRequestAsync()
    {
        return SendAssociationReleaseResponseAsync();
    }

    public void OnReceiveAbort(DicomAbortSource source, DicomAbortReason reason)
    {
        // Abort from peer -- nothing to do; connection will close.
    }

    public void OnConnectionClosed(Exception? exception)
    {
        // Bubble non-DICOM exceptions up so AppDomain handler catches them.
        if (exception is not null
            && exception is not DicomNetworkException
            && exception is not DicomDataException
            && exception is not DicomFileException
            && exception is not IOException
            && exception is not System.Net.Sockets.SocketException)
        {
            throw exception;
        }
    }

    public Task<DicomCStoreResponse> OnCStoreRequestAsync(DicomCStoreRequest request)
    {
        try
        {
            TraverseDataset(request.Dataset);
            return Task.FromResult(new DicomCStoreResponse(request, DicomStatus.Success));
        }
        catch (DicomFileException)
        {
            return Task.FromResult(new DicomCStoreResponse(request, DicomStatus.ProcessingFailure));
        }
        catch (DicomDataException)
        {
            return Task.FromResult(new DicomCStoreResponse(request, DicomStatus.ProcessingFailure));
        }
        // Other exceptions propagate -> AppDomain handler -> exit 1.
    }

    public Task OnCStoreRequestExceptionAsync(string tempFileName, Exception e)
    {
        // fo-dicom calls this when it fails to persist the incoming
        // dataset to a temp file. Anything beyond DicomFileException
        // is a fo-dicom bug candidate.
        if (e is not DicomFileException && e is not DicomDataException && e is not IOException)
        {
            throw e;
        }
        return Task.CompletedTask;
    }

    public Task<DicomCEchoResponse> OnCEchoRequestAsync(DicomCEchoRequest request)
    {
        return Task.FromResult(new DicomCEchoResponse(request, DicomStatus.Success));
    }

    // Iterative walk so the harness doesn't contribute stack frames
    // proportional to sequence nesting; any stack overflow comes from
    // fo-dicom's own decoder.
    private static void TraverseDataset(DicomDataset root)
    {
        var stack = new Stack<DicomDataset>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var ds = stack.Pop();
            foreach (var item in ds)
            {
                switch (item)
                {
                    case DicomSequence seq:
                        foreach (var child in seq.Items)
                        {
                            stack.Push(child);
                        }
                        break;
                    case DicomElement elem:
                        _ = elem.Buffer.Size;
                        _ = elem.Buffer.Data;
                        break;
                    case DicomFragmentSequence frags:
                        foreach (var frag in frags.Fragments)
                        {
                            _ = frag.Size;
                            _ = frag.Data;
                        }
                        break;
                }
            }
        }
    }
}
