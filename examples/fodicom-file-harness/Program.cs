// fo-dicom file harness.
//
// Opens a single DICOM file with fo-dicom, walks every element (forcing
// value materialisation), and exits with a distinct code depending on
// what happened. Designed to be invoked by dicom-fuzzer's -t EXE flow
// so our Python target runner can classify findings without guessing.
//
// Exit codes:
//   0  parsed, traversed, and decoded cleanly
//   1  uncaught exception during parse/traversal (fo-dicom bug candidate)
//   2  invalid CLI args
//   10 DicomFileException during parse (fo-dicom's designed malformation report)
//   11 any exception during pixel-data decode (transfer-syntax codec path)
//
// 11 is split from 10 so campaign telemetry can distinguish parser-side
// findings from decoder-side ones. Most fo-dicom crashes worth chasing
// live in the JPEG-LS / JPEG2000 / RLE decoder paths that GetFrame triggers,
// not in the dataset walker.
//
// StackOverflowException is not catchable in .NET; the runtime will
// terminate the process with its own non-zero exit. That's fine --
// target_runner already logs non-zero exits and a stack overflow from
// deeply-nested SQ is precisely the crash class we want surfaced.

using FellowOakDicom;
using FellowOakDicom.Imaging;

namespace DicomFuzzer.Targets.FoDicomFileHarness;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("usage: fodicom-file-harness <file.dcm>");
            return 2;
        }

        DicomFile file;
        try
        {
            file = DicomFile.Open(args[0]);
            TraverseDataset(file.Dataset);
            if (file.FileMetaInfo is not null)
            {
                TraverseDataset(file.FileMetaInfo);
            }
        }
        catch (DicomFileException ex)
        {
            Console.Error.WriteLine($"DicomFileException: {ex.Message}");
            return 10;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }

        // Decode frame 0 to exercise the transfer-syntax codec paths
        // (JPEG-LS, JPEG2000, RLE, encapsulated streams). This is where
        // most of the interesting fo-dicom bugs live -- the dataset walker
        // above is too lenient on its own.
        if (file.Dataset.Contains(DicomTag.PixelData))
        {
            try
            {
                var pixelData = DicomPixelData.Create(file.Dataset);
                if (pixelData.NumberOfFrames > 0)
                {
                    _ = pixelData.GetFrame(0);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"PixelData decode failed: {ex}");
                return 11;
            }
        }

        return 0;
    }

    // Iterative walk so we don't contribute stack frames proportional to
    // sequence nesting. Any StackOverflowException we observe then comes
    // from fo-dicom's own recursion, not our traversal.
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
                        // Force buffer materialisation -- this is what
                        // exercises VR parsing and value decoding.
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
