// Minimal ITlsAcceptor that loads a PFX from disk and wraps incoming
// connections in an SslStream. Sidesteps DefaultTlsAcceptor, whose
// constructor insists on resolving its argument via the Windows
// certificate store (or a path-based helper that didn't work for our
// self-signed PFX) before any custom Certificate property can be set.

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using FellowOakDicom.Network.Tls;

namespace DicomFuzzer.Targets.FoDicomNetworkHarness;

internal sealed class PfxTlsAcceptor : ITlsAcceptor
{
    private readonly X509Certificate2 _certificate;

    public PfxTlsAcceptor(string pfxPath, string password)
    {
        _certificate = new X509Certificate2(pfxPath, password);
    }

    public Stream AcceptTls(Stream encryptedStream, string remoteAddress, int localPort)
    {
        var sslStream = new SslStream(
            encryptedStream,
            leaveInnerStreamOpen: false,
            userCertificateValidationCallback: null
        );
        sslStream.AuthenticateAsServer(
            _certificate,
            clientCertificateRequired: false,
            enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
            checkCertificateRevocation: false
        );
        return sslStream;
    }
}
