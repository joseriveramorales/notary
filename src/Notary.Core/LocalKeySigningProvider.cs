using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Notary.Core;

/// <summary>
/// A signing provider backed by a local ECDSA P-256 key wrapped in a self-signed X.509
/// certificate. Good enough to learn and demo. In production you would never keep the
/// private key on disk — that is exactly the problem Key Vault / an HSM solves, and why
/// Milestone 5 swaps this class out without touching anything else.
/// </summary>
public sealed class LocalKeySigningProvider : ISigningProvider, IDisposable
{
    private readonly ECDsa _ecdsa;
    public X509Certificate2 Certificate { get; }

    private LocalKeySigningProvider(X509Certificate2 certWithKey)
    {
        Certificate = certWithKey;
        _ecdsa = certWithKey.GetECDsaPrivateKey()
                 ?? throw new InvalidOperationException("Certificate has no ECDSA private key.");
    }

    /// <summary>Generate a fresh key + self-signed certificate for the given identity.</summary>
    public static LocalKeySigningProvider Create(string commonName = "Personal Notary")
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            $"CN={commonName}", ecdsa, HashAlgorithmName.SHA256);

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));

        // Round-trip through PFX so the returned cert reliably carries the private key.
        var pfx = cert.Export(X509ContentType.Pkcs12);
        var loaded = new X509Certificate2(pfx, (string?)null,
            X509KeyStorageFlags.Exportable);
        return new LocalKeySigningProvider(loaded);
    }

    /// <summary>Persist the key + cert to an encrypted PFX (keep this OUT of your repo and iCloud).</summary>
    public void SaveToPfx(string path, string password)
        => File.WriteAllBytes(path, Certificate.Export(X509ContentType.Pkcs12, password));

    /// <summary>Load a previously saved PFX.</summary>
    public static LocalKeySigningProvider LoadFromPfx(string path, string password)
    {
        var cert = new X509Certificate2(
            File.ReadAllBytes(path), password, X509KeyStorageFlags.Exportable);
        return new LocalKeySigningProvider(cert);
    }

    public byte[] SignHash(byte[] sha256Hash)
        // IEEE P1363 fixed-size (r||s) signature, matching VerifyHash on the other side.
        => _ecdsa.SignHash(sha256Hash);

    public void Dispose()
    {
        _ecdsa.Dispose();
        Certificate.Dispose();
    }
}
