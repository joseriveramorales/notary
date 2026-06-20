using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Notary.Core;

public enum VerificationStatus { Trusted, Tampered, Unverifiable }

public sealed record VerificationResult(
    VerificationStatus Status,
    string? Signer,
    string Message,
    DateTimeOffset? TimestampUtc = null,
    string? TimestampAuthority = null);

/// <summary>The public material produced by signing some bytes: the detached signature, the
/// certificate to verify it with, and (optionally) an RFC 3161 trusted-timestamp token.</summary>
public sealed record SignatureBundle(byte[] Signature, byte[] Certificate, byte[]? Timestamp);

/// <summary>
/// The notary. Produces DETACHED sidecars next to a document and never modifies the
/// original. For "contract.pdf" it writes:
///   contract.pdf.sig   -> the signature over the file's SHA-256 hash
///   contract.pdf.cert  -> the X.509 certificate needed to verify it
///   contract.pdf.tsr   -> (optional) an RFC 3161 trusted timestamp over the same hash, proving WHEN
///
/// The file-based methods are thin wrappers over the byte-based core (SignBytes/VerifyBytes), which
/// the Web API (Milestone 6) uses directly so it never has to touch the filesystem.
/// </summary>
public sealed class NotaryService
{
    private readonly ISigningProvider _provider;
    private readonly ITimestampAuthority? _timestamper;
    public const string SigExt  = ".sig";
    public const string CertExt = ".cert";
    public const string TsrExt  = ".tsr";

    /// <param name="provider">Holds the private key and signs hashes on our behalf.</param>
    /// <param name="timestamper">Optional. When supplied, signing also produces an RFC 3161
    /// timestamp proving the content existed at a given time.</param>
    public NotaryService(ISigningProvider provider, ITimestampAuthority? timestamper = null)
    {
        _provider = provider;
        _timestamper = timestamper;
    }

    /// <summary>Sign raw content: hash it, sign the hash, return the public bundle
    /// (and, if a timestamp authority was supplied, an RFC 3161 token over the same hash).</summary>
    public SignatureBundle SignBytes(byte[] content)
    {
        byte[] hash = Hashing.Sha256(content);             // §2 fingerprint
        byte[] signature = _provider.SignHash(hash);        // §4 sign with private key
        byte[] cert = _provider.Certificate.Export(X509ContentType.Cert); // public cert only
        byte[]? tsr = _timestamper?.RequestToken(hash);     // §4 prove WHEN
        return new SignatureBundle(signature, cert, tsr);
    }

    /// <summary>Notarize a file: write the detached sidecars next to it (original untouched).</summary>
    public void Notarize(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException("Document not found.", filePath);

        var bundle = SignBytes(File.ReadAllBytes(filePath));
        File.WriteAllBytes(filePath + SigExt, bundle.Signature);
        File.WriteAllBytes(filePath + CertExt, bundle.Certificate);
        if (bundle.Timestamp is not null)
            File.WriteAllBytes(filePath + TsrExt, bundle.Timestamp);
    }

    /// <summary>Verify content against its signature, certificate and optional timestamp.
    /// Static: verification needs only public material, never the private key.</summary>
    public static VerificationResult VerifyBytes(byte[] content, byte[] signature, byte[] certificate, byte[]? timestamp = null)
    {
        using var cert = new X509Certificate2(certificate);
        using ECDsa? pub = cert.GetECDsaPublicKey();
        if (pub is null)
            return new(VerificationStatus.Unverifiable, null, "Certificate has no ECDSA public key.");

        byte[] hash = Hashing.Sha256(content);
        bool ok = pub.VerifyHash(hash, signature);
        var result = ok
            ? new VerificationResult(VerificationStatus.Trusted, cert.Subject, "Signature valid; file unchanged since signing.")
            : new VerificationResult(VerificationStatus.Tampered, cert.Subject, "Signature does NOT match — file altered or wrong key.");

        // If a trusted-timestamp token is present, fold its result in (proves WHEN, not just WHAT).
        if (timestamp is not null)
        {
            var ts = Timestamping.Verify(timestamp, hash);
            result = result with
            {
                TimestampUtc = ts.Valid ? ts.TimestampUtc : null,
                TimestampAuthority = ts.Valid ? ts.Authority : null,
                Message = $"{result.Message} {ts.Message}",
            };
        }

        return result;
    }

    /// <summary>Verify a file against its sidecars (.sig, .cert, optional .tsr).</summary>
    public static VerificationResult Verify(string filePath)
    {
        string sigPath = filePath + SigExt;
        string certPath = filePath + CertExt;
        string tsrPath = filePath + TsrExt;

        if (!File.Exists(filePath))  return new(VerificationStatus.Unverifiable, null, "Document not found.");
        if (!File.Exists(sigPath))   return new(VerificationStatus.Unverifiable, null, "Missing .sig sidecar.");
        if (!File.Exists(certPath))  return new(VerificationStatus.Unverifiable, null, "Missing .cert sidecar.");

        byte[] content = File.ReadAllBytes(filePath);
        byte[] signature = File.ReadAllBytes(sigPath);
        byte[] certificate = File.ReadAllBytes(certPath);
        byte[]? timestamp = File.Exists(tsrPath) ? File.ReadAllBytes(tsrPath) : null;

        return VerifyBytes(content, signature, certificate, timestamp);
    }
}
