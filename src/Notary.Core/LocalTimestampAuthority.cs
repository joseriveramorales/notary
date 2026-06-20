using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Notary.Core;

/// <summary>
/// A self-contained RFC 3161 Time-Stamp Authority that issues genuine timestamp tokens
/// in-process. It exists so the notary can be demoed and tested offline and deterministically
/// — a real deployment would point <see cref="HttpTimestampAuthority"/> at a public TSA instead.
///
/// What it produces is a real RFC 3161 token: a CMS SignedData whose encapsulated content is a
/// TSTInfo (the messageImprint + genTime), signed by a certificate carrying the *timeStamping*
/// extended-key-usage (RFC 3161 §2.3). The token verifies with the BCL's
/// <see cref="Rfc3161TimestampToken"/> just like a token from a commercial TSA.
/// </summary>
public sealed class LocalTimestampAuthority : ITimestampAuthority, IDisposable
{
    // OIDs referenced below.
    private static readonly Oid Sha256       = new("2.16.840.1.101.3.4.2.1");      // id-sha256
    private static readonly Oid TstInfo      = new("1.2.840.113549.1.9.16.1.4");   // id-ct-TSTInfo
    private static readonly Oid SigningCertV2 = new("1.2.840.113549.1.9.16.2.47"); // id-aa-signingCertificateV2
    private static readonly Oid TimeStampingEku = new("1.3.6.1.5.5.7.3.8");        // id-kp-timeStamping
    // A made-up private policy OID — a real TSA publishes its policy under its own arc.
    private static readonly Oid Policy = new("1.3.6.1.4.1.99999.1.1");

    private readonly X509Certificate2 _tsaCert; // self-signed, holds the private key

    public LocalTimestampAuthority(string commonName = "Personal Notary TSA")
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={commonName}", ecdsa, HashAlgorithmName.SHA256);

        // RFC 3161 §2.3: the TSA cert MUST have the timeStamping EKU, marked critical, and nothing else.
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(new OidCollection { TimeStampingEku }, critical: true));
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, false, 0, critical: true));

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));

        // Round-trip through PFX so the cert reliably carries its private key (same trick as the signer).
        var pfx = cert.Export(X509ContentType.Pkcs12);
        _tsaCert = new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.Exportable);
    }

    public byte[] RequestToken(byte[] sha256Hash)
    {
        // 1) Build the TSTInfo: "I, the TSA, attest that this hash was presented to me at genTime."
        var tstInfo = new Rfc3161TimestampTokenInfo(
            policyId: Policy,
            hashAlgorithmId: Sha256,
            messageHash: sha256Hash,
            serialNumber: NewSerialNumber(),
            timestamp: DateTimeOffset.UtcNow,
            accuracyInMicroseconds: 1_000_000); // claim ±1s accuracy

        // 2) Wrap it as the encapsulated content of a CMS SignedData, signed by the TSA cert.
        var content = new ContentInfo(TstInfo, tstInfo.Encode());
        var cms = new SignedCms(content, detached: false);

        var signer = new CmsSigner(_tsaCert)
        {
            DigestAlgorithm = Sha256,
            IncludeOption = X509IncludeOption.EndCertOnly,
        };
        // RFC 3161 verifiers (incl. the BCL) require the signer to pin its own cert via ESSCertIDv2.
        signer.SignedAttributes.Add(BuildSigningCertificateV2(_tsaCert));

        cms.ComputeSignature(signer);
        return cms.Encode(); // the DER token -> this is what gets written as the .tsr sidecar
    }

    /// <summary>Random, positive, minimally-encoded DER INTEGER for the token serial number.</summary>
    private static byte[] NewSerialNumber()
    {
        byte[] serial = RandomNumberGenerator.GetBytes(8);
        serial[0] = (byte)((serial[0] & 0x7F) | 0x01); // 0x01..0x7F: positive and no redundant leading zero
        return serial;
    }

    /// <summary>
    /// id-aa-signingCertificateV2 attribute value: a SigningCertificateV2 holding one ESSCertIDv2.
    /// With the default SHA-256 hash algorithm the algorithm field is omitted, so the value is just
    /// SEQUENCE { SEQUENCE { SEQUENCE { OCTET STRING certHash } } }.
    /// </summary>
    private static AsnEncodedData BuildSigningCertificateV2(X509Certificate2 cert)
    {
        byte[] certHash = SHA256.HashData(cert.RawData);

        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())          // SigningCertificateV2
        using (writer.PushSequence())          // certs : SEQUENCE OF ESSCertIDv2
        using (writer.PushSequence())          // ESSCertIDv2 (hashAlgorithm omitted => SHA-256 default)
            writer.WriteOctetString(certHash); // certHash

        return new AsnEncodedData(SigningCertV2, writer.Encode());
    }

    public void Dispose() => _tsaCert.Dispose();
}
