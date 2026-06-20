using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Notary.Core;

/// <summary>Outcome of checking a <c>.tsr</c> sidecar against a document's current hash.</summary>
public sealed record TimestampCheck(bool Valid, DateTimeOffset? TimestampUtc, string? Authority, string Message);

/// <summary>
/// Reads and verifies RFC 3161 timestamp tokens (the <c>.tsr</c> sidecar).
/// Verification here is cryptographic: it proves the token's signature is intact and that its
/// messageImprint equals the hash we just computed from the file. (A production verifier would
/// *additionally* build and validate the TSA certificate chain to a trusted anchor — our local
/// demo TSA is self-signed, so that step is intentionally out of scope.)
/// </summary>
public static class Timestamping
{
    public static TimestampCheck Verify(byte[] tsrBytes, byte[] documentHash)
    {
        if (!Rfc3161TimestampToken.TryDecode(tsrBytes, out Rfc3161TimestampToken? token, out _) || token is null)
            return new(false, null, null, "Could not decode .tsr as an RFC 3161 token.");

        // VerifySignatureForHash checks BOTH the CMS signature AND that the token's messageImprint
        // matches this hash — so a tampered file (different hash) fails right here.
        bool ok = token.VerifySignatureForHash(documentHash, HashAlgorithmName.SHA256, out var signerCert);
        var when = token.TokenInfo.Timestamp;
        string? authority = signerCert?.Subject;
        signerCert?.Dispose();

        return ok
            ? new(true, when, authority, $"Timestamp valid; hash existed at {when:u}.")
            : new(false, when, authority, "Timestamp does NOT match this file's hash.");
    }
}
