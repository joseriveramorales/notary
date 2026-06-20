namespace Notary.Core;

/// <summary>
/// Abstraction over "a trusted clock that will vouch, in writing, for *when* a hash existed."
/// This is the same seam idea as <see cref="ISigningProvider"/>: today
/// <see cref="LocalTimestampAuthority"/> issues RFC 3161 tokens in-process (great for tests and
/// offline demos); swap in <see cref="HttpTimestampAuthority"/> to use a real public TSA
/// (DigiCert, freeTSA, …) without changing a line of <see cref="NotaryService"/>.
///
/// Note we hand the authority a precomputed HASH, never the document — exactly the
/// RFC 3161 "messageImprint" shape, so the file's bytes never leave the machine.
/// </summary>
public interface ITimestampAuthority
{
    /// <summary>
    /// Request an RFC 3161 timestamp over <paramref name="sha256Hash"/>.
    /// Returns the DER-encoded timestamp token (a CMS SignedData wrapping a TSTInfo),
    /// which is what we persist as the <c>.tsr</c> sidecar.
    /// </summary>
    byte[] RequestToken(byte[] sha256Hash);
}
