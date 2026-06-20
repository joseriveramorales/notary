using System.Security.Cryptography.X509Certificates;

namespace Notary.Core;

/// <summary>
/// Abstraction over "the thing that holds the private key and signs on our behalf."
/// Today: <see cref="LocalKeySigningProvider"/> (key in a local PFX).
/// Later (Milestone 5): a KeyVaultSigningProvider where the private key NEVER leaves
/// Azure Key Vault — the contract is identical, only the implementation changes.
/// Note we hand the provider a precomputed HASH, exactly the shape Key Vault expects.
/// </summary>
public interface ISigningProvider
{
    /// <summary>Sign a precomputed SHA-256 hash. Returns the raw signature bytes.</summary>
    byte[] SignHash(byte[] sha256Hash);

    /// <summary>The X.509 certificate (public key + identity) used to verify signatures.</summary>
    X509Certificate2 Certificate { get; }
}
