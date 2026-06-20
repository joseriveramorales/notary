using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Notary.Core;

/// <summary>
/// An <see cref="ISigningProvider"/> whose private key lives in Azure Key Vault and NEVER leaves it.
/// We send the 32-byte digest to the vault; the vault signs it (ES256 = ECDSA P-256 + SHA-256) and
/// returns the signature. That is the entire reason <see cref="ISigningProvider.SignHash"/> was
/// designed to take a precomputed hash rather than the document.
///
/// Because the contract is byte-for-byte identical to <see cref="LocalKeySigningProvider"/>,
/// <see cref="NotaryService"/>, the CLI, the .sig/.cert sidecars and the verifier are all unchanged
/// — swapping local custody for an HSM-backed vault is a one-line provider switch. That is the seam.
/// </summary>
public sealed class KeyVaultSigningProvider : ISigningProvider, IDisposable
{
    private readonly CryptographyClient _crypto;
    public X509Certificate2 Certificate { get; }

    /// <summary>
    /// Inject a <see cref="CryptographyClient"/> + public certificate directly. Production uses
    /// <see cref="Connect"/>; this constructor also allows a local-key CryptographyClient, which is
    /// how the provider is exercised in tests without an Azure subscription.
    /// </summary>
    public KeyVaultSigningProvider(CryptographyClient cryptographyClient, X509Certificate2 certificate)
    {
        _crypto = cryptographyClient;
        Certificate = certificate;
    }

    /// <summary>
    /// Connect to a vault, fetch the public certificate, and bind a crypto client to its key.
    /// Authentication is <see cref="DefaultAzureCredential"/> (env vars → managed identity →
    /// az login → Visual Studio), so no secrets live in code.
    /// </summary>
    public static KeyVaultSigningProvider Connect(Uri vaultUri, string certificateName, TokenCredential? credential = null)
    {
        credential ??= new DefaultAzureCredential();

        var certClient = new CertificateClient(vaultUri, credential);
        KeyVaultCertificateWithPolicy cert = certClient.GetCertificate(certificateName);

        var publicCert = new X509Certificate2(cert.Cer);             // public key + identity only
        var crypto = new CryptographyClient(cert.KeyId, credential); // signs remotely; key stays in the vault
        return new KeyVaultSigningProvider(crypto, publicCert);
    }

    public byte[] SignHash(byte[] sha256Hash)
        // Key Vault returns the IEEE P1363 (r||s) signature for ES256 — exactly the shape
        // ECDsa.VerifyHash expects on the verify side, identical to the local provider.
        => _crypto.Sign(SignatureAlgorithm.ES256, sha256Hash).Signature;

    public void Dispose() => Certificate.Dispose();
}
