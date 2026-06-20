using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Notary.Core;
using Xunit;

namespace Notary.Tests;

public class NotaryTests
{
    private static string TempFile(string content)
    {
        string path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public void Notarized_File_Verifies_As_Trusted()
    {
        string doc = TempFile("My important contract. v1.");
        using var provider = LocalKeySigningProvider.Create("Test Signer");

        new NotaryService(provider).Notarize(doc);
        var result = NotaryService.Verify(doc);

        Assert.Equal(VerificationStatus.Trusted, result.Status);
    }

    [Fact]
    public void Tampered_File_Verifies_As_Tampered()
    {
        string doc = TempFile("Pay Jose $100.");
        using var provider = LocalKeySigningProvider.Create("Test Signer");
        new NotaryService(provider).Notarize(doc);

        File.WriteAllText(doc, "Pay Jose $9000.");   // tamper after signing
        var result = NotaryService.Verify(doc);

        Assert.Equal(VerificationStatus.Tampered, result.Status);
    }

    [Fact]
    public void Notarize_Does_Not_Modify_Original()
    {
        const string original = "Untouched bytes.";
        string doc = TempFile(original);
        using var provider = LocalKeySigningProvider.Create();

        new NotaryService(provider).Notarize(doc);

        Assert.Equal(original, File.ReadAllText(doc));
        Assert.True(File.Exists(doc + NotaryService.SigExt));
        Assert.True(File.Exists(doc + NotaryService.CertExt));
    }

    [Fact]
    public void Saved_And_Reloaded_Key_Still_Verifies()
    {
        string doc = TempFile("Persisted-key document.");
        string pfx = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName() + ".pfx");

        using (var p = LocalKeySigningProvider.Create("Persistent Signer"))
            p.SaveToPfx(pfx, "pw");

        using (var reloaded = LocalKeySigningProvider.LoadFromPfx(pfx, "pw"))
            new NotaryService(reloaded).Notarize(doc);

        Assert.Equal(VerificationStatus.Trusted, NotaryService.Verify(doc).Status);
    }

    // ---- Milestone 4: RFC 3161 trusted timestamping ----

    [Fact]
    public void Timestamped_File_Verifies_And_Reports_When()
    {
        string doc = TempFile("Time-stamped contract.");
        using var provider = LocalKeySigningProvider.Create("Test Signer");
        using var tsa = new LocalTimestampAuthority("Test TSA");

        var before = DateTimeOffset.UtcNow.AddSeconds(-5);
        new NotaryService(provider, tsa).Notarize(doc);
        var after = DateTimeOffset.UtcNow.AddSeconds(5);

        Assert.True(File.Exists(doc + NotaryService.TsrExt)); // .tsr sidecar written

        var result = NotaryService.Verify(doc);
        Assert.Equal(VerificationStatus.Trusted, result.Status);
        Assert.NotNull(result.TimestampUtc);                  // a time was proven
        Assert.InRange(result.TimestampUtc!.Value, before, after);
        Assert.Contains("TSA", result.TimestampAuthority);    // CN=Test TSA
    }

    [Fact]
    public void Tampering_Breaks_The_Timestamp_Imprint()
    {
        string doc = TempFile("Pay Jose $100.");
        using var provider = LocalKeySigningProvider.Create("Test Signer");
        using var tsa = new LocalTimestampAuthority();
        new NotaryService(provider, tsa).Notarize(doc);

        File.WriteAllText(doc, "Pay Jose $9000.");            // tamper after timestamping
        var result = NotaryService.Verify(doc);

        Assert.Equal(VerificationStatus.Tampered, result.Status);
        Assert.Null(result.TimestampUtc);                     // imprint no longer matches the file
    }

    // ---- Milestone 5: Azure Key Vault (the ISigningProvider swap) ----

    [Fact]
    public void KeyVault_Provider_Produces_Sidecars_That_Verify()
    {
        string doc = TempFile("Signed as if by the vault.");

        // Stand in for Key Vault locally: one EC P-256 key drives a CryptographyClient over a
        // JsonWebKey (private) — the SAME client and the SAME ES256 Sign call the real provider uses
        // against a remote vault. The public cert is what the verifier sees. No Azure account needed.
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var crypto = new CryptographyClient(new JsonWebKey(ecdsa, includePrivateParameters: true));

        var request = new CertificateRequest("CN=Vault Signer", ecdsa, HashAlgorithmName.SHA256);
        using var fullCert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var publicCert = new X509Certificate2(fullCert.Export(X509ContentType.Cert)); // public only

        using var provider = new KeyVaultSigningProvider(crypto, publicCert);
        new NotaryService(provider).Notarize(doc);

        // The whole point of the seam: sidecars from the vault verify with the unchanged verifier.
        Assert.Equal(VerificationStatus.Trusted, NotaryService.Verify(doc).Status);
    }

    [Fact]
    public void Live_KeyVault_Signs_And_Verifies_When_Configured()
    {
        // Opt-in integration test. xunit 2.x has no dynamic skip, so when the vault isn't configured
        // this is a no-op; set NOTARY_KEYVAULT_URI + NOTARY_KEYVAULT_CERT (and be logged in to Azure)
        // to actually exercise a real vault end-to-end.
        string? vaultUri = Environment.GetEnvironmentVariable("NOTARY_KEYVAULT_URI");
        string? certName = Environment.GetEnvironmentVariable("NOTARY_KEYVAULT_CERT");
        if (vaultUri is null || certName is null)
            return;

        string doc = TempFile("Signed by a real Azure Key Vault.");
        using var provider = KeyVaultSigningProvider.Connect(new Uri(vaultUri), certName);
        new NotaryService(provider).Notarize(doc);

        Assert.Equal(VerificationStatus.Trusted, NotaryService.Verify(doc).Status);
    }
}
