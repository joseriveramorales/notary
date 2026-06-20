using Notary.Core;

// Tiny CLI:  notary notarize <file> [--key key.pfx] [--pass <pw>] [--timestamp] [--tsa <url>]
//                                    [--keyvault <vaultUri> [--cert <name>]]
//            notary verify   <file>
// The signing key is loaded from (or created at) the --key PFX path.
// Keep that PFX OUT of your repo and OUT of iCloud.
//
//   --timestamp        also write an RFC 3161 .tsr proving WHEN (local in-process TSA, offline)
//   --tsa <url>        use a real RFC 3161 TSA over HTTP instead (implies --timestamp)
//   --keyvault <uri>   sign via Azure Key Vault (key never leaves the vault); --cert names the cert

if (args.Length < 2)
{
    Console.WriteLine("""
        Personal Notary
          notary notarize <file> [--key <key.pfx>] [--pass <password>] [--timestamp] [--tsa <url>]
                                 [--keyvault <vaultUri> [--cert <name>]]
          notary verify   <file>

        Produces detached sidecars next to the file (.sig, .cert, optional .tsr); never modifies the original.
        Verify is identical no matter where the key lived — it only needs the public .cert.
        """);
    return 1;
}

string command = args[0].ToLowerInvariant();
string file = args[1];
string keyPath = GetOpt("--key") ?? "notary-key.pfx";
string keyPass = GetOpt("--pass") ?? "changeit";

try
{
    switch (command)
    {
        case "notarize":
        {
            // The key lives locally by default, or in Azure Key Vault with --keyvault (Milestone 5).
            // Either way NotaryService only ever sees an ISigningProvider — that's the seam.
            string? vaultUri = GetOpt("--keyvault");
            ISigningProvider provider = vaultUri is not null
                ? KeyVaultSigningProvider.Connect(new Uri(vaultUri), GetOpt("--cert") ?? "notary")
                : File.Exists(keyPath)
                    ? LocalKeySigningProvider.LoadFromPfx(keyPath, keyPass)
                    : CreateAndSave(keyPath, keyPass);

            string? tsaUrl = GetOpt("--tsa");
            bool stamp = tsaUrl is not null || Array.IndexOf(args, "--timestamp") >= 0;

            // Pick a timestamp authority only if the user asked for one (keeps the default offline).
            ITimestampAuthority? tsa = tsaUrl is not null ? new HttpTimestampAuthority(tsaUrl)
                                     : stamp              ? new LocalTimestampAuthority()
                                     : null;
            try
            {
                if (vaultUri is not null) Console.WriteLine($"Signing via Azure Key Vault: {vaultUri}");
                new NotaryService(provider, tsa).Notarize(file);
                Console.WriteLine($"Notarized '{file}'");
                Console.WriteLine($"  -> {file}{NotaryService.SigExt}");
                Console.WriteLine($"  -> {file}{NotaryService.CertExt}");
                if (tsa is not null) Console.WriteLine($"  -> {file}{NotaryService.TsrExt}");
                Console.WriteLine($"  signer: {provider.Certificate.Subject}");
            }
            finally
            {
                (provider as IDisposable)?.Dispose();
                (tsa as IDisposable)?.Dispose();
            }
            return 0;
        }
        case "verify":
        {
            // Verify needs only the public sidecars, not the key.
            var result = NotaryService.Verify(file);
            Console.WriteLine($"[{result.Status}] {result.Message}");
            if (result.Signer is not null) Console.WriteLine($"  signer: {result.Signer}");
            if (result.TimestampUtc is not null)
            {
                Console.WriteLine($"  timestamped: {result.TimestampUtc:u}");
                if (result.TimestampAuthority is not null)
                    Console.WriteLine($"  TSA: {result.TimestampAuthority}");
            }
            return result.Status == VerificationStatus.Trusted ? 0 : 2;
        }
        default:
            Console.Error.WriteLine($"Unknown command '{command}'.");
            return 1;
    }
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

LocalKeySigningProvider CreateAndSave(string path, string pass)
{
    var p = LocalKeySigningProvider.Create("Jose Rivera Notary");
    p.SaveToPfx(path, pass);
    Console.WriteLine($"Generated new signing key -> {path} (keep this safe, out of git/iCloud)");
    return p;
}

string? GetOpt(string name)
{
    int i = Array.IndexOf(args, name);
    return (i >= 0 && i + 1 < args.Length) ? args[i + 1] : null;
}
