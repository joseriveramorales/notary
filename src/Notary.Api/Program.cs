using Notary.Core;

// Personal Notary HTTP API (Milestone 6). Thin REST shell over the exact same NotaryService:
//   POST /sign     multipart 'file' [+ timestamp=true]  -> { signer, signature, certificate, timestamp? }
//   POST /verify   multipart 'file' + 'signature' + 'certificate' [+ 'timestamp']  -> { status, ... }
// Signatures/certs/timestamps cross the wire as base64. The service never writes to disk.

var builder = WebApplication.CreateBuilder(args);

// One signing identity for the whole process. Where the key lives is decided by env vars
// (Key Vault > local PFX > ephemeral dev key) — the API code never cares, that's the seam.
builder.Services.AddSingleton(ProviderFactory.Build());
builder.Services.AddSingleton<ITimestampAuthority>(_ => new LocalTimestampAuthority());

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "Personal Notary",
    endpoints = new[]
    {
        "POST /sign   (multipart: file, [timestamp=true])",
        "POST /verify (multipart: file, signature, certificate, [timestamp])",
    },
}));

// Liveness probe for containers / orchestrators.
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/sign", async (HttpRequest req, ISigningProvider signer, ITimestampAuthority tsa) =>
{
    if (!req.HasFormContentType) return Results.BadRequest("Send multipart/form-data with a 'file' field.");
    var form = await req.ReadFormAsync();
    var file = form.Files["file"];
    if (file is null) return Results.BadRequest("Missing 'file'.");

    bool stamp = form.TryGetValue("timestamp", out var t) &&
                 (t == "true" || t == "1");

    byte[] content = await ReadAllBytesAsync(file);
    var bundle = new NotaryService(signer, stamp ? tsa : null).SignBytes(content);

    return Results.Ok(new SignResponse(
        Signer: signer.Certificate.Subject,
        Signature: Convert.ToBase64String(bundle.Signature),
        Certificate: Convert.ToBase64String(bundle.Certificate),
        Timestamp: bundle.Timestamp is null ? null : Convert.ToBase64String(bundle.Timestamp)));
});

app.MapPost("/verify", async (HttpRequest req) =>
{
    if (!req.HasFormContentType) return Results.BadRequest("Send multipart/form-data.");
    var form = await req.ReadFormAsync();
    var file = form.Files["file"];
    if (file is null) return Results.BadRequest("Missing 'file'.");
    if (!form.TryGetValue("signature", out var sigB64)) return Results.BadRequest("Missing 'signature'.");
    if (!form.TryGetValue("certificate", out var certB64)) return Results.BadRequest("Missing 'certificate'.");
    form.TryGetValue("timestamp", out var tsrB64);

    byte[] signature, certificate;
    byte[]? timestamp = null;
    try
    {
        signature = Convert.FromBase64String(sigB64!);
        certificate = Convert.FromBase64String(certB64!);
        if (!string.IsNullOrEmpty(tsrB64)) timestamp = Convert.FromBase64String(tsrB64!);
    }
    catch (FormatException)
    {
        return Results.BadRequest("signature/certificate/timestamp must be base64.");
    }

    byte[] content = await ReadAllBytesAsync(file);
    var r = NotaryService.VerifyBytes(content, signature, certificate, timestamp);

    // 200 = trusted, 422 = anything else (tampered / unverifiable) so callers can branch on the code.
    var body = new VerifyResponse(r.Status.ToString(), r.Signer, r.Message, r.TimestampUtc, r.TimestampAuthority);
    return r.Status == VerificationStatus.Trusted
        ? Results.Ok(body)
        : Results.UnprocessableEntity(body);
});

app.Run();

static async Task<byte[]> ReadAllBytesAsync(IFormFile file)
{
    using var ms = new MemoryStream();
    await file.CopyToAsync(ms);
    return ms.ToArray();
}

internal sealed record SignResponse(string Signer, string Signature, string Certificate, string? Timestamp);
internal sealed record VerifyResponse(string Status, string? Signer, string Message, DateTimeOffset? TimestampUtc, string? TimestampAuthority);

/// <summary>Decides where the signing key lives, from environment configuration.</summary>
internal static class ProviderFactory
{
    public static ISigningProvider Build()
    {
        // 1) Azure Key Vault — the key never leaves the vault (Milestone 5).
        var vault = Environment.GetEnvironmentVariable("NOTARY_KEYVAULT_URI");
        if (!string.IsNullOrWhiteSpace(vault))
            return KeyVaultSigningProvider.Connect(
                new Uri(vault), Environment.GetEnvironmentVariable("NOTARY_KEYVAULT_CERT") ?? "notary");

        // 2) A local PFX mounted into the container/host.
        var keyPath = Environment.GetEnvironmentVariable("NOTARY_KEY_PATH");
        if (!string.IsNullOrWhiteSpace(keyPath) && File.Exists(keyPath))
            return LocalKeySigningProvider.LoadFromPfx(
                keyPath, Environment.GetEnvironmentVariable("NOTARY_KEY_PASS") ?? "changeit");

        // 3) Dev fallback: an ephemeral in-memory key, regenerated every start. Fine for the demo,
        //    never for production (sidecars won't verify after a restart).
        return LocalKeySigningProvider.Create("Personal Notary API (ephemeral dev key)");
    }
}

// Exposed so the integration tests can host the app with WebApplicationFactory<Program>.
public partial class Program { }
