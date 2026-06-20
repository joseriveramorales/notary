using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace Notary.Core;

/// <summary>
/// Talks to a real RFC 3161 Time-Stamp Authority over HTTP (e.g.
/// <c>http://timestamp.digicert.com</c>). Same <see cref="ITimestampAuthority"/> contract as the
/// local one — only the implementation changes, exactly the seam this project is built around.
///
/// We send a DER timestamp REQUEST (Content-Type application/timestamp-query) and the server
/// returns a DER timestamp RESPONSE; we keep just the embedded token to persist as the .tsr.
/// </summary>
public sealed class HttpTimestampAuthority : ITimestampAuthority, IDisposable
{
    private readonly Uri _tsaUrl;
    private readonly HttpClient _http;

    public HttpTimestampAuthority(string tsaUrl, HttpClient? http = null)
    {
        _tsaUrl = new Uri(tsaUrl);
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public byte[] RequestToken(byte[] sha256Hash)
    {
        var request = Rfc3161TimestampRequest.CreateFromHash(
            sha256Hash, HashAlgorithmName.SHA256, requestSignerCertificates: true);

        using var content = new ByteArrayContent(request.Encode());
        content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");

        using var resp = _http.PostAsync(_tsaUrl, content).GetAwaiter().GetResult();
        resp.EnsureSuccessStatusCode();
        byte[] replyBytes = resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();

        // Parse the TimeStampResp, validate it answers our request, and keep the token bytes.
        Rfc3161TimestampToken token = request.ProcessResponse(replyBytes, out _);
        return token.AsSignedCms().Encode();
    }

    public void Dispose() => _http.Dispose();
}
