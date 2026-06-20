using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace Notary.Tests;

/// <summary>
/// Milestone 6: the HTTP API. These host the real ASP.NET Core app in-process
/// (no ports, no Docker needed) and drive /sign and /verify over real HTTP.
/// </summary>
public class ApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    public ApiTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private sealed record SignDto(string Signer, string Signature, string Certificate, string? Timestamp);
    private sealed record VerifyDto(string Status, string? Signer, string Message, DateTimeOffset? TimestampUtc, string? TimestampAuthority);

    private static MultipartFormDataContent FileForm(byte[] content)
    {
        var form = new MultipartFormDataContent();
        var fileContent = new ByteArrayContent(content);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        form.Add(fileContent, "file", "doc.txt");
        return form;
    }

    [Fact]
    public async Task Sign_Then_Verify_Roundtrips_As_Trusted()
    {
        var client = _factory.CreateClient();
        byte[] doc = Encoding.UTF8.GetBytes("API-signed contract.");

        var signResp = await client.PostAsync("/sign", FileForm(doc));
        signResp.EnsureSuccessStatusCode();
        var signed = await signResp.Content.ReadFromJsonAsync<SignDto>();
        Assert.NotNull(signed);

        var verifyForm = FileForm(doc);
        verifyForm.Add(new StringContent(signed!.Signature), "signature");
        verifyForm.Add(new StringContent(signed.Certificate), "certificate");
        var verifyResp = await client.PostAsync("/verify", verifyForm);

        Assert.Equal(HttpStatusCode.OK, verifyResp.StatusCode);
        var verified = await verifyResp.Content.ReadFromJsonAsync<VerifyDto>();
        Assert.Equal("Trusted", verified!.Status);
    }

    [Fact]
    public async Task Verify_Detects_Tampering_With_422()
    {
        var client = _factory.CreateClient();
        byte[] doc = Encoding.UTF8.GetBytes("Pay Jose $100.");
        var signed = await (await client.PostAsync("/sign", FileForm(doc)))
            .Content.ReadFromJsonAsync<SignDto>();

        byte[] tampered = Encoding.UTF8.GetBytes("Pay Jose $9000.");
        var form = FileForm(tampered);                                  // same sidecars, altered file
        form.Add(new StringContent(signed!.Signature), "signature");
        form.Add(new StringContent(signed.Certificate), "certificate");
        var resp = await client.PostAsync("/verify", form);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, resp.StatusCode);
        var verified = await resp.Content.ReadFromJsonAsync<VerifyDto>();
        Assert.Equal("Tampered", verified!.Status);
    }

    [Fact]
    public async Task Sign_With_Timestamp_Returns_Tsr_And_Verify_Reports_When()
    {
        var client = _factory.CreateClient();
        byte[] doc = Encoding.UTF8.GetBytes("Timestamped via API.");

        var signForm = FileForm(doc);
        signForm.Add(new StringContent("true"), "timestamp");
        var signed = await (await client.PostAsync("/sign", signForm))
            .Content.ReadFromJsonAsync<SignDto>();
        Assert.NotNull(signed!.Timestamp);                              // .tsr came back

        var verifyForm = FileForm(doc);
        verifyForm.Add(new StringContent(signed.Signature), "signature");
        verifyForm.Add(new StringContent(signed.Certificate), "certificate");
        verifyForm.Add(new StringContent(signed.Timestamp!), "timestamp");
        var verified = await (await client.PostAsync("/verify", verifyForm))
            .Content.ReadFromJsonAsync<VerifyDto>();

        Assert.Equal("Trusted", verified!.Status);
        Assert.NotNull(verified.TimestampUtc);                          // proven "when"
    }
}
