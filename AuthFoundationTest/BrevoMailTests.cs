using System.Net;
using AuthFoundationTest.TestSupport;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace AuthFoundationTest;

[TestClass]
public sealed class BrevoMailTests
{
    /// <summary>
    /// 検証項目: Brevo API送信正常系でapi-keyヘッダーとJSON bodyを付けてメール送信APIを呼び出すこと。
    /// </summary>
    [TestMethod]
    public async Task SendMailAsync_BrevoApiSuccess_SendsApiRequest()
    {
        var handler = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK));
        var mail = CreateBrevoMail(handler);

        await mail.SendMailAsync("to@example.com", "To User", "Subject", "<p>Hello</p>");

        Assert.IsNotNull(handler.LastRequest);
        Assert.AreEqual(HttpMethod.Post, handler.LastRequest.Method);
        Assert.AreEqual("https://api.brevo.com/v3/smtp/email", handler.LastRequest.RequestUri!.ToString());
        Assert.AreEqual("test-api-key", handler.LastRequest.Headers.GetValues("api-key").Single());
        string body = await handler.LastRequest.Content!.ReadAsStringAsync();
        StringAssert.Contains(body, "to@example.com");
        StringAssert.Contains(body, "Subject");
    }

    /// <summary>
    /// 検証項目: Brevo APIが失敗した場合、レスポンス本文を含むHttpRequestExceptionを送出すること。
    /// </summary>
    [TestMethod]
    public async Task SendMailAsync_BrevoApiFailure_ThrowsHttpRequestException()
    {
        var handler = new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("{\"message\":\"invalid\"}")
        });
        var mail = CreateBrevoMail(handler);

        HttpRequestException ex = await Assert.ThrowsExactlyAsync<HttpRequestException>(() =>
            mail.SendMailAsync("to@example.com", "To User", "Subject", "<p>Hello</p>"));

        StringAssert.Contains(ex.Message, "Brevo API error");
        StringAssert.Contains(ex.Message, "invalid");
    }

    /// <summary>
    /// 検証項目: SMTP設定不足時にネットワーク送信せずInvalidOperationExceptionを送出すること。
    /// </summary>
    [TestMethod]
    public async Task SendMailAsync_SmtpMissingConfiguration_ThrowsInvalidOperationException()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:Provider"] = "Smtp"
            })
            .Build();
        var mail = new BrevoMail(new HttpClient(new StubHttpMessageHandler(new HttpResponseMessage(HttpStatusCode.OK))), config, NullLogger<BrevoMail>.Instance);

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() =>
            mail.SendMailAsync("to@example.com", "To User", "Subject", "<p>Hello</p>"));

        StringAssert.Contains(ex.Message, "SMTP configuration is incomplete");
    }

    private static BrevoMail CreateBrevoMail(StubHttpMessageHandler handler)
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:Provider"] = "BrevoApi",
                ["Brevo:ApiKey"] = "test-api-key",
                ["Mail:FromEmail"] = "from@example.com",
                ["Mail:FromName"] = "From User"
            })
            .Build();

        return new BrevoMail(new HttpClient(handler), config, NullLogger<BrevoMail>.Instance);
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public HttpRequestMessage? LastRequest { get; private set; }

        public StubHttpMessageHandler(HttpResponseMessage response)
        {
            _response = response;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(_response);
        }
    }
}
