using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using Microsoft.Extensions.Primitives;

namespace AuthFoundationTest;

[TestClass]
public sealed class LogoutRevokeEndpointShapeTests
{
    [TestMethod]
    public void Logout_ReturnsLoggedOutAndDeletesRequestCookie()
    {
        var controller = EndpointTestHelper.WithHttpContext(new LogoutController(new AuditLogService()));

        var ok = EndpointTestHelper.AssertOk(controller.Post());

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("logged_out", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.IsTrue(controller.Response.Headers.SetCookie.ToString().Contains("AuthRequestId=", StringComparison.Ordinal));
    }

    [TestMethod]
    public async Task Revoke_ReturnsRevokedForKnownToken()
    {
        var store = new InMemoryOidcStore();
        var controller = EndpointTestHelper.WithHttpContext(new RevokeController(store, new AuditLogService()));
        AccessTokenRecord token = CreateAccessToken(store);
        EndpointTestHelper.SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["token"] = token.AccessToken
        });

        var ok = EndpointTestHelper.AssertOk(await controller.Post());

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("revoked", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.ThrowsExactly<ApiException>(() => store.FindAccessToken(token.AccessToken));
    }

    [TestMethod]
    public async Task Revoke_ReturnsBadRequestForMissingToken()
    {
        var controller = EndpointTestHelper.WithHttpContext(new RevokeController(new InMemoryOidcStore(), new AuditLogService()));
        EndpointTestHelper.SetForm(controller.HttpContext, new Dictionary<string, StringValues>());

        ErrorOutput error = EndpointTestHelper.AssertError(await controller.Post(), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("token is required", error.ErrorDescription);
    }

    private static AccessTokenRecord CreateAccessToken(InMemoryOidcStore store)
    {
        return store.CreateAccessToken(new AuthorizationCodeRecord(
            "code",
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "nonce",
            "challenge",
            "subject_1",
            "subject@example.com",
            "Subject One",
            DateTimeOffset.UtcNow.AddMinutes(5)));
    }
}
