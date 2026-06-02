using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using Microsoft.Extensions.Primitives;

namespace AuthFoundationTest;

[TestClass]
public sealed class LogoutRevokeEndpointShapeTests
{
    /// <summary>
    /// 目的: Logout / Returns Logged Out And Deletes Request Cookie の仕様を検証する。
    /// 入力値: Logout / Returns Logged Out And Deletes Request Cookie を確認するためにテスト内で作成したデータ。
    /// 期待値: Logout / Returns Logged Out And Deletes Request Cookie の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Logout_ReturnsLoggedOutAndDeletesRequestCookie()
    {
        var controller = EndpointTestHelper.WithHttpContext(new LogoutController());

        var ok = EndpointTestHelper.AssertOk(controller.Post());

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("logged_out", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.IsTrue(controller.Response.Headers.SetCookie.ToString().Contains("AuthRequestId=", StringComparison.Ordinal));
    }

    /// <summary>
    /// 目的: Revoke / Returns Revoked For Known Token の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: 対象を失効し、失効後の利用を拒否すること。
    /// </summary>
    [TestMethod]
    public async Task Revoke_ReturnsRevokedForKnownToken()
    {
        var store = new InMemoryOidcStore();
        var controller = EndpointTestHelper.WithHttpContext(new RevokeController(store));
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

    /// <summary>
    /// 目的: Revoke / Returns Bad Request For Missing Token の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task Revoke_ReturnsBadRequestForMissingToken()
    {
        var controller = EndpointTestHelper.WithHttpContext(new RevokeController(new InMemoryOidcStore()));
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
