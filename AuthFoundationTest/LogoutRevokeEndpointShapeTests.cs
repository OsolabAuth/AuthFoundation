using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using Microsoft.Extensions.Primitives;

namespace AuthFoundationTest;

[TestClass]
public sealed class LogoutRevokeEndpointShapeTests
{
    /// <summary>
    /// 逶ｮ逧・ Logout / Returns Logged Out And Deletes Request Cookie 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Logout / Returns Logged Out And Deletes Request Cookie 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Logout / Returns Logged Out And Deletes Request Cookie 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
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
    /// 逶ｮ逧・ Revoke / Returns Revoked For Known Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 蟇ｾ雎｡繧貞､ｱ蜉ｹ縺励∝､ｱ蜉ｹ蠕鯉ｿｽE蛻ｩ逕ｨ繧呈拠蜷ｦ縺吶ｋ縺薙→縲・
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
    /// 逶ｮ逧・ Revoke / Returns Bad Request For Missing Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
