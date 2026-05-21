using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class LogoutApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: LogoutController のクラスルートは 1 つ（logout）で曖昧マッチの原因となる重複定義を持たないこと。
    /// </summary>
    [TestMethod]
    public void LogoutController_ClassRoute_IsSingleLogoutTemplate()
    {
        var routeAttributes = typeof(LogoutController)
            .GetCustomAttributes(typeof(IRouteTemplateProvider), inherit: false)
            .Cast<IRouteTemplateProvider>()
            .Where(x => !string.IsNullOrWhiteSpace(x.Template))
            .ToList();

        Assert.AreEqual(1, routeAttributes.Count);
        Assert.AreEqual("logout", routeAttributes[0].Template);
    }

    /// <summary>
    /// 検証項目: POST /logout 正常系でAuthSession CookieとRedisセッションを削除し、指定Bearer Access Tokenを失効すること。
    /// </summary>
    [TestMethod]
    public async Task PostLogout_LoggedInSession_DeletesCookiesAndRedisSessions()
    {
        var redis = new FakeRedisClient();
        string osolabId = ApiTestData.NewOsolabId();
        string clientId = Code.InnerClient.OSOLAB_CLIENT_ID;
        string loginSessionId = await ApiTestData.WriteLoginSessionAsync(redis, osolabId, "logout@example.com", clientId);
        string accessToken = $"{osolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";
        await new AccessTokenSession
        {
            AccessToken = accessToken,
            OsolabId = osolabId,
            ClientId = clientId,
            Scope = "openid"
        }.WriteToRedisAsync(redis);

        var controller = new LogoutController(redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["logout_all"] = "false"
        });
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, loginSessionId);
        httpContext.Request.Headers.Authorization = $"Bearer {accessToken}";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostLogout();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("logged_out", body.Value<string>("result"));
        Assert.IsNull(await redis.GetStringAsync(AuthSession.GetRedisKey(loginSessionId)));
        Assert.IsNull(await redis.GetStringAsync(AccessTokenSession.GetRedisKey(accessToken), Code.RedisDbNo.ACCESS_TOKEN));
        string setCookie = string.Join("\n", httpContext.Response.Headers.SetCookie.ToArray());
        StringAssert.Contains(setCookie, $"{Code.AUTH_SESSION_COOKIE_KEY}=");
        StringAssert.Contains(setCookie, "session_id=");
    }

    /// <summary>
    /// 検証項目: ログインセッションが存在しない場合も200でalready_logged_outを返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostLogout_NoLoginSession_ReturnsAlreadyLoggedOut()
    {
        var controller = new LogoutController(new FakeRedisClient());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["logout_all"] = "true"
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostLogout();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("already_logged_out", body.Value<string>("result"));
        Assert.AreEqual(true, body.Value<bool>("logout_all"));
    }

    /// <summary>
    /// 検証項目: Content-Type不正時に設計書どおり00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostLogout_InvalidContentType_ReturnsRequestParameterError()
    {
        var controller = new LogoutController(new FakeRedisClient());
        var httpContext = new DefaultHttpContext();
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostLogout();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    /// <summary>
    /// 検証項目: logout_all未指定時に設計書どおり00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostLogout_MissingLogoutAll_ReturnsRequestParameterError()
    {
        var controller = new LogoutController(new FakeRedisClient());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostLogout();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }
}
