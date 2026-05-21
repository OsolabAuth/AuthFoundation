using AuthFoundation.Common;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;
using AuthTermController = AuthFoundation.Controllers.Auth.TermController;

namespace AuthFoundationTest;

[TestClass]
public sealed class TermApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: POST /terms/list がCookieのsession_idから認可セッションを取得し、対象クライアントの規約とscopeを返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostTermsList_ValidCookieSession_ReturnsTermsAndScopes()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string termId = $"term-{Guid.NewGuid():N}"[..32];
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateRequiredTermAsync(context, clientId, termId);

        var redis = new FakeRedisClient();
        string sessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(sessionId, clientId, "https://portal.osolab-auth.jp/callback", "openid email"));

        var controller = CreateController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        ControllerTestHelper.SetCookie(httpContext, "session_id", sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTermsList();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(clientId, body.Value<string>("client_id"));
        Assert.AreEqual(termId, body["terms"]!.First!.Value<string>("term_id"));
        CollectionAssert.AreEqual(new[] { "openid", "email" }, body["scopes"]!.Values<string>().ToArray());
    }

    /// <summary>
    /// 検証項目: POST /terms/list の認可セッション期限切れ時に設計書どおり00003を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostTermsList_ExpiredSession_ReturnsScreenExpired()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = CreateController(context, new FakeRedisClient());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        ControllerTestHelper.SetCookie(httpContext, "session_id", Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant());
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTermsList();

        ControllerTestHelper.AssertError(result, (int)Code.SCREEN_EXPIRED.Status, Code.SCREEN_EXPIRED.Code);
    }

    /// <summary>
    /// 検証項目: POST /terms でaccepted=falseの場合、同意を保存せずredirect_uriへaccess_deniedを返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostTerms_Denied_ReturnsAccessDeniedRedirect()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        await ApiTestData.CreateClientAsync(context, clientId, redirectUri: redirectUri);

        var redis = new FakeRedisClient();
        string sessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(sessionId, clientId, redirectUri, "openid", ApiTestData.NewOsolabId()));

        var controller = CreateController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["accepted"] = "false"
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTerms();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual("redirect", body.Value<string>("result"));
        Assert.AreEqual("access_denied", body.Value<string>("error"));
        StringAssert.StartsWith(httpContext.Response.Headers.Location.ToString(), $"{redirectUri}?error=access_denied");
    }

    /// <summary>
    /// 検証項目: POST /terms 同意正常系で必須規約とscope同意をDBに保存し、認可コード付きLocationを返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostTerms_AcceptsRequiredTerm_SavesConsentAndRedirectsWithCode()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        string termId = $"term-{Guid.NewGuid():N}"[..32];
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"term-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateClientAsync(context, clientId, redirectUri: redirectUri);
        await ApiTestData.CreateRequiredTermAsync(context, clientId, termId);
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(authzSessionId, clientId, redirectUri, "openid email", osolabId));
        string loginSessionId = await ApiTestData.WriteLoginSessionAsync(redis, osolabId, email, clientId);

        var controller = CreateController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, IEnumerable<string>>
        {
            ["accepted"] = new[] { "true" },
            ["term_ids"] = new[] { termId }
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", authzSessionId);
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, loginSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTerms();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual("redirect", body.Value<string>("result"));
        StringAssert.StartsWith(httpContext.Response.Headers.Location.ToString(), $"{redirectUri}?code=");
        Assert.IsTrue(await context.user_term_consents.AnyAsync(x =>
            x.osolab_id == osolabId
            && x.client_id == clientId
            && x.term_id == termId
            && x.consent_result == Code.Status.ACTIVE));
        Assert.IsTrue(await context.user_client_scope_consents.AnyAsync(x =>
            x.osolab_id == osolabId
            && x.client_id == clientId
            && x.scope == "openid"
            && x.status == Code.Status.ACTIVE));

        string? authRequestSession = await redis.GetStringAsync(AuthRequestSession.GetRedisKey(authzSessionId));
        Assert.IsTrue(string.IsNullOrWhiteSpace(authRequestSession));
    }

    /// <summary>
    /// 検証項目: accepted未指定時に設計書どおり00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostTerms_MissingAccepted_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = CreateController(context, new FakeRedisClient());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        ControllerTestHelper.SetCookie(httpContext, "session_id", Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant());
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTerms();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    private static AuthTermController CreateController(AuthFoundation.Data.OsolabAuthContext context, FakeRedisClient redis)
    {
        return new AuthTermController(
            context,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
    }
}

