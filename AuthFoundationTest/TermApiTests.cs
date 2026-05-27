using AuthFoundation.Common;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;
using AuthTermController = AuthFoundation.Controllers.Auth.TermController;

namespace AuthFoundationTest;

[TestClass]
[DoNotParallelize]
public sealed class TermApiTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テスト実行前の初期データを投入可能
    /// 　リクエスト：なし（テスト初期化処理）
    /// 期待値
    /// 　共通設定とテスト実行環境が初期化される
    /// </summary>
    /// <returns></returns>
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Terms List を Valid Cookie Session 条件で実行
    /// 期待値
    /// 　Returns Terms And Scopes を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostTermsList_ValidCookieSession_ReturnsTermsAndScopes()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);
        await ApiTestData.DeactivateGeneratedInnerTermsAsync(context);

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
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_REQUEST_SESSION_COOKIE_KEY, sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTermsList();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(clientId, body.Value<string>("client_id"));
        CollectionAssert.Contains(GetTermIds(body), termId);
        CollectionAssert.AreEqual(new[] { "openid", "email" }, body["scopes"]!.Values<string>().ToArray());
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Terms List を 標準入力 条件で実行
    /// 期待値
    /// 　Prefers Auth Request Cookie Over Compatibility Session Id を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostTermsList_PrefersAuthRequestCookieOverCompatibilitySessionId()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string termId = $"term-{Guid.NewGuid():N}"[..32];
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateRequiredTermAsync(context, clientId, termId);

        var redis = new FakeRedisClient();
        string authRequestSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(authRequestSessionId, clientId, "https://portal.osolab-auth.jp/callback", "openid email"));

        var controller = CreateController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_REQUEST_SESSION_COOKIE_KEY, authRequestSessionId);
        ControllerTestHelper.SetCookie(httpContext, "session_id", Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant());
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTermsList();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(clientId, body.Value<string>("client_id"));
        CollectionAssert.Contains(GetTermIds(body), termId);
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：通常クライアントの規約と内部クライアント共通規約を事前投入済み
    /// 　リクエスト：Post Terms List を通常クライアントのセッションで実行
    /// 期待値
    /// 　通常クライアント規約と内部クライアント共通規約の両方が返却される
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostTermsList_ClientSession_IncludesInnerClientTerms()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);
        await ApiTestData.DeactivateGeneratedInnerTermsAsync(context);

        string clientId = ApiTestData.NewClientId();
        string clientTermId = $"term-{Guid.NewGuid():N}"[..32];
        string commonTermId = $"term-{Guid.NewGuid():N}"[..32];
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateRequiredTermAsync(context, clientId, clientTermId);
        await ApiTestData.CreateRequiredTermAsync(context, Code.InnerClient.OSOLAB_CLIENT_ID, commonTermId);

        var redis = new FakeRedisClient();
        string sessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(sessionId, clientId, "https://portal.osolab-auth.jp/callback", "openid email"));

        var controller = CreateController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_REQUEST_SESSION_COOKIE_KEY, sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTermsList();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        string[] termIds = GetTermIds(body);
        CollectionAssert.Contains(termIds, clientTermId);
        CollectionAssert.Contains(termIds, commonTermId);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Terms List を Expired Session 条件で実行
    /// 期待値
    /// 　Returns Screen Expired を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostTermsList_ExpiredSession_ReturnsScreenExpired()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = CreateController(context, new FakeRedisClient());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_REQUEST_SESSION_COOKIE_KEY, Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant());
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTermsList();

        JObject body = ControllerTestHelper.AssertError(result, (int)Code.SCREEN_EXPIRED.Status, Code.SCREEN_EXPIRED.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Terms を Denied 条件で実行
    /// 期待値
    /// 　Returns Access Denied Redirect を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostTerms_Denied_ReturnsAccessDeniedRedirect()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);
        await ApiTestData.DeactivateGeneratedInnerTermsAsync(context);

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
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_REQUEST_SESSION_COOKIE_KEY, sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTerms();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual("redirect", body.Value<string>("result"));
        Assert.AreEqual("access_denied", body.Value<string>("error"));
        StringAssert.StartsWith(httpContext.Response.Headers.Location.ToString(), $"{redirectUri}?error=access_denied");
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Terms を Accepts Required Term 条件で実行
    /// 期待値
    /// 　Saves Consent And Redirects With Code を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostTerms_AcceptsRequiredTerm_SavesConsentAndRedirectsWithCode()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);
        await ApiTestData.DeactivateGeneratedInnerTermsAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        string termId = $"term-{Guid.NewGuid():N}"[..32];
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"term-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateClientAsync(context, clientId, redirectUri: redirectUri);
        await ApiTestData.CreateRequiredTermAsync(context, clientId, termId);
        string commonTermId = $"term-{Guid.NewGuid():N}"[..32];
        await ApiTestData.CreateRequiredTermAsync(context, Code.InnerClient.OSOLAB_CLIENT_ID, commonTermId);
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(authzSessionId, clientId, redirectUri, "openid email", osolabId));
        string loginSessionId = await ApiTestData.WriteLoginSessionAsync(redis, osolabId, email, clientId);
        string[] acceptedTermIds = await context.client_terms
            .Where(x => (x.client_id == clientId || x.client_id == Code.InnerClient.OSOLAB_CLIENT_ID)
                && x.status == Code.Status.ACTIVE
                && x.required == Code.Status.ACTIVE)
            .Select(x => x.term_id)
            .ToArrayAsync();
        CollectionAssert.Contains(acceptedTermIds, termId);
        CollectionAssert.Contains(acceptedTermIds, commonTermId);

        var controller = CreateController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, IEnumerable<string>>
        {
            ["accepted"] = new[] { "true" },
            ["term_ids"] = acceptedTermIds
        });
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_REQUEST_SESSION_COOKIE_KEY, authzSessionId);
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, loginSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTerms();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual("redirect", body.Value<string>("result"));
        var requiredTermsAfterConsent = await context.client_terms
            .Where(x => (x.client_id == clientId || x.client_id == Code.InnerClient.OSOLAB_CLIENT_ID)
                && x.status == Code.Status.ACTIVE
                && x.required == Code.Status.ACTIVE)
            .Select(x => new { x.client_id, x.term_id, x.term_version })
            .ToListAsync();
        var consentsAfterConsent = await context.user_term_consents
            .Where(x => x.osolab_id == osolabId && x.consent_result == Code.Status.ACTIVE)
            .Select(x => new { x.client_id, x.term_id, x.term_version })
            .ToListAsync();
        string[] missingTermsAfterConsent = requiredTermsAfterConsent
            .Where(term => !consentsAfterConsent.Any(consent =>
                consent.client_id == term.client_id
                && consent.term_id == term.term_id
                && consent.term_version == term.term_version))
            .Select(x => $"{x.client_id}:{x.term_id}:{x.term_version}")
            .ToArray();
        Assert.AreEqual(0, missingTermsAfterConsent.Length, string.Join(", ", missingTermsAfterConsent));
        StringAssert.StartsWith(httpContext.Response.Headers.Location.ToString(), $"{redirectUri}?code=");
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        Assert.IsTrue(await context.user_term_consents.AnyAsync(x =>
            x.osolab_id == osolabId
            && x.client_id == clientId
            && x.term_id == termId
            && x.consent_result == Code.Status.ACTIVE));
        Assert.IsTrue(await context.user_term_consents.AnyAsync(x =>
            x.osolab_id == osolabId
            && x.client_id == Code.InnerClient.OSOLAB_CLIENT_ID
            && x.term_id == commonTermId
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Terms を Missing Accepted 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostTerms_MissingAccepted_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = CreateController(context, new FakeRedisClient());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_REQUEST_SESSION_COOKIE_KEY, Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant());
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTerms();

        JObject body = ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    private static AuthTermController CreateController(AuthFoundation.Data.OsolabAuthContext context, FakeRedisClient redis)
    {
        return new AuthTermController(
            context,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
    }

    private static string[] GetTermIds(JObject body)
    {
        return body["terms"]!.Select(x => x.Value<string>("term_id")!).ToArray();
    }
}

