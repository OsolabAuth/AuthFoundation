using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;

namespace AuthFoundationTest;

[TestClass]
public sealed class AuthorizeApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: GET /authorize 未ログイン正常系で認可セッションをRedisへ保存し、body modeではredirect_urlからsession_idを除去しCookieへ設定すること。
    /// </summary>
    [TestMethod]
    public async Task GetAuthorize_AnonymousUser_ReturnsLoginRedirectBodyAndStoresAuthRequestSession()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["x-auth-ui-session-mode"] = "body";
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={Code.InnerClient.OSOLAB_CLIENT_ID}"
            + "&redirect_uri=https%3A%2F%2Fportal.osolab-auth.jp%2Fcallback"
            + "&state=state-api-test"
            + "&scope=openid%20email%20profile"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();
        Assert.IsInstanceOfType<OkObjectResult>(result);

        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("redirect", body.Value<string>("result"));

        string sessionId = body.Value<string>("session_id") ?? string.Empty;
        Assert.AreEqual(Code.Session.LENGTH, sessionId.Length);
        StringAssert.StartsWith(body.Value<string>("redirect_url"), $"{AppConfig.AuthUiBaseUrl}/login");
        Assert.IsFalse(body.Value<string>("redirect_url")!.Contains("session_id=", StringComparison.OrdinalIgnoreCase));
        Assert.AreEqual(sessionId, ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, Code.AUTH_REQUEST_SESSION_COOKIE_KEY));
        Assert.AreEqual(sessionId, ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, "session_id"));

        string? stored = await redis.GetStringAsync(AuthRequestSession.GetRedisKey(sessionId));
        Assert.IsFalse(string.IsNullOrWhiteSpace(stored));

        var saved = new AuthRequestSession();
        Assert.IsTrue(saved.SetValue(stored!));
        Assert.AreEqual(Code.InnerClient.OSOLAB_CLIENT_ID, saved.ClientId);
        Assert.AreEqual("openid email profile", saved.Scope);
    }

    /// <summary>
    /// 検証項目: GET /authorize の未登録client_idで設計書どおり00002を返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetAuthorize_InvalidClient_ReturnsRequestError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + "&client_id=99999999999999999999999999999999"
            + "&redirect_uri=https%3A%2F%2Fportal.osolab-auth.jp%2Fcallback"
            + "&state=state-api-test"
            + "&scope=openid"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();
        Assert.IsInstanceOfType<ObjectResult>(result);

        var objectResult = (ObjectResult)result;
        Assert.AreEqual((int)Code.ILLEGAL_CLIENT.Status, objectResult.StatusCode);

        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.ILLEGAL_CLIENT.Code, body.Value<string>("response_code"));
    }

    /// <summary>
    /// 検証項目: GET /authorize の未登録redirect_uriで設計書どおり00005を返し、未登録URIへリダイレクトしないこと。
    /// </summary>
    [TestMethod]
    public async Task GetAuthorize_UnregisteredRedirectUri_ReturnsIllegalRedirectUri()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={Code.InnerClient.OSOLAB_CLIENT_ID}"
            + "&redirect_uri=https%3A%2F%2Fevil.example.com%2Fcallback"
            + "&state=state-api-test"
            + "&scope=openid"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();

        ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_REDIRECT_URI.Status, Code.ILLEGAL_REDIRECT_URI.Code);
        Assert.IsTrue(string.IsNullOrWhiteSpace(httpContext.Response.Headers.Location));
    }

    /// <summary>
    /// 検証項目: GET /authorize の形式不正なredirect_uriで00005を返し、指定URIへリダイレクトしないこと。
    /// </summary>
    [TestMethod]
    public async Task GetAuthorize_InvalidRedirectUriFormat_ReturnsIllegalRedirectUri()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={Code.InnerClient.OSOLAB_CLIENT_ID}"
            + "&redirect_uri=http%3A%2F%2Fevil.example.com%2Fcallback"
            + "&state=state-api-test"
            + "&scope=openid"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();

        ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_REDIRECT_URI.Status, Code.ILLEGAL_REDIRECT_URI.Code);
        Assert.IsTrue(string.IsNullOrWhiteSpace(httpContext.Response.Headers.Location));
    }

    /// <summary>
    /// 検証項目: GET /authorize で要求scopeがクライアント必須scopeを満たさない場合に設計書どおり00009を返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetAuthorize_MissingRequiredScope_ReturnsInvalidScope()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId, "secret", "https://portal.osolab-auth.jp/callback", Code.Scope.OPENID);

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={clientId}"
            + "&redirect_uri=https%3A%2F%2Fportal.osolab-auth.jp%2Fcallback"
            + "&state=state-api-test"
            + "&scope=email"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();

        ControllerTestHelper.AssertError(result, (int)Code.INVALID_SCOPE.Status, Code.INVALID_SCOPE.Code);
    }

    /// <summary>
    /// 検証項目: GET /authorize ログイン済みかつscope同意済みの場合、認可コードを発行してredirect_uriへリダイレクトすること。
    /// </summary>
    [TestMethod]
    public async Task GetAuthorize_LoggedInAndConsented_RedirectsWithAuthorizationCode()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"authorize-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateClientAsync(context, clientId, "secret", redirectUri, Code.Scope.OPENID, Code.Scope.EMAIL);
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());
        await ApiTestData.AddScopeConsentsAsync(context, osolabId, clientId, Code.Scope.OPENID, Code.Scope.EMAIL);

        var redis = new FakeRedisClient();
        string loginSessionId = await ApiTestData.WriteLoginSessionAsync(redis, osolabId, email, clientId);
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, loginSessionId);
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={clientId}"
            + "&redirect_uri=https%3A%2F%2Fportal.osolab-auth.jp%2Fcallback"
            + "&state=state-api-test"
            + "&scope=openid%20email"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();

        Assert.IsInstanceOfType<RedirectResult>(result);
        string url = ((RedirectResult)result).Url!;
        StringAssert.StartsWith(url, $"{redirectUri}?code=");
        StringAssert.Contains(url, "state=state-api-test");

        string code = ExtractQueryValue(url, "code");
        string? rawCodeSession = await redis.GetStringAsync(AuthCodeSession.GetRedisKey(code), Code.RedisDbNo.AUTHORIZATION_CODE);
        Assert.IsFalse(string.IsNullOrWhiteSpace(rawCodeSession));

        var codeSession = new AuthCodeSession();
        Assert.IsTrue(codeSession.SetValue(rawCodeSession!));
        Assert.AreEqual(osolabId, codeSession.OsolabId);
        Assert.AreEqual(clientId, codeSession.ClientId);
    }

    private static string ExtractQueryValue(string url, string key)
    {
        Uri uri = new Uri(url);
        string query = uri.Query.TrimStart('?');
        foreach (string part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair = part.Split('=', 2);
            if (pair.Length == 2 && string.Equals(pair[0], key, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[1]);
            }
        }

        Assert.Fail($"Query '{key}' was not found.");
        return string.Empty;
    }
}

