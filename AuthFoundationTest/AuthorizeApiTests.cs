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
    /// 　リクエスト：Get Authorize を Anonymous User 条件で実行
    /// 期待値
    /// 　Returns Login Redirect Body And Stores Auth Request Session を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetAuthorize_AnonymousUser_ReturnsLoginRedirectBodyAndStoresAuthRequestSession()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["x-auth-ui-response-mode"] = "json";
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
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());

        Assert.IsNull(body["session_id"]);
        string sessionId = ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, Code.AUTH_REQUEST_SESSION_COOKIE_KEY);
        Assert.AreEqual(Code.Session.LENGTH, sessionId.Length);
        StringAssert.StartsWith(body.Value<string>("redirect_url"), $"{AppConfig.AuthUiBaseUrl}/login");
        Assert.IsFalse(body.Value<string>("redirect_url")!.Contains("session_id=", StringComparison.OrdinalIgnoreCase));
        Assert.AreEqual(sessionId, ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, "session_id"));

        string? stored = await redis.GetStringAsync(AuthRequestSession.GetRedisKey(sessionId));
        Assert.IsFalse(string.IsNullOrWhiteSpace(stored));

        var saved = new AuthRequestSession();
        Assert.IsTrue(saved.SetValue(stored!));
        Assert.AreEqual(Code.InnerClient.OSOLAB_CLIENT_ID, saved.ClientId);
        Assert.AreEqual("openid email profile", saved.Scope);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Authorize を Invalid Client 条件で実行
    /// 期待値
    /// 　Returns Request Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
        Assert.AreEqual("unauthorized_client", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Authorize を Unregistered Redirect Uri 条件で実行
    /// 期待値
    /// 　Returns Illegal Redirect Uri を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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

        var body = ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_REDIRECT_URI.Status, Code.ILLEGAL_REDIRECT_URI.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        Assert.IsTrue(string.IsNullOrWhiteSpace(httpContext.Response.Headers.Location));
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Authorize を Invalid Redirect Uri Format 条件で実行
    /// 期待値
    /// 　Returns Illegal Redirect Uri を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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

        var body = ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_REDIRECT_URI.Status, Code.ILLEGAL_REDIRECT_URI.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        Assert.IsTrue(string.IsNullOrWhiteSpace(httpContext.Response.Headers.Location));
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Authorize を Redirect Uri With Fragment 条件で実行
    /// 期待値
    /// 　Returns Illegal Redirect Uri を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetAuthorize_RedirectUriWithFragment_ReturnsIllegalRedirectUri()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        await ApiTestData.CreateClientAsync(context, clientId, redirectUri: redirectUri);

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={clientId}"
            + "&redirect_uri=https%3A%2F%2Fportal.osolab-auth.jp%2Fcallback%23fragment"
            + "&state=state-api-test"
            + "&scope=openid"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();

        var body = ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_REDIRECT_URI.Status, Code.ILLEGAL_REDIRECT_URI.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Authorize を Localhost Http Redirect Uri When Registered 条件で実行
    /// 期待値
    /// 　Is Accepted を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetAuthorize_LocalhostHttpRedirectUri_WhenRegistered_IsAccepted()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "http://localhost:5173/callback";
        await ApiTestData.CreateClientAsync(context, clientId, redirectUri: redirectUri);

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["x-auth-ui-response-mode"] = "json";
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={clientId}"
            + "&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback"
            + "&state=state-api-test"
            + "&scope=openid"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("redirect", body.Value<string>("result"));
        StringAssert.StartsWith(body.Value<string>("redirect_url"), $"{AppConfig.AuthUiBaseUrl}/login");
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Authorize を Missing Required Scope 条件で実行
    /// 期待値
    /// 　Returns Invalid Scope を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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

        var body = ControllerTestHelper.AssertError(result, (int)Code.INVALID_SCOPE.Status, Code.INVALID_SCOPE.Code);
        Assert.AreEqual("invalid_scope", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Authorize を Logged In And Consented 条件で実行
    /// 期待値
    /// 　Redirects With Authorization Code を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());

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

