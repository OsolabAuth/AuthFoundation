using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Models;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;

namespace AuthFoundationTest;

[TestClass]
public sealed class AuthFlowSmokeTests
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
    /// 　リクエスト：End To End を Login Token User Info Logout 条件で実行
    /// 期待値
    /// 　Completes Successfully を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task EndToEnd_LoginTokenUserInfoLogout_CompletesSuccessfully()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        string state = "state-smoke-test";
        string verifier = new string('v', 64);
        string challenge = ApiTestData.CodeChallengeFor(verifier);
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"smoke-{Guid.NewGuid():N}@example.com";
        string password = "Password123";

        await ApiTestData.CreateClientAsync(
            context,
            clientId,
            clientSecret: "smoke-secret",
            redirectUri: redirectUri,
            Code.Scope.OPENID,
            Code.Scope.EMAIL);
        await ApiTestData.CreateUserAsync(context, osolabId, email, password);
        await ApiTestData.AddScopeConsentsAsync(context, osolabId, clientId, Code.Scope.OPENID, Code.Scope.EMAIL);
        await AddRequiredTermConsentsAsync(context, osolabId, clientId);

        var redis = new FakeRedisClient();
        var authorizeService = new AuthorizeExecutionService(context, redis);

        string authRequestSessionId = await ExecuteAuthorizeAsync(
            context,
            authorizeService,
            clientId,
            redirectUri,
            state,
            challenge);

        (string authSessionId, string code) = await ExecuteLoginAsync(
            context,
            redis,
            authorizeService,
            email,
            password,
            authRequestSessionId,
            redirectUri);

        string accessToken = await ExecuteTokenAsync(context, redis, clientId, redirectUri, code, verifier);

        await ExecuteUserInfoAsync(context, redis, accessToken, osolabId, email);

        await ExecuteLogoutAsync(redis, authSessionId, accessToken);

        Assert.IsNull(await redis.GetStringAsync(AccessTokenSession.GetRedisKey(accessToken), Code.RedisDbNo.ACCESS_TOKEN));
        Assert.IsNull(await redis.GetStringAsync(AuthSession.GetRedisKey(authSessionId), Code.RedisDbNo.AUTH_SESSION));
    }

    private static async Task<string> ExecuteAuthorizeAsync(
        AuthFoundation.Data.OsolabAuthContext context,
        AuthorizeExecutionService authorizeService,
        string clientId,
        string redirectUri,
        string state,
        string challenge)
    {
        var controller = new AuthorizeController(context, authorizeService);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["x-auth-ui-response-mode"] = "json";
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={clientId}"
            + $"&redirect_uri={Uri.EscapeDataString(redirectUri)}"
            + $"&state={Uri.EscapeDataString(state)}"
            + "&scope=openid%20email"
            + "&code_challenge_method=S256"
            + $"&code_challenge={Uri.EscapeDataString(challenge)}"
            + "&nonce=nonce-smoke-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();
        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual("redirect", body.Value<string>("result"));

        Assert.IsNull(body["session_id"]);
        string authRequestSessionId = ControllerTestHelper.ExtractCookieValue(
            httpContext.Response.Headers,
            Code.AUTH_REQUEST_SESSION_COOKIE_KEY);
        Assert.AreEqual(Code.Session.LENGTH, authRequestSessionId.Length);
        StringAssert.StartsWith(body.Value<string>("redirect_url"), $"{AppConfig.AuthUiBaseUrl}/login");
        return authRequestSessionId;
    }

    private static async Task<(string AuthSessionId, string Code)> ExecuteLoginAsync(
        AuthFoundation.Data.OsolabAuthContext context,
        FakeRedisClient redis,
        AuthorizeExecutionService authorizeService,
        string email,
        string password,
        string authRequestSessionId,
        string redirectUri)
    {
        var controller = new LoginController(
            context,
            redis,
            new TestWebHostEnvironment(),
            authorizeService);

        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["session_id"] = authRequestSessionId,
            ["email"] = email,
            ["password"] = password
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostLogin();
        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual("redirect", body.Value<string>("result"));

        string location = httpContext.Response.Headers.Location.ToString();
        StringAssert.StartsWith(location, $"{redirectUri}?");

        string code = ExtractQueryValue(location, "code");
        string authSessionId = ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, Code.AUTH_SESSION_COOKIE_KEY);
        return (authSessionId, code);
    }

    private static async Task<string> ExecuteTokenAsync(
        AuthFoundation.Data.OsolabAuthContext context,
        FakeRedisClient redis,
        string clientId,
        string redirectUri,
        string code,
        string verifier)
    {
        var controller = new TokenController(context, redis, SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = redirectUri
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();
        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        return body.Value<string>("access_token") ?? string.Empty;
    }

    private static async Task ExecuteUserInfoAsync(
        AuthFoundation.Data.OsolabAuthContext context,
        FakeRedisClient redis,
        string accessToken,
        string osolabId,
        string email)
    {
        var controller = new UserInfoController(context, redis);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {accessToken}";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetUserInfo();
        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(osolabId, body.Value<string>("sub"));
        Assert.AreEqual(email, body.Value<string>("email"));
    }

    private static async Task ExecuteLogoutAsync(
        FakeRedisClient redis,
        string authSessionId,
        string accessToken)
    {
        var controller = new LogoutController(redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["logout_all"] = "false"
        });
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, authSessionId);
        httpContext.Request.Headers.Authorization = $"Bearer {accessToken}";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostLogout();
        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("logged_out", body.Value<string>("result"));
    }

    private static async Task AddRequiredTermConsentsAsync(
        AuthFoundation.Data.OsolabAuthContext context,
        string osolabId,
        string clientId)
    {
        List<client_term> requiredTerms = await context.client_terms
            .Where(x =>
                (x.client_id == clientId || x.client_id == Code.InnerClient.OSOLAB_CLIENT_ID)
                && x.status == Code.Status.ACTIVE
                && x.required == Code.Status.ACTIVE)
            .ToListAsync();

        if (requiredTerms.Count == 0)
        {
            return;
        }

        DateTime now = DateTime.UtcNow;
        foreach (client_term term in requiredTerms)
        {
            context.user_term_consents.Add(new user_term_consent
            {
                osolab_id = osolabId,
                client_id = term.client_id,
                term_id = term.term_id,
                term_version = term.term_version,
                consent_result = Code.Status.ACTIVE,
                consented_datetime = now,
                create_datetime = now
            });
        }

        await context.SaveChangesAsync();
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
