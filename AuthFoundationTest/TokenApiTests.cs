using System.Text.RegularExpressions;
using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class TokenApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: POST /token 正常系でAccess Token/Refresh Token/ID Tokenを返し、認可コードを使用済みにすること。
    /// </summary>
    [TestMethod]
    public async Task PostToken_ValidAuthorizationCode_ReturnsTokensAndDeletesAuthorizationCode()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        await ApiTestData.CreateClientAsync(context, clientId, redirectUri: redirectUri);

        var redis = new FakeRedisClient();
        string verifier = new string('v', 64);
        var codeSession = new AuthCodeSession
        {
            Code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
            OsolabId = ApiTestData.NewOsolabId(),
            Email = $"token-{Guid.NewGuid():N}@example.com",
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scope = "openid email",
            CodeChallenge = ApiTestData.CodeChallengeFor(verifier),
            CodeChallengeMethod = "S256",
            Nonce = "nonce-token-test",
            State = "state-token-test"
        };
        await codeSession.WriteToRedisAsync(redis);

        var controller = new TokenController(context, redis, SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = codeSession.Code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = redirectUri
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual(Code.AccessToken.TOKEN_TYPE_BEARER, body.Value<string>("token_type"));
        Assert.IsTrue(Regex.IsMatch(body.Value<string>("access_token")!, @"^[A-Fa-f0-9]{16}_[A-Fa-f0-9]{32}_[0-9]{32}$"));
        Assert.IsTrue(Regex.IsMatch(body.Value<string>("refresh_token")!, @"^[A-Fa-f0-9]{16}_[A-Fa-f0-9]{32}_[0-9]{32}$"));
        Assert.AreEqual(3, body.Value<string>("id_token")!.Split('.').Length);
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        Assert.IsNull(await redis.GetStringAsync(AuthCodeSession.GetRedisKey(codeSession.Code), Code.RedisDbNo.AUTHORIZATION_CODE));
        Assert.IsFalse(string.IsNullOrWhiteSpace(await redis.GetStringAsync(AccessTokenSession.GetRedisKey(body.Value<string>("access_token")!), Code.RedisDbNo.ACCESS_TOKEN)));
        Assert.IsFalse(string.IsNullOrWhiteSpace(await redis.GetStringAsync(RefreshTokenSession.GetRedisKey(body.Value<string>("refresh_token")!), Code.RedisDbNo.REFRESH_TOKEN)));
    }

    /// <summary>
    /// 検証項目: client_secret_basicの正常系で、bodyのclient_idなしでもConfidential Clientとしてトークン発行できること。
    /// </summary>
    [TestMethod]
    public async Task PostToken_BasicClientAuthentication_ReturnsTokens()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string clientSecret = "basic-secret";
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        await ApiTestData.CreateClientAsync(context, clientId, clientSecret, redirectUri);

        var redis = new FakeRedisClient();
        string verifier = new string('b', 64);
        var codeSession = new AuthCodeSession
        {
            Code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
            OsolabId = ApiTestData.NewOsolabId(),
            Email = $"basic-{Guid.NewGuid():N}@example.com",
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scope = "openid",
            CodeChallenge = ApiTestData.CodeChallengeFor(verifier),
            CodeChallengeMethod = "S256",
            Nonce = "nonce-basic-test"
        };
        await codeSession.WriteToRedisAsync(redis);

        var controller = new TokenController(context, redis, SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = codeSession.Code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = redirectUri
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(clientId, clientSecret);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("openid", body.Value<string>("scope"));
    }

    /// <summary>
    /// 検証項目: grant_type等の必須パラメータ不足時に設計書どおり00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostToken_MissingFlowType_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new TokenController(context, new FakeRedisClient(), SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = Code.InnerClient.OSOLAB_CLIENT_ID,
            ["code"] = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
            ["code_verifier"] = new string('v', 64),
            ["redirect_uri"] = "https://portal.osolab-auth.jp/callback"
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    /// <summary>
    /// 検証項目: 存在しない認可コードでは設計書どおり00007を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostToken_UnknownAuthorizationCode_ReturnsInvalidAuthCode()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new TokenController(context, new FakeRedisClient(), SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = Code.InnerClient.OSOLAB_CLIENT_ID,
            ["code"] = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
            ["code_verifier"] = new string('v', 64),
            ["redirect_uri"] = "https://portal.osolab-auth.jp/callback"
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        ControllerTestHelper.AssertError(result, (int)Code.INVALID_AUTH_CODE.Status, Code.INVALID_AUTH_CODE.Code);
    }

    /// <summary>
    /// 検証項目: 認可コードに紐づくredirect_uriとリクエスト値が不一致の場合に00005を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostToken_RedirectUriMismatch_ReturnsIllegalRedirectUri()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId);
        var redis = new FakeRedisClient();
        string verifier = new string('r', 64);
        var codeSession = new AuthCodeSession
        {
            Code = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
            OsolabId = ApiTestData.NewOsolabId(),
            Email = $"redirect-{Guid.NewGuid():N}@example.com",
            ClientId = clientId,
            RedirectUri = "https://portal.osolab-auth.jp/callback",
            Scope = "openid",
            CodeChallenge = ApiTestData.CodeChallengeFor(verifier),
            CodeChallengeMethod = "S256",
            Nonce = "nonce-redirect-test"
        };
        await codeSession.WriteToRedisAsync(redis);

        var controller = new TokenController(context, redis, SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = codeSession.Code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = "https://portal.osolab-auth.jp/other"
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_REDIRECT_URI.Status, Code.ILLEGAL_REDIRECT_URI.Code);
    }

    /// <summary>
    /// 検証項目: Basic認証のsecret不一致時に設計書どおり00002を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostToken_InvalidBasicSecret_ReturnsIllegalClient()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId, "expected-secret");

        var controller = new TokenController(context, new FakeRedisClient(), SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = Helper.GenerateRandomCode(Code.AuthCode.LENGTH, Code.AuthCode.CHARACTORS),
            ["code_verifier"] = new string('v', 64),
            ["redirect_uri"] = "https://portal.osolab-auth.jp/callback"
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(clientId, "wrong-secret");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        var body = ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_CLIENT.Status, Code.ILLEGAL_CLIENT.Code);
        Assert.AreEqual("invalid_client", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }
}
