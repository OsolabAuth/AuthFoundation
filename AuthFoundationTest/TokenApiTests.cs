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
    /// 　リクエスト：Post Token を Valid Authorization Code 条件で実行
    /// 期待値
    /// 　Returns Tokens And Deletes Authorization Code を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Token を Basic Client Authentication 条件で実行
    /// 期待値
    /// 　Returns Tokens を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Token を Missing Flow Type 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Token を Unknown Authorization Code 条件で実行
    /// 期待値
    /// 　Returns Invalid Auth Code を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Token を Redirect Uri Mismatch 条件で実行
    /// 期待値
    /// 　Returns Illegal Redirect Uri を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Token を Invalid Basic Secret 条件で実行
    /// 期待値
    /// 　Returns Illegal Client を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Token を Refresh Grant 条件で実行
    /// 期待値
    /// 　Rotates Refresh Token を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostToken_RefreshGrant_RotatesRefreshToken()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId);

        string osolabId = ApiTestData.NewOsolabId();
        string currentRefreshToken = $"{osolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";
        var redis = new FakeRedisClient();
        await new RefreshTokenSession
        {
            RefreshToken = currentRefreshToken,
            OsolabId = osolabId,
            ClientId = clientId,
            Scope = "openid email"
        }.CreateSession(redis);

        var controller = new TokenController(context, redis, SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = clientId,
            ["refresh_token"] = currentRefreshToken
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.IsTrue(Regex.IsMatch(body.Value<string>("access_token")!, @"^[A-Fa-f0-9]{16}_[A-Fa-f0-9]{32}_[0-9]{32}$"));
        Assert.IsTrue(Regex.IsMatch(body.Value<string>("refresh_token")!, @"^[A-Fa-f0-9]{16}_[A-Fa-f0-9]{32}_[0-9]{32}$"));
        Assert.AreNotEqual(currentRefreshToken, body.Value<string>("refresh_token"));
        Assert.AreEqual("openid email", body.Value<string>("scope"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());

        Assert.IsNull(await redis.GetStringAsync(RefreshTokenSession.GetRedisKey(currentRefreshToken), Code.RedisDbNo.REFRESH_TOKEN));
        Assert.IsFalse(string.IsNullOrWhiteSpace(await redis.GetStringAsync(
            RefreshTokenSession.GetRedisKey(body.Value<string>("refresh_token")!),
            Code.RedisDbNo.REFRESH_TOKEN)));
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Token を Refresh Grant Unknown Refresh Token 条件で実行
    /// 期待値
    /// 　Returns Invalid Grant を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostToken_RefreshGrant_UnknownRefreshToken_ReturnsInvalidGrant()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId);

        var controller = new TokenController(context, new FakeRedisClient(), SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = clientId,
            ["refresh_token"] = $"{ApiTestData.NewOsolabId()}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}"
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        var body = ControllerTestHelper.AssertError(result, (int)Code.INVALID_AUTH_CODE.Status, Code.INVALID_AUTH_CODE.Code);
        Assert.AreEqual("invalid_grant", body.Value<string>("error"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Token を Refresh Grant Client Mismatch 条件で実行
    /// 期待値
    /// 　Returns Invalid Grant を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostToken_RefreshGrant_ClientMismatch_ReturnsInvalidGrant()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string ownerClientId = ApiTestData.NewClientId();
        string otherClientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, ownerClientId);
        await ApiTestData.CreateClientAsync(context, otherClientId);

        string osolabId = ApiTestData.NewOsolabId();
        string refreshToken = $"{osolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{ownerClientId}";
        var redis = new FakeRedisClient();
        await new RefreshTokenSession
        {
            RefreshToken = refreshToken,
            OsolabId = osolabId,
            ClientId = ownerClientId,
            Scope = "openid"
        }.CreateSession(redis);

        var controller = new TokenController(context, redis, SigningTestHelper.CreateSigningService());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = otherClientId,
            ["refresh_token"] = refreshToken
        });
        httpContext.Request.Headers[Code.HttpHeaders.X_FLOW_TYPE.Key] = "AuthorizationCode";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostToken();

        var body = ControllerTestHelper.AssertError(result, (int)Code.INVALID_AUTH_CODE.Status, Code.INVALID_AUTH_CODE.Code);
        Assert.AreEqual("invalid_grant", body.Value<string>("error"));
        Assert.IsFalse(string.IsNullOrWhiteSpace(await redis.GetStringAsync(
            RefreshTokenSession.GetRedisKey(refreshToken),
            Code.RedisDbNo.REFRESH_TOKEN)));
    }
}
