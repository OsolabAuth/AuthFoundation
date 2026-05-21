using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class RevokeApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: POST /revoke でaccess_token指定時に対象アクセストークンを失効できること。
    /// </summary>
    [TestMethod]
    public async Task PostRevoke_AccessToken_DeletesAccessTokenSession()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string clientSecret = "client-secret";
        await ApiTestData.CreateClientAsync(context, clientId, clientSecret);

        var redis = new FakeRedisClient();
        string accessToken = BuildToken(clientId);
        await new AccessTokenSession
        {
            AccessToken = accessToken,
            OsolabId = ApiTestData.NewOsolabId(),
            ClientId = clientId,
            Scope = "openid email"
        }.WriteToRedisAsync(redis);

        var controller = new RevokeController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["token"] = accessToken,
            ["token_type"] = "access_token"
        });
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(clientId, clientSecret);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostRevoke();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("revoked", body.Value<string>("result"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        Assert.IsNull(await redis.GetStringAsync(AccessTokenSession.GetRedisKey(accessToken), Code.RedisDbNo.ACCESS_TOKEN));
    }

    /// <summary>
    /// 検証項目: POST /revoke でrefresh_token指定時に対象リフレッシュトークンを失効できること。
    /// </summary>
    [TestMethod]
    public async Task PostRevoke_RefreshToken_DeletesRefreshTokenSession()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string clientSecret = "client-secret";
        await ApiTestData.CreateClientAsync(context, clientId, clientSecret);

        var redis = new FakeRedisClient();
        string refreshToken = BuildToken(clientId);
        await new RefreshTokenSession
        {
            RefreshToken = refreshToken,
            OsolabId = ApiTestData.NewOsolabId(),
            ClientId = clientId,
            Scope = "openid email"
        }.WriteToRedisAsync(redis);

        var controller = new RevokeController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["token"] = refreshToken,
            ["token_type"] = "refresh_token"
        });
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(clientId, clientSecret);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostRevoke();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("revoked", body.Value<string>("result"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        Assert.IsNull(await redis.GetStringAsync(RefreshTokenSession.GetRedisKey(refreshToken), Code.RedisDbNo.REFRESH_TOKEN));
    }

    /// <summary>
    /// 検証項目: token_type_hint 指定でも失効処理できること。
    /// </summary>
    [TestMethod]
    public async Task PostRevoke_TokenTypeHint_Works()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId, "client-secret");

        var redis = new FakeRedisClient();
        string accessToken = BuildToken(clientId);
        await new AccessTokenSession
        {
            AccessToken = accessToken,
            OsolabId = ApiTestData.NewOsolabId(),
            ClientId = clientId,
            Scope = "openid"
        }.WriteToRedisAsync(redis);

        var controller = new RevokeController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["token"] = accessToken,
            ["token_type_hint"] = "access_token",
            ["client_id"] = clientId
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostRevoke();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        Assert.IsNull(await redis.GetStringAsync(AccessTokenSession.GetRedisKey(accessToken), Code.RedisDbNo.ACCESS_TOKEN));
    }

    /// <summary>
    /// 検証項目: 別クライアントのトークンは失効しないこと。
    /// </summary>
    [TestMethod]
    public async Task PostRevoke_OtherClientToken_DoesNotDelete()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string tokenOwnerClientId = ApiTestData.NewClientId();
        string requesterClientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, tokenOwnerClientId, "owner-secret");
        await ApiTestData.CreateClientAsync(context, requesterClientId, "requester-secret");

        var redis = new FakeRedisClient();
        string accessToken = BuildToken(tokenOwnerClientId);
        await new AccessTokenSession
        {
            AccessToken = accessToken,
            OsolabId = ApiTestData.NewOsolabId(),
            ClientId = tokenOwnerClientId,
            Scope = "openid"
        }.WriteToRedisAsync(redis);

        var controller = new RevokeController(context, redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["token"] = accessToken,
            ["token_type"] = "access_token"
        });
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(requesterClientId, "requester-secret");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostRevoke();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        Assert.IsNotNull(await redis.GetStringAsync(AccessTokenSession.GetRedisKey(accessToken), Code.RedisDbNo.ACCESS_TOKEN));
    }

    /// <summary>
    /// 検証項目: token_type不正時に00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostRevoke_InvalidTokenType_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId, "client-secret");

        var controller = new RevokeController(context, new FakeRedisClient());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["token"] = BuildToken(clientId),
            ["token_type"] = "id_token",
            ["client_id"] = clientId
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostRevoke();

        var body = ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
        StringAssert.Contains(body.Value<string>("error_description"), "token_type");
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    private static string BuildToken(string clientId)
    {
        return $"{ApiTestData.NewOsolabId()}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";
    }
}
