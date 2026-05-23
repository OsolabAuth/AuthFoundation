using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Models;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;

namespace AuthFoundationTest;

[TestClass]
public sealed class UserInfoApiTests
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
    /// 　リクエスト：Get User Info を Valid Access Token 条件で実行
    /// 期待値
    /// 　Returns Scoped Claims を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetUserInfo_ValidAccessToken_ReturnsScopedClaims()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"userinfo-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());
        context.user_infos.Add(new user_info
        {
            osolab_id = osolabId,
            client_id = clientId,
            data_key = "name",
            data_value = "Test User",
            create_datetime = DateTime.UtcNow,
            update_datetime = DateTime.UtcNow,
            status = Code.Status.ACTIVE
        });
        await context.SaveChangesAsync();

        var redis = new FakeRedisClient();
        string accessToken = $"{osolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";
        await new AccessTokenSession
        {
            AccessToken = accessToken,
            OsolabId = osolabId,
            ClientId = clientId,
            Scope = "openid email profile"
        }.WriteToRedisAsync(redis);

        var controller = new UserInfoController(context, redis);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {accessToken}";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetUserInfo();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(osolabId, body.Value<string>("sub"));
        Assert.AreEqual(email, body.Value<string>("email"));
        Assert.AreEqual(true, body.Value<bool>("email_verified"));
        Assert.AreEqual("Test User", body.Value<string>("name"));
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get User Info を Missing Authorization 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetUserInfo_MissingAuthorization_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new UserInfoController(context, new FakeRedisClient());
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        IActionResult result = await controller.GetUserInfo();

        JObject body = ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
        StringAssert.Contains(body.Value<string>("error_description"), "Authorization");
        Assert.AreEqual("no-store", controller.HttpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", controller.HttpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get User Info を Unknown Access Token 条件で実行
    /// 期待値
    /// 　Returns Unauthorized を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetUserInfo_UnknownAccessToken_ReturnsUnauthorized()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string accessToken = $"{ApiTestData.NewOsolabId()}_{Helper.GenerateHex(32).ToLowerInvariant()}_{Code.InnerClient.OSOLAB_CLIENT_ID}";
        var controller = new UserInfoController(context, new FakeRedisClient());
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {accessToken}";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetUserInfo();

        JObject body = ControllerTestHelper.AssertError(result, (int)Code.UNAUTHORIZED.Status, Code.UNAUTHORIZED.Code);
        Assert.AreEqual("invalid_token", body.Value<string>("error"));
        Assert.AreEqual(Code.UNAUTHORIZED.ErrorDescription, body.Value<string>("error_description"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        StringAssert.Contains(httpContext.Response.Headers["WWW-Authenticate"].ToString(), "Bearer error=\"invalid_token\"");
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get User Info を Inactive User 条件で実行
    /// 期待値
    /// 　Returns Unauthorized を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetUserInfo_InactiveUser_ReturnsUnauthorized()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string osolabId = ApiTestData.NewOsolabId();
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateUserAsync(context, osolabId, $"inactive-{Guid.NewGuid():N}@example.com", ApiTestData.NewPassword(), Code.Status.INACTIVE);

        var redis = new FakeRedisClient();
        string accessToken = $"{osolabId}_{Helper.GenerateHex(32).ToLowerInvariant()}_{clientId}";
        await new AccessTokenSession
        {
            AccessToken = accessToken,
            OsolabId = osolabId,
            ClientId = clientId,
            Scope = "openid"
        }.WriteToRedisAsync(redis);

        var controller = new UserInfoController(context, redis);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = $"Bearer {accessToken}";
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetUserInfo();

        JObject body = ControllerTestHelper.AssertError(result, (int)Code.UNAUTHORIZED.Status, Code.UNAUTHORIZED.Code);
        Assert.AreEqual("invalid_token", body.Value<string>("error"));
        Assert.AreEqual(Code.UNAUTHORIZED.ErrorDescription, body.Value<string>("error_description"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
        StringAssert.Contains(httpContext.Response.Headers["WWW-Authenticate"].ToString(), "Bearer error=\"invalid_token\"");
    }
}
