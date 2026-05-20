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
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: GET /userinfo 正常系でBearer Access Tokenを検証し、scopeに応じたsub/email/profile claimsを返すこと。
    /// </summary>
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
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(osolabId, body.Value<string>("sub"));
        Assert.AreEqual(email, body.Value<string>("email"));
        Assert.AreEqual(true, body.Value<bool>("email_verified"));
        Assert.AreEqual("Test User", body.Value<string>("name"));
    }

    /// <summary>
    /// 検証項目: Authorizationヘッダー未指定時に設計書どおり00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetUserInfo_MissingAuthorization_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new UserInfoController(context, new FakeRedisClient());
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        IActionResult result = await controller.GetUserInfo();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    /// <summary>
    /// 検証項目: Redisに存在しないAccess Tokenでは設計書どおり00008を返すこと。
    /// </summary>
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

        ControllerTestHelper.AssertError(result, (int)Code.UNAUTHORIZED.Status, Code.UNAUTHORIZED.Code);
    }

    /// <summary>
    /// 検証項目: Access Tokenが有効でもユーザーが無効な場合は00008を返すこと。
    /// </summary>
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

        ControllerTestHelper.AssertError(result, (int)Code.UNAUTHORIZED.Status, Code.UNAUTHORIZED.Code);
    }
}
