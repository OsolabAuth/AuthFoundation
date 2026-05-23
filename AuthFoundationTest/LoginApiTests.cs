using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Models;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class LoginApiTests
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
    /// 　リクエスト：Post Login を Valid Password 条件で実行
    /// 期待値
    /// 　Writes Login Session Cookie And Redis Value を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostLogin_ValidPassword_WritesLoginSessionCookieAndRedisValue()
    {
        await using var context = TestDbContextFactory.Create();
        Assert.IsTrue(await context.Database.CanConnectAsync(), "SQL Server is not available. Run the SQL folder initialization before this test.");

        string osolabId = Helper.GenerateHex(Code.OsolabId.LENGTH).ToLowerInvariant();
        string email = $"api-{Guid.NewGuid():N}@example.com";
        string password = "Password123";
        await CreateUserAsync(context, osolabId, email, password);

        try
        {
            var redis = new FakeRedisClient();
            var controller = new LoginController(
                context,
                redis,
                new TestWebHostEnvironment(),
                new AuthorizeExecutionService(context, redis));
            var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
            {
                ["email"] = email,
                ["password"] = password
            });
            controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

            IActionResult result = await controller.PostLogin();
            Assert.IsInstanceOfType<OkObjectResult>(result, ControllerTestHelper.ToJObject(result).ToString());

            var body = ControllerTestHelper.ToJObject(result);
            Assert.AreEqual("logged_in", body.Value<string>("result"));
            Assert.AreEqual("00006", body.Value<string>("response_code"));
            Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
            Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());

            string setCookie = string.Join("\n", httpContext.Response.Headers.SetCookie.ToArray());
            StringAssert.Contains(setCookie, $"{Code.AUTH_SESSION_COOKIE_KEY}=");
            StringAssert.Contains(setCookie, "session_id=");

            string sessionId = ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, Code.AUTH_SESSION_COOKIE_KEY);
            string? stored = await redis.GetStringAsync(AuthSession.GetRedisKey(sessionId));
            Assert.IsFalse(string.IsNullOrWhiteSpace(stored));

            var session = new AuthSession();
            Assert.IsTrue(session.SetValue(stored!));
            Assert.AreEqual(osolabId, session.OsolabId);
            Assert.AreEqual(email, session.Email);
        }
        finally
        {
            context.osolab_users.RemoveRange(context.osolab_users.Where(x => x.osolab_id == osolabId));
            await context.SaveChangesAsync();
        }
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Login を With Auth Request Session Cookie 条件で実行
    /// 期待値
    /// 　Returns Redirect Result を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostLogin_WithAuthRequestSessionCookie_ReturnsRedirectResult()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string osolabId = Helper.GenerateHex(Code.OsolabId.LENGTH).ToLowerInvariant();
        string email = $"login-cookie-{Guid.NewGuid():N}@example.com";
        string password = "Password123";
        await CreateUserAsync(context, osolabId, email, password);

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback", "openid"));

        try
        {
            var controller = new LoginController(
                context,
                redis,
                new TestWebHostEnvironment(),
                new AuthorizeExecutionService(context, redis));
            var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
            {
                ["email"] = email,
                ["password"] = password
            });
            ControllerTestHelper.SetCookie(httpContext, "session_id", authzSessionId);
            controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

            IActionResult result = await controller.PostLogin();

            Assert.IsInstanceOfType<OkObjectResult>(result, ControllerTestHelper.ToJObject(result).ToString());
            var body = ControllerTestHelper.ToJObject(result);
            Assert.AreEqual("redirect", body.Value<string>("result"));
            Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
            StringAssert.StartsWith(httpContext.Response.Headers.Location.ToString(), $"{AppConfig.AuthUiBaseUrl}/terms");
            Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
            Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());

            string? storedAuthz = await redis.GetStringAsync(AuthRequestSession.GetRedisKey(authzSessionId));
            var authz = new AuthRequestSession();
            Assert.IsTrue(authz.SetValue(storedAuthz!));
            Assert.AreEqual(osolabId, authz.OsolabId);
        }
        finally
        {
            context.osolab_users.RemoveRange(context.osolab_users.Where(x => x.osolab_id == osolabId));
            await context.SaveChangesAsync();
        }
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Login を Invalid Password 条件で実行
    /// 期待値
    /// 　Returns Authentication Failed を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostLogin_InvalidPassword_ReturnsAuthenticationFailed()
    {
        await using var context = TestDbContextFactory.Create();
        Assert.IsTrue(await context.Database.CanConnectAsync(), "SQL Server is not available. Run the SQL folder initialization before this test.");

        string osolabId = Helper.GenerateHex(Code.OsolabId.LENGTH).ToLowerInvariant();
        string email = $"api-{Guid.NewGuid():N}@example.com";
        await CreateUserAsync(context, osolabId, email, "Password123");

        try
        {
            var redis = new FakeRedisClient();
            var controller = new LoginController(
                context,
                redis,
                new TestWebHostEnvironment(),
                new AuthorizeExecutionService(context, redis));
            var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
            {
                ["email"] = email,
                ["password"] = "Wrong123"
            });
            controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

            IActionResult result = await controller.PostLogin();
            Assert.IsInstanceOfType<ObjectResult>(result);

            var objectResult = (ObjectResult)result;
            Assert.AreEqual((int)Code.AUTHENTICATION_FAILED.Status, objectResult.StatusCode);

            var body = ControllerTestHelper.ToJObject(result);
            Assert.AreEqual("error", body.Value<string>("result"));
            Assert.AreEqual(Code.AUTHENTICATION_FAILED.Code, body.Value<string>("response_code"));
            Assert.AreEqual("access_denied", body.Value<string>("error"));
            Assert.AreEqual(Code.AUTHENTICATION_FAILED.ErrorDescription, body.Value<string>("error_description"));
            Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
            Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
            Assert.AreEqual(0, httpContext.Response.Headers.SetCookie.Count);
        }
        finally
        {
            context.osolab_users.RemoveRange(context.osolab_users.Where(x => x.osolab_id == osolabId));
            await context.SaveChangesAsync();
        }
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Login を Invalid Mail Address Format 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostLogin_InvalidMailAddressFormat_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new LoginController(
            context,
            redis,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["email"] = "user@@example.com",
            ["password"] = "Password123"
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostLogin();

        var body = ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
    }

    private static async Task CreateUserAsync(
        AuthFoundation.Data.OsolabAuthContext context,
        string osolabId,
        string email,
        string password)
    {
        string nonce = Helper.GenerateRandomCode(Code.Nonce.LENGTH, Code.Nonce.CHARACTORS);
        string storedPasswordHash = Helper.GetPassHash(password, nonce);
        DateTime now = DateTime.UtcNow;

        context.osolab_users.Add(new osolab_user
        {
            osolab_id = osolabId,
            email = email,
            password = storedPasswordHash,
            nonce = nonce,
            create_datetime = now,
            update_datetime = now,
            status = Code.Status.ACTIVE
        });

        await context.SaveChangesAsync();
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Login を Invalid Content Type 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostLogin_InvalidContentType_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new LoginController(
            context,
            redis,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        IActionResult result = await controller.PostLogin();

        var body = ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
        Assert.AreEqual("invalid_request", body.Value<string>("error"));
        Assert.AreEqual("no-store", controller.HttpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", controller.HttpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Status を With Valid Session 条件で実行
    /// 期待値
    /// 　Returns Logged In True を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetStatus_WithValidSession_ReturnsLoggedInTrue()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string loginSessionId = await ApiTestData.WriteLoginSessionAsync(
            redis,
            ApiTestData.NewOsolabId(),
            $"status-{Guid.NewGuid():N}@example.com");

        var controller = new LoginController(
            context,
            redis,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, loginSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetStatus();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual(true, body.Value<bool>("logged_in"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Status を Without Session 条件で実行
    /// 期待値
    /// 　Returns Logged In False を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetStatus_WithoutSession_ReturnsLoggedInFalse()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new LoginController(
            context,
            redis,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        IActionResult result = await controller.GetStatus();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual(false, body.Value<bool>("logged_in"));
        Assert.AreEqual("no-store", controller.HttpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", controller.HttpContext.Response.Headers["Pragma"].ToString());
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Status を Invalid Session 条件で実行
    /// 期待値
    /// 　Returns Logged In False を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetStatus_InvalidSession_ReturnsLoggedInFalse()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        var controller = new LoginController(
            context,
            redis,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, "missing-session");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetStatus();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual(false, body.Value<bool>("logged_in"));
        Assert.AreEqual("no-store", httpContext.Response.Headers["Cache-Control"].ToString());
        Assert.AreEqual("no-cache", httpContext.Response.Headers["Pragma"].ToString());
    }
}

