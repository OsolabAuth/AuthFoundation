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
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: POST /login 正常系でAuthSession CookieとRedisログインセッションを作成し、認可セッションなしの場合は00006を返すこと。
    /// </summary>
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
    /// 検証項目: POST /login でCookieのsession_idを認可セッションとして使用し、ログイン後に同意画面へのLocationを返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostLogin_WithAuthorizationSessionCookie_ReturnsRedirectResult()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string osolabId = Helper.GenerateHex(Code.OsolabId.LENGTH).ToLowerInvariant();
        string email = $"login-cookie-{Guid.NewGuid():N}@example.com";
        string password = "Password123";
        await CreateUserAsync(context, osolabId, email, password);

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthorizationSessionAsync(
            redis,
            ApiTestData.CreateAuthorizationSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback", "openid"));

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
            StringAssert.StartsWith(httpContext.Response.Headers.Location.ToString(), $"{AppConfig.AuthUiBaseUrl}/terms?session_id=");

            string? storedAuthz = await redis.GetStringAsync(AuthorizationSession.GetRedisKey(authzSessionId));
            var authz = new AuthorizationSession();
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
    /// 検証項目: POST /login でパスワード不一致の場合に設計書どおり00004を返し、Cookieを発行しないこと。
    /// </summary>
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
            Assert.AreEqual(0, httpContext.Response.Headers.SetCookie.Count);
        }
        finally
        {
            context.osolab_users.RemoveRange(context.osolab_users.Where(x => x.osolab_id == osolabId));
            await context.SaveChangesAsync();
        }
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
    /// 検証項目: POST /login のContent-Type不正時に設計書どおり00001を返すこと。
    /// </summary>
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

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }
}
