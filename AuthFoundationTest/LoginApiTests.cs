using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Models;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
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

    [TestMethod]
    public async Task PostLogin_ValidPassword_WritesLoginSessionCookieAndRedisValue()
    {
        await using var context = TestDbContextFactory.Create();
        Assert.IsTrue(await context.Database.CanConnectAsync(), "SQL Server is not available. Run the SQL folder initialization before this test.");

        string osolabId = Helper.GenerateHex(Code.OsolabId.LENGTH).ToLowerInvariant();
        string email = $"api-{Guid.NewGuid():N}@example.com";
        string password = "correct-password";
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
            Assert.IsInstanceOfType<OkObjectResult>(result);

            var body = ControllerTestHelper.ToJObject(result);
            Assert.AreEqual("logged_in", body.Value<string>("result"));
            Assert.AreEqual("00006", body.Value<string>("response_code"));

            string setCookie = string.Join("\n", httpContext.Response.Headers.SetCookie.ToArray());
            StringAssert.Contains(setCookie, $"{Code.AUTH_SESSION_COOKIE_KEY}=");
            StringAssert.Contains(setCookie, "session_id=");

            string sessionId = ExtractCookieValue(setCookie, Code.AUTH_SESSION_COOKIE_KEY);
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

    [TestMethod]
    public async Task PostLogin_InvalidPassword_ReturnsAuthenticationFailed()
    {
        await using var context = TestDbContextFactory.Create();
        Assert.IsTrue(await context.Database.CanConnectAsync(), "SQL Server is not available. Run the SQL folder initialization before this test.");

        string osolabId = Helper.GenerateHex(Code.OsolabId.LENGTH).ToLowerInvariant();
        string email = $"api-{Guid.NewGuid():N}@example.com";
        await CreateUserAsync(context, osolabId, email, "correct-password");

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
                ["password"] = "wrong-password"
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
        string normalizedPasswordHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
        string storedPasswordHash = Helper.GetPassHash(normalizedPasswordHash, nonce);
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

    private static string ExtractCookieValue(string setCookie, string key)
    {
        foreach (string cookie in setCookie.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!cookie.StartsWith($"{key}=", StringComparison.Ordinal))
            {
                continue;
            }

            string valuePart = cookie.Split(';', 2)[0];
            return valuePart[(key.Length + 1)..];
        }

        Assert.Fail($"Cookie '{key}' was not set.");
        return string.Empty;
    }
}
