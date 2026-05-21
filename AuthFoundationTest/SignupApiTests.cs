using AuthFoundation.Common;
using AuthFoundation.Controllers.Signup;
using AuthFoundation.Models;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Newtonsoft.Json.Linq;

namespace AuthFoundationTest;

[TestClass]
public sealed class SignupApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: POST /signup/email 正常系でサインアップセッションを作成し、signup_session_id Cookieを発行すること。
    /// </summary>
    [TestMethod]
    public async Task PostEmail_ValidRequest_CreatesSignupSessionAndCookie()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback"));

        string email = $"signup-mail-{Guid.NewGuid():N}@example.com";
        var controller = new SignupEmailController(
            context,
            redis,
            CreateGmailSmtpMail(),
            NullLogger<SignupEmailController>.Instance);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["email"] = email
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", authzSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostEmail();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));
        string signupSessionId = ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, "signup_session_id");
        string? raw = await redis.GetStringAsync(SignupSession.GetRedisKey(signupSessionId), Code.RedisDbNo.SIGNUP_SESSION);
        Assert.IsFalse(string.IsNullOrWhiteSpace(raw));

        var verify = new SignupSession();
        Assert.IsTrue(verify.SetValue(raw!));
        Assert.AreEqual(email, verify.Email);
        Assert.AreEqual(authzSessionId, verify.AuthRequestSessionId);
        Assert.IsFalse(verify.Verified);
    }

    /// <summary>
    /// 検証項目: POST /signup/email で既存有効メールアドレス指定時に00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostEmail_ExistingActiveEmail_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string email = $"exists-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateUserAsync(context, ApiTestData.NewOsolabId(), email, ApiTestData.NewPassword());

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback"));

        var controller = new SignupEmailController(context, redis, CreateGmailSmtpMail(), NullLogger<SignupEmailController>.Instance);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["email"] = email
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", authzSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostEmail();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    /// <summary>
    /// 検証項目: POST /signup/email で認可セッションが無効な場合に00003を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostEmail_MissingAuthRequestSession_ReturnsScreenExpired()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new SignupEmailController(context, new FakeRedisClient(), CreateGmailSmtpMail(), NullLogger<SignupEmailController>.Instance);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["email"] = $"nosession-{Guid.NewGuid():N}@example.com"
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant());
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostEmail();

        ControllerTestHelper.AssertError(result, (int)Code.SCREEN_EXPIRED.Status, Code.SCREEN_EXPIRED.Code);
    }

    /// <summary>
    /// 検証項目: POST /signup/verify 正常系で認証コードを照合し、セッションを認証済みにすること。
    /// </summary>
    [TestMethod]
    public async Task Verify_ValidCode_MarksSessionVerified()
    {
        var redis = new FakeRedisClient();
        string signupSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await new SignupSession
        {
            SignupSessionId = signupSessionId,
            AuthRequestSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant(),
            Email = $"verify-{Guid.NewGuid():N}@example.com",
            Code = "12345",
            Verified = false
        }.WriteToRedisAsync(redis);

        var controller = new SignupVerifyController(redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["code"] = "12345"
        });
        ControllerTestHelper.SetCookie(httpContext, "signup_session_id", signupSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.Verify();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));

        var saved = new SignupSession();
        string? raw = await redis.GetStringAsync(SignupSession.GetRedisKey(signupSessionId), Code.RedisDbNo.SIGNUP_SESSION);
        Assert.IsTrue(saved.SetValue(raw!));
        Assert.IsTrue(saved.Verified);
    }

    /// <summary>
    /// 検証項目: POST /signup/verify で確認コード不一致時に00001を返し、セッション状態を変更しないこと。
    /// </summary>
    [TestMethod]
    public async Task Verify_InvalidCode_ReturnsRequestParameterError()
    {
        var redis = new FakeRedisClient();
        string signupSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await new SignupSession
        {
            SignupSessionId = signupSessionId,
            AuthRequestSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant(),
            Email = $"verify-invalid-{Guid.NewGuid():N}@example.com",
            Code = "12345",
            Verified = false
        }.WriteToRedisAsync(redis);

        var controller = new SignupVerifyController(redis);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["code"] = "99999"
        });
        ControllerTestHelper.SetCookie(httpContext, "signup_session_id", signupSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.Verify();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
        var saved = new SignupSession();
        string? raw = await redis.GetStringAsync(SignupSession.GetRedisKey(signupSessionId), Code.RedisDbNo.SIGNUP_SESSION);
        Assert.IsTrue(saved.SetValue(raw!));
        Assert.IsFalse(saved.Verified);
    }

    /// <summary>
    /// 検証項目: POST /signup/account 正常系でユーザー有効化、ログインCookie発行、認可再開を行うこと。
    /// </summary>
    [TestMethod]
    public async Task PostAccount_VerifiedSession_ActivatesUserAndRedirects()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        string email = $"account-{Guid.NewGuid():N}@example.com";
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback", "openid"));

        string signupSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await new SignupSession
        {
            SignupSessionId = signupSessionId,
            AuthRequestSessionId = authzSessionId,
            Email = email,
            Code = "12345",
            Verified = true
        }.WriteToRedisAsync(redis);

        var controller = new SignupAccountController(
            context,
            redis,
            new AuthorizeExecutionService(context, redis),
            NullLogger<SignupAccountController>.Instance);
        string password = ApiTestData.NewPassword();
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["password"] = password
        });
        ControllerTestHelper.SetCookie(httpContext, "signup_session_id", signupSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostAccount();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual("redirect", body.Value<string>("result"));
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.IsFalse(string.IsNullOrWhiteSpace(httpContext.Response.Headers.Location.ToString()));

        osolab_user user = context.osolab_users.Single(x => x.email == email);
        Assert.AreEqual(Code.Status.ACTIVE, user.status);
        Assert.IsNull(await redis.GetStringAsync(SignupSession.GetRedisKey(signupSessionId), Code.RedisDbNo.SIGNUP_SESSION));

        string authSessionId = ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, Code.AUTH_SESSION_COOKIE_KEY);
        Assert.IsFalse(string.IsNullOrWhiteSpace(await redis.GetStringAsync(AuthSession.GetRedisKey(authSessionId))));
    }

    /// <summary>
    /// 検証項目: POST /signup/account で認証未完了セッション指定時に00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostAccount_NotVerified_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string signupSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await new SignupSession
        {
            SignupSessionId = signupSessionId,
            AuthRequestSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant(),
            Email = $"not-verified-{Guid.NewGuid():N}@example.com",
            Code = "12345",
            Verified = false
        }.WriteToRedisAsync(redis);

        var controller = new SignupAccountController(
            context,
            redis,
            new AuthorizeExecutionService(context, redis),
            NullLogger<SignupAccountController>.Instance);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["password"] = ApiTestData.NewPassword()
        });
        ControllerTestHelper.SetCookie(httpContext, "signup_session_id", signupSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostAccount();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    /// <summary>
    /// 検証項目: POST /signup/resend 正常系で確認コードを更新すること。
    /// </summary>
    [TestMethod]
    public async Task Resend_ValidSession_UpdatesVerificationCode()
    {
        var redis = new FakeRedisClient();
        string signupSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await new SignupSession
        {
            SignupSessionId = signupSessionId,
            AuthRequestSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant(),
            Email = $"resend-{Guid.NewGuid():N}@example.com",
            Code = "99999",
            Verified = true
        }.WriteToRedisAsync(redis);

        var controller = new SignupResendController(redis, CreateGmailSmtpMail());
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>());
        ControllerTestHelper.SetCookie(httpContext, "signup_session_id", signupSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.Resend();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));

        var saved = new SignupSession();
        Assert.IsTrue(saved.SetValue((await redis.GetStringAsync(SignupSession.GetRedisKey(signupSessionId), Code.RedisDbNo.SIGNUP_SESSION))!));
        Assert.AreEqual("00000", saved.Code);
        Assert.IsFalse(saved.Verified);
    }

    private static GmailSmtpMail CreateGmailSmtpMail()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:FromEmail"] = "from@example.com",
                ["GmailSmtp:Host"] = "smtp.gmail.com",
                ["GmailSmtp:Username"] = "user@example.com",
                ["GmailSmtp:AppPassword"] = "app-password"
            })
            .Build();

        return new GmailSmtpMail(config, NullLogger<GmailSmtpMail>.Instance);
    }
}



