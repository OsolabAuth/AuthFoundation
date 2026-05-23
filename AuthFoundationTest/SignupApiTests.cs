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
    /// 　リクエスト：Post Email を Valid Request 条件で実行
    /// 期待値
    /// 　Creates Signup Session And Cookie を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Email を Existing Active Email 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Email を Invalid Mail Address Format 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task PostEmail_InvalidMailAddressFormat_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthRequestSessionAsync(
            redis,
            ApiTestData.CreateAuthRequestSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback"));

        var controller = new SignupEmailController(context, redis, CreateGmailSmtpMail(), NullLogger<SignupEmailController>.Instance);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["email"] = "user@@example.com"
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", authzSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostEmail();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Email を Missing Auth Request Session 条件で実行
    /// 期待値
    /// 　Returns Screen Expired を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Verify を Valid Code 条件で実行
    /// 期待値
    /// 　Marks Session Verified を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Verify を Invalid Code 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Account を Verified Session 条件で実行
    /// 期待値
    /// 　Activates User And Redirects を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Post Account を Not Verified 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Resend を Valid Session 条件で実行
    /// 期待値
    /// 　Updates Verification Code を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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



