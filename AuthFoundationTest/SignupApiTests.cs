using AuthFoundation.Common;
using AuthFoundation.Controllers.Signup;
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
    /// 検証項目: POST /Signup/Account 正常系でCookieのsession_idを使い、仮ユーザーとメール確認セッションを作成すること。
    /// </summary>
    [TestMethod]
    public async Task PostAccount_ValidRequest_CreatesTentativeUserAndMailVerificationSession()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthorizationSessionAsync(
            redis,
            ApiTestData.CreateAuthorizationSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback"));

        string email = $"signup-{Guid.NewGuid():N}@example.com";
        var controller = new SignupAccountController(
            context,
            redis,
            new TestWebHostEnvironment(),
            CreateBrevoMail(),
            NullLogger<SignupAccountController>.Instance);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["email"] = email,
            ["password"] = ApiTestData.NewPassword()
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", authzSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostAccount();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));
        string verifyUrl = body.Value<string>("VerifyUrl")!;
        StringAssert.StartsWith(verifyUrl, "/Signup/Verify?token=");
        string token = Uri.UnescapeDataString(verifyUrl.Split("token=", 2)[1]);
        Assert.IsFalse(string.IsNullOrWhiteSpace(await redis.GetStringAsync(MailVerificationSession.GetRedisKey(token), Code.RedisDbNo.MAIL_VERIFICATION_SESSION)));
        Assert.IsTrue(context.osolab_users.Any(x => x.email == email && x.status == Code.Status.TENTATIVE));
    }

    /// <summary>
    /// 検証項目: 既存の有効メールアドレス指定時に設計書どおり00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostAccount_ExistingActiveEmail_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string email = $"exists-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateUserAsync(context, ApiTestData.NewOsolabId(), email, ApiTestData.NewPassword());

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthorizationSessionAsync(
            redis,
            ApiTestData.CreateAuthorizationSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback"));

        var controller = new SignupAccountController(context, redis, new TestWebHostEnvironment(), CreateBrevoMail(), NullLogger<SignupAccountController>.Instance);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["email"] = email,
            ["password"] = ApiTestData.NewPassword()
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", authzSessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostAccount();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    /// <summary>
    /// 検証項目: 認可セッションが存在しない場合に00003を返し、仮ユーザーを作成しないこと。
    /// </summary>
    [TestMethod]
    public async Task PostAccount_MissingAuthorizationSession_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string email = $"nosession-{Guid.NewGuid():N}@example.com";
        var controller = new SignupAccountController(context, new FakeRedisClient(), new TestWebHostEnvironment(), CreateBrevoMail(), NullLogger<SignupAccountController>.Instance);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["email"] = email,
            ["password"] = ApiTestData.NewPassword()
        });
        ControllerTestHelper.SetCookie(httpContext, "session_id", Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant());
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostAccount();

        ControllerTestHelper.AssertError(result, (int)Code.SCREEN_EXPIRED.Status, Code.SCREEN_EXPIRED.Code);
        Assert.IsFalse(context.osolab_users.Any(x => x.email == email));
    }

    /// <summary>
    /// 検証項目: GET /Signup/Verify 正常系で確認コードを照合し、仮ユーザーを有効化してAuthSession Cookieを発行すること。
    /// </summary>
    [TestMethod]
    public async Task Verify_ValidTokenAndCode_ActivatesUserAndRedirects()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string osolabId = ApiTestData.NewOsolabId();
        string email = $"verify-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword(), Code.Status.TENTATIVE);

        var redis = new FakeRedisClient();
        string authzSessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthorizationSessionAsync(
            redis,
            ApiTestData.CreateAuthorizationSession(authzSessionId, Code.InnerClient.OSOLAB_CLIENT_ID, "https://portal.osolab-auth.jp/callback", "openid"));
        string token = Helper.GenerateRandomCode(48, Code.AuthCode.CHARACTORS);
        await new MailVerificationSession
        {
            VerificationToken = token,
            OsolabId = osolabId,
            Email = email,
            SessionId = authzSessionId,
            Code = "12345"
        }.WriteToRedisAsync(redis);

        var controller = new SignupVerifyController(context, redis, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString($"?token={Uri.EscapeDataString(token)}&code=12345");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.Verify();

        Assert.IsInstanceOfType<RedirectResult>(result);
        Assert.AreEqual(Code.Status.ACTIVE, context.osolab_users.Single(x => x.osolab_id == osolabId).status);
        Assert.IsNull(await redis.GetStringAsync(MailVerificationSession.GetRedisKey(token), Code.RedisDbNo.MAIL_VERIFICATION_SESSION));
        string authSessionId = ControllerTestHelper.ExtractCookieValue(httpContext.Response.Headers, Code.AUTH_SESSION_COOKIE_KEY);
        Assert.IsFalse(string.IsNullOrWhiteSpace(await redis.GetStringAsync(AuthSession.GetRedisKey(authSessionId))));
    }

    /// <summary>
    /// 検証項目: GET /Signup/Verify で確認コードが不一致の場合、ユーザーを有効化せず00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task Verify_InvalidCode_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string osolabId = ApiTestData.NewOsolabId();
        string email = $"verify-invalid-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword(), Code.Status.TENTATIVE);

        var redis = new FakeRedisClient();
        string token = Helper.GenerateRandomCode(48, Code.AuthCode.CHARACTORS);
        await new MailVerificationSession
        {
            VerificationToken = token,
            OsolabId = osolabId,
            Email = email,
            SessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant(),
            Code = "12345"
        }.WriteToRedisAsync(redis);

        var controller = new SignupVerifyController(context, redis, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString($"?token={Uri.EscapeDataString(token)}&code=99999");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.Verify();

        var body = ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.Code, body.Value<string>("StatusCode"));
        Assert.AreEqual(Code.Status.TENTATIVE, context.osolab_users.Single(x => x.osolab_id == osolabId).status);
    }

    /// <summary>
    /// 検証項目: POST /Signup/Resend 正常系で既存のメール確認セッションを読み、確認コードを更新すること。
    /// </summary>
    [TestMethod]
    public async Task Resend_ValidToken_UpdatesMailVerificationCode()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string osolabId = ApiTestData.NewOsolabId();
        string email = $"resend-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword(), Code.Status.TENTATIVE);

        var redis = new FakeRedisClient();
        string token = Helper.GenerateRandomCode(48, Code.AuthCode.CHARACTORS);
        await new MailVerificationSession
        {
            VerificationToken = token,
            OsolabId = osolabId,
            Email = email,
            SessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant(),
            Code = "99999"
        }.WriteToRedisAsync(redis);

        var controller = new SignupResendController(context, redis, CreateBrevoMail());
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString($"?token={Uri.EscapeDataString(token)}");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.Resend();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));
        var saved = new MailVerificationSession();
        Assert.IsTrue(saved.SetValue((await redis.GetStringAsync(MailVerificationSession.GetRedisKey(token), Code.RedisDbNo.MAIL_VERIFICATION_SESSION))!));
        Assert.AreEqual("00000", saved.Code);
    }

    private static BrevoMail CreateBrevoMail()
    {
        IConfiguration config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Mail:Provider"] = "BrevoApi"
            })
            .Build();

        return new BrevoMail(new HttpClient(), config, NullLogger<BrevoMail>.Instance);
    }
}
