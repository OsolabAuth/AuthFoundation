using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using Microsoft.Extensions.Primitives;

namespace AuthFoundationTest;

[TestClass]
public sealed class SignupEndpointShapeTests
{
    /// <summary>
    /// 目的: Post / Returns Created User Profile の仕様を検証する。
    /// 入力値: Post / Returns Created User Profile を確認するためにテスト内で作成したデータ。
    /// 期待値: Post / Returns Created User Profile の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Post_ReturnsCreatedUserProfile()
    {
        var users = new InMemoryUserStore();
        var emailSender = new CapturingEmailSender();
        var signupSessions = new SignupSessionService(emailSender, new AttemptLimiter());
        SignupEmailChallenge challenge = signupSessions.StartEmailChallenge("signup-success@example.com");
        SignupVerifiedSession verified = signupSessions.VerifyEmailChallenge(challenge.SessionId, emailSender.LastCode);
        var controller = EndpointTestHelper.WithHttpContext(new SignupController(users, new TermsService(), signupSessions));
        controller.Request.Headers.Cookie = $"AuthSignupSessionId={verified.SessionId}";
        var request = new SignupRequest(
            "signup-success@example.com",
            "Passw0rd!",
            "Signup User",
            "2001-02-03",
            true);

        var ok = EndpointTestHelper.AssertOk(controller.Post(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        string sub = EndpointTestHelper.ReadProperty<string>(ok.Value, "sub");
        Assert.IsTrue(sub.StartsWith("user_", StringComparison.Ordinal));
        Assert.AreEqual("signup-success@example.com", EndpointTestHelper.ReadProperty<string>(ok.Value, "email"));
        Assert.AreEqual("Signup User", EndpointTestHelper.ReadProperty<string>(ok.Value, "name"));
        Assert.AreEqual("2001-02-03", EndpointTestHelper.ReadProperty<string>(ok.Value, "birth_date"));
        Assert.AreEqual(sub, users.Authenticate("signup-success@example.com", "Passw0rd!").Subject);
    }

    /// <summary>
    /// 旧POST /signupがメール検証済みsignup sessionなしではアカウントを作成しないことを確認する。
    /// </summary>
    [TestMethod]
    public void Post_ReturnsUnauthorizedWithoutVerifiedSignupSession()
    {
        var users = new InMemoryUserStore();
        var controller = EndpointTestHelper.WithHttpContext(new SignupController(users, new TermsService()));
        var request = new SignupRequest(
            "signup-direct@example.com",
            "Passw0rd!",
            "Signup User",
            "2001-02-03",
            true);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Post(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.ThrowsExactly<ApiException>(() => users.FindByEmail("signup-direct@example.com"));
    }

    /// <summary>
    /// 目的: Post / Returns Bad Request For Invalid Email の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Post_ReturnsBadRequestForInvalidEmail()
    {
        var controller = EndpointTestHelper.WithHttpContext(new SignupController(new InMemoryUserStore(), new TermsService()));
        var request = new SignupRequest("invalid", "Passw0rd!", "Signup User", "2001-02-03", true);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Post(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Post / Returns Bad Request For Invalid Birth Date の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Post_ReturnsBadRequestForInvalidBirthDate()
    {
        var controller = EndpointTestHelper.WithHttpContext(new SignupController(new InMemoryUserStore(), new TermsService()));
        var request = new SignupRequest("signup-birth@example.com", "Passw0rd!", "Signup User", "2001-13-40", true);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Post(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("some of the input values are incorrect", error.ErrorDescription);
    }

    /// <summary>
    /// Portal本番の3段階登録フローがメール送信、コード確認、アカウント作成の順に完了することを検証する。
    /// </summary>
    [TestMethod]
    public async Task PortalSignupFlow_CreatesUserAfterEmailVerification()
    {
        var users = new InMemoryUserStore();
        var emailSender = new CapturingEmailSender();
        var signupSessions = new SignupSessionService(emailSender, new AttemptLimiter());
        var terms = new TermsService();
        var emailController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        EndpointTestHelper.SetForm(emailController.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = "portal-signup@example.com"
        });

        var emailOk = EndpointTestHelper.AssertOk(await emailController.Email());
        string signupCookie = ReadCookie(emailController.Response.Headers.SetCookie.ToString());
        Assert.AreEqual("verification_code_sent", EndpointTestHelper.ReadProperty<string>(emailOk.Value, "result"));
        Assert.AreEqual("portal-signup@example.com", emailSender.LastEmail);
        Assert.IsFalse(string.IsNullOrWhiteSpace(emailSender.LastCode));

        var verifyController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        verifyController.Request.Headers.Cookie = signupCookie;
        EndpointTestHelper.SetForm(verifyController.HttpContext, new Dictionary<string, StringValues>
        {
            ["code"] = emailSender.LastCode
        });

        var verifyOk = EndpointTestHelper.AssertOk(await verifyController.Verify());
        Assert.AreEqual("verified", EndpointTestHelper.ReadProperty<string>(verifyOk.Value, "result"));

        var accountController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        accountController.Request.Headers.Cookie = signupCookie;
        EndpointTestHelper.SetForm(accountController.HttpContext, new Dictionary<string, StringValues>
        {
            ["password"] = "Passw0rd!",
            ["name"] = "Portal Signup",
            ["birthdate"] = "2000-01-02",
            ["terms_accepted"] = "true"
        });

        var accountOk = EndpointTestHelper.AssertOk(await accountController.Account());

        Assert.AreEqual("redirect", EndpointTestHelper.ReadProperty<string>(accountOk.Value, "result"));
        Assert.AreEqual($"{AppConfig.AuthUiBaseUrl}/login", EndpointTestHelper.ReadProperty<string>(accountOk.Value, "redirect_url"));
        Assert.AreEqual($"{AppConfig.AuthUiBaseUrl}/login", accountController.Response.Headers.Location.ToString());
        Assert.AreEqual("Portal Signup", users.Authenticate("portal-signup@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// Purpose: prevent repeated signup verification email sends within the cooldown window.
    /// Input: the same email is submitted to the signup email endpoint twice.
    /// Expected: the second request returns 429 slow_down and no second email is sent.
    /// </summary>
    [TestMethod]
    public async Task PortalSignupEmail_ReturnsTooManyRequestsWhenRepeated()
    {
        var users = new InMemoryUserStore();
        var emailSender = new CapturingEmailSender();
        var signupSessions = new SignupSessionService(
            emailSender,
            new AttemptLimiter(),
            new EmailSendCooldown(TimeSpan.FromMinutes(1)),
            null);
        var terms = new TermsService();
        var controller = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        EndpointTestHelper.SetForm(controller.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = "portal-repeat@example.com"
        });

        _ = EndpointTestHelper.AssertOk(await controller.Email());
        ErrorOutput error = EndpointTestHelper.AssertError(await controller.Email(), 429);

        Assert.AreEqual("00010", error.ResponseCode);
        Assert.AreEqual("slow_down", error.Error);
        Assert.AreEqual("portal-repeat@example.com", emailSender.LastEmail);
        Assert.AreEqual(1, emailSender.SendCount);
    }

    /// <summary>
    /// サインアップのメール送信、コード検証、アカウント作成が別アプリケーションインスタンスで処理されても、Redis共有状態により完了できることを確認する。
    /// </summary>
    [TestMethod]
    public async Task PortalSignupFlow_UsesSharedRedisSessionAcrossInstances()
    {
        var users = new InMemoryUserStore();
        var redis = new FakeRedisStringStore();
        var emailSender = new CapturingEmailSender();
        var terms = new TermsService();
        var emailSessions = new SignupSessionService(emailSender, new AttemptLimiter(redis), redis);
        var verifySessions = new SignupSessionService(emailSender, new AttemptLimiter(redis), redis);
        var accountSessions = new SignupSessionService(emailSender, new AttemptLimiter(redis), redis);
        var emailController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, emailSessions));
        EndpointTestHelper.SetForm(emailController.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = "portal-redis-signup@example.com"
        });
        _ = EndpointTestHelper.AssertOk(await emailController.Email());
        string signupCookie = ReadCookie(emailController.Response.Headers.SetCookie.ToString());

        var verifyController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, verifySessions));
        verifyController.Request.Headers.Cookie = signupCookie;
        EndpointTestHelper.SetForm(verifyController.HttpContext, new Dictionary<string, StringValues>
        {
            ["code"] = emailSender.LastCode
        });
        _ = EndpointTestHelper.AssertOk(await verifyController.Verify());

        var accountController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, accountSessions));
        accountController.Request.Headers.Cookie = signupCookie;
        EndpointTestHelper.SetForm(accountController.HttpContext, new Dictionary<string, StringValues>
        {
            ["password"] = "Passw0rd!",
            ["name"] = "Portal Redis Signup",
            ["birthdate"] = "2000-01-02",
            ["terms_accepted"] = "true"
        });

        var accountOk = EndpointTestHelper.AssertOk(await accountController.Account());

        Assert.AreEqual("redirect", EndpointTestHelper.ReadProperty<string>(accountOk.Value, "result"));
        Assert.AreEqual("Portal Redis Signup", users.Authenticate("portal-redis-signup@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// メール認証が未完了の登録セッションではアカウント作成を拒否することを検証する。
    /// </summary>
    [TestMethod]
    public async Task PortalSignupAccount_ReturnsUnauthorizedBeforeEmailVerification()
    {
        var users = new InMemoryUserStore();
        var emailSender = new CapturingEmailSender();
        var signupSessions = new SignupSessionService(emailSender, new AttemptLimiter());
        var terms = new TermsService();
        var emailController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        EndpointTestHelper.SetForm(emailController.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = "portal-unverified@example.com"
        });
        _ = await emailController.Email();
        string signupCookie = ReadCookie(emailController.Response.Headers.SetCookie.ToString());

        var accountController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        accountController.Request.Headers.Cookie = signupCookie;
        EndpointTestHelper.SetForm(accountController.HttpContext, new Dictionary<string, StringValues>
        {
            ["password"] = "Passw0rd!",
            ["name"] = "Portal Signup",
            ["birthdate"] = "2000-01-02",
            ["terms_accepted"] = "true"
        });

        ErrorOutput error = EndpointTestHelper.AssertError(await accountController.Account(), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// Purpose: verify portal-compatible signup account creation requires explicit terms consent.
    /// Input: verified signup session, password, name, birthdate, and terms_accepted=false.
    /// Expected: 400 invalid_request and no user is created.
    /// </summary>
    [TestMethod]
    public async Task PortalSignupAccount_ReturnsBadRequestWhenTermsAreNotAccepted()
    {
        var users = new InMemoryUserStore();
        var emailSender = new CapturingEmailSender();
        var signupSessions = new SignupSessionService(emailSender, new AttemptLimiter());
        var terms = new TermsService();
        var emailController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        EndpointTestHelper.SetForm(emailController.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = "portal-no-terms@example.com"
        });
        _ = await emailController.Email();
        string signupCookie = ReadCookie(emailController.Response.Headers.SetCookie.ToString());

        var verifyController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        verifyController.Request.Headers.Cookie = signupCookie;
        EndpointTestHelper.SetForm(verifyController.HttpContext, new Dictionary<string, StringValues>
        {
            ["code"] = emailSender.LastCode
        });
        _ = EndpointTestHelper.AssertOk(await verifyController.Verify());

        var accountController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        accountController.Request.Headers.Cookie = signupCookie;
        EndpointTestHelper.SetForm(accountController.HttpContext, new Dictionary<string, StringValues>
        {
            ["password"] = "Passw0rd!",
            ["name"] = "Portal Signup",
            ["birthdate"] = "2000-01-02",
            ["terms_accepted"] = "false"
        });

        ErrorOutput error = EndpointTestHelper.AssertError(await accountController.Account(), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("terms consent is required", error.ErrorDescription);
        Assert.ThrowsExactly<ApiException>(() => users.FindByEmail("portal-no-terms@example.com"));
    }

    /// <summary>
    /// Portal互換のコード確認で誤った認証コードを拒否することを検証する。
    /// </summary>
    [TestMethod]
    public async Task PortalSignupVerify_ReturnsUnauthorizedForWrongCode()
    {
        var users = new InMemoryUserStore();
        var emailSender = new CapturingEmailSender();
        var signupSessions = new SignupSessionService(emailSender, new AttemptLimiter());
        var terms = new TermsService();
        var emailController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        EndpointTestHelper.SetForm(emailController.HttpContext, new Dictionary<string, StringValues>
        {
            ["email"] = "portal-wrong-code@example.com"
        });
        _ = await emailController.Email();
        string signupCookie = ReadCookie(emailController.Response.Headers.SetCookie.ToString());

        var verifyController = EndpointTestHelper.WithHttpContext(new SignupController(users, terms, signupSessions));
        verifyController.Request.Headers.Cookie = signupCookie;
        EndpointTestHelper.SetForm(verifyController.HttpContext, new Dictionary<string, StringValues>
        {
            ["code"] = "000000"
        });

        ErrorOutput error = EndpointTestHelper.AssertError(await verifyController.Verify(), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    private static string ReadCookie(string setCookie)
    {
        int separator = setCookie.IndexOf(';', StringComparison.Ordinal);
        Assert.IsTrue(separator > 0);
        return setCookie[..separator];
    }

    private sealed class CapturingEmailSender : IEmailSender
    {
        public string LastEmail { get; private set; } = string.Empty;
        public string LastCode { get; private set; } = string.Empty;
        public int SendCount { get; private set; }

        public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
        {
            SendCount++;
            LastEmail = email;
            LastCode = code;
        }
    }

    private sealed class FakeRedisStringStore : IRedisStringStore
    {
        private readonly Dictionary<string, StoredValue> _values = new();

        public void SetString(string key, string value, TimeSpan expiresIn)
        {
            _values[key] = new StoredValue(value, DateTimeOffset.UtcNow.Add(expiresIn));
        }

        public bool SetStringIfNotExists(string key, string value, TimeSpan expiresIn)
        {
            if (GetString(key) is not null)
            {
                return false;
            }

            SetString(key, value, expiresIn);
            return true;
        }

        public string? GetString(string key)
        {
            if (!_values.TryGetValue(key, out StoredValue? stored) || stored.ExpiresAt <= DateTimeOffset.UtcNow)
            {
                return null;
            }

            return stored.Value;
        }

        public string? TakeString(string key)
        {
            string? value = GetString(key);
            _ = _values.Remove(key);
            return value;
        }

        public bool DeleteString(string key)
        {
            return _values.Remove(key);
        }
    }

    private sealed record StoredValue(string Value, DateTimeOffset ExpiresAt);
}
