using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetEndpointShapeTests
{
    /// <summary>
    /// 目的: パスワードリセット開始時に、メールアドレスと生年月日が一致する利用者へ認証コードを送信することを検証する。
    /// 入力値: 登録済みメールアドレス、登録済み生年月日。
    /// 期待値: 200 OK と reset_challenge_started を返し、認証コードを1通だけ送信すること。
    /// </summary>
    [TestMethod]
    public void StartReset_SendsEmailCodeWhenEmailAndBirthDateMatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-start@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var controller = CreateController(users, new StepUpService(users, emailSender, new AttemptLimiter()));
        var request = new ResetPasswordStartRequest("reset-start@example.com", "2000-01-02");

        var ok = EndpointTestHelper.AssertOk(controller.StartReset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("reset_challenge_started", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("email", EndpointTestHelper.ReadProperty<string>(ok.Value, "delivery"));
        Assert.AreEqual(1, emailSender.SentCodes.Count);
        Assert.AreEqual("reset-start@example.com", emailSender.SentCodes[0].Email);
        Assert.IsTrue(emailSender.SentCodes[0].ExpiresAt > DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 目的: 生年月日が一致しないパスワードリセット開始要求で、アカウント状態を露出しないことを検証する。
    /// 入力値: 登録済みメールアドレス、不一致の生年月日。
    /// 期待値: 200 OK と通常の開始レスポンスを返すが、認証コードを送信しないこと。
    /// </summary>
    [TestMethod]
    public void StartReset_DoesNotSendEmailCodeForMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-start-mismatch@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var controller = CreateController(users, new StepUpService(users, emailSender, new AttemptLimiter()));
        var request = new ResetPasswordStartRequest("reset-start-mismatch@example.com", "2001-01-02");

        var ok = EndpointTestHelper.AssertOk(controller.StartReset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("reset_challenge_started", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual(0, emailSender.SentCodes.Count);
    }

    /// <summary>
    /// 目的: 存在しないメールアドレスのパスワードリセット開始要求で、アカウント有無を露出しないことを検証する。
    /// 入力値: 未登録メールアドレス、生年月日。
    /// 期待値: 200 OK と通常の開始レスポンスを返すが、認証コードを送信しないこと。
    /// </summary>
    [TestMethod]
    public void StartReset_DoesNotRevealUnknownEmail()
    {
        var users = new InMemoryUserStore();
        var emailSender = new RecordingEmailSender();
        var controller = CreateController(users, new StepUpService(users, emailSender, new AttemptLimiter()));
        var request = new ResetPasswordStartRequest("unknown-reset@example.com", "2001-01-02");

        var ok = EndpointTestHelper.AssertOk(controller.StartReset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("reset_challenge_started", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual(0, emailSender.SentCodes.Count);
    }

    /// <summary>
    /// 目的: パスワードリセット開始要求の生年月日形式検証を確認する。
    /// 入力値: yyyy-MM-dd ではない生年月日。
    /// 期待値: 400 Bad Request と invalid_request を返すこと。
    /// </summary>
    [TestMethod]
    public void StartReset_ReturnsBadRequestForInvalidBirthDateFormat()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new StepUpService(users));
        var request = new ResetPasswordStartRequest("reset-format@example.com", "2000-13-40");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.StartReset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("some of the input values are incorrect", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: メールコードと生年月日が一致する場合に、パスワードリセットが完了することを検証する。
    /// 入力値: 登録済みメールアドレス、登録済み生年月日、発行済みメールコード、新しいパスワード。
    /// 期待値: 200 OK と password_reset を返し、新しいパスワードで認証できること。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsPasswordResetForMatchingBirthDateAndEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-endpoint@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var stepUp = new StepUpService(users, emailSender, new AttemptLimiter());
        var controller = CreateController(users, stepUp);
        _ = EndpointTestHelper.AssertOk(controller.StartReset(new ResetPasswordStartRequest("reset-endpoint@example.com", "2000-01-02")));
        var request = new ResetPasswordRequest("reset-endpoint@example.com", "2000-01-02", emailSender.SentCodes[0].Code, "Newpass1!");

        var ok = EndpointTestHelper.AssertOk(controller.Reset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("password_reset", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("Reset User", users.Authenticate("reset-endpoint@example.com", "Newpass1!").Name);
    }

    /// <summary>
    /// パスワードリセット開始と完了が別アプリケーションインスタンスで処理されても、Redis共有状態によりメールコードを検証できることを確認する。
    /// </summary>
    [TestMethod]
    public void Reset_UsesSharedRedisEmailChallengeAcrossInstances()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-redis@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var redis = new FakeRedisStringStore();
        var sender = new RecordingEmailSender();
        var startController = CreateController(users, new StepUpService(users, sender, new AttemptLimiter(), redis));
        var resetController = CreateController(users, new StepUpService(users, sender, new AttemptLimiter(), redis));

        _ = EndpointTestHelper.AssertOk(startController.StartReset(new ResetPasswordStartRequest("reset-redis@example.com", "2000-01-02")));
        var request = new ResetPasswordRequest("reset-redis@example.com", "2000-01-02", sender.SentCodes[0].Code, "Newpass1!");

        var ok = EndpointTestHelper.AssertOk(resetController.Reset(request));

        Assert.AreEqual("password_reset", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("Reset User", users.Authenticate("reset-redis@example.com", "Newpass1!").Name);
    }

    /// <summary>
    /// 目的: MFA用メールコードをパスワードリセット用コードとして流用できないことを検証する。
    /// 入力値: MFA開始で発行されたメールコード、登録済みメールアドレス、生年月日、新しいパスワード。
    /// 期待値: 401 Unauthorized を返し、既存パスワードが維持されること。
    /// </summary>
    [TestMethod]
    public void Reset_RejectsMfaEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-mfa-code@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = new StepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-mfa-code@example.com");
        var request = new ResetPasswordRequest("reset-mfa-code@example.com", "2000-01-02", challenge.Code, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-mfa-code@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// 目的: パスワードリセット完了要求の生年月日形式検証を確認する。
    /// 入力値: yyyy-MM-dd ではない生年月日。
    /// 期待値: 400 Bad Request と invalid_request を返すこと。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForInvalidBirthDateFormat()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new StepUpService(users));
        var request = new ResetPasswordRequest("reset-format@example.com", "2000-13-40", "123456", "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("some of the input values are incorrect", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: パスワードリセット完了要求でメールコードが必須であることを検証する。
    /// 入力値: 空のメールコード。
    /// 期待値: 400 Bad Request と email_code is required を返すこと。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForMissingEmailCode()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new StepUpService(users));
        var request = new ResetPasswordRequest("reset-missing-code@example.com", "1990-01-01", string.Empty, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email_code is required", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: 生年月日が一致しない場合に、パスワードが変更されないことを検証する。
    /// 入力値: 登録済みメールアドレス、不一致の生年月日、正しいメールコード、新しいパスワード。
    /// 期待値: 401 Unauthorized を返し、旧パスワードで引き続き認証できること。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsUnauthorizedForMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-mismatch@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var stepUp = new StepUpService(users, emailSender, new AttemptLimiter());
        var controller = CreateController(users, stepUp);
        _ = EndpointTestHelper.AssertOk(controller.StartReset(new ResetPasswordStartRequest("reset-mismatch@example.com", "2000-01-02")));
        var request = new ResetPasswordRequest("reset-mismatch@example.com", "2001-01-02", emailSender.SentCodes[0].Code, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-mismatch@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// 目的: メールコードが一致しない場合に、パスワードが変更されないことを検証する。
    /// 入力値: 登録済みメールアドレス、登録済み生年月日、不一致のメールコード、新しいパスワード。
    /// 期待値: 401 Unauthorized を返し、旧パスワードで引き続き認証できること。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsUnauthorizedForWrongEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-wrong-code@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var stepUp = new StepUpService(users, emailSender, new AttemptLimiter());
        var controller = CreateController(users, stepUp);
        _ = EndpointTestHelper.AssertOk(controller.StartReset(new ResetPasswordStartRequest("reset-wrong-code@example.com", "2000-01-02")));
        var request = new ResetPasswordRequest("reset-wrong-code@example.com", "2000-01-02", DifferentCode(emailSender.SentCodes[0].Code), "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-wrong-code@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// 目的: 新しいパスワードがポリシーを満たさない場合に、パスワードリセットを拒否することを検証する。
    /// 入力値: 弱い新パスワード。
    /// 期待値: 400 Bad Request と password is invalid を返すこと。
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForWeakNewPassword()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new StepUpService(users));
        var request = new ResetPasswordRequest("reset-weak@example.com", "2000-01-02", "123456", "weak");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("password is invalid", error.ErrorDescription);
    }

    private static PasswordController CreateController(InMemoryUserStore users, StepUpService stepUp)
    {
        return EndpointTestHelper.WithHttpContext(new PasswordController(users, stepUp));
    }

    private static string DifferentCode(string code)
    {
        return string.Equals(code, "000000", StringComparison.Ordinal) ? "000001" : "000000";
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public List<SentEmailCode> SentCodes { get; } = [];

        public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
        {
            SentCodes.Add(new SentEmailCode(email, code, expiresAt));
        }
    }

    private sealed record SentEmailCode(string Email, string Code, DateTimeOffset ExpiresAt);

    private sealed class FakeRedisStringStore : IRedisStringStore
    {
        private readonly Dictionary<string, StoredValue> _values = new();

        public void SetString(string key, string value, TimeSpan expiresIn)
        {
            _values[key] = new StoredValue(value, DateTimeOffset.UtcNow.Add(expiresIn));
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
