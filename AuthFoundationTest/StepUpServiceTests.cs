using AuthFoundation.Services;
using AuthFoundation.Common;
using System.Collections.Concurrent;
using System.Reflection;

namespace AuthFoundationTest;

[TestClass]
public sealed class StepUpServiceTests
{
    /// <summary>
    /// 目的: Start Email Challenge / Returns Six Digit Code の仕様を検証する。
    /// 入力値: Start Email Challenge / Returns Six Digit Code を確認するためにテスト内で作成したデータ。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void StartEmailChallenge_ReturnsSixDigitCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-code@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-code@example.com");

        Assert.AreEqual(6, challenge.Code.Length);
        StringAssert.Matches(challenge.Code, new System.Text.RegularExpressions.Regex("^[0-9]{6}$"));
    }

    /// <summary>
    /// 目的: Start Email Challenge / Sends Mfa Code の仕様を検証する。
    /// 入力値: Start Email Challenge / Sends Mfa Code を確認するためにテスト内で作成したデータ。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void StartEmailChallenge_SendsMfaCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-send@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var sender = new RecordingEmailSender();
        var stepUp = new StepUpService(users, sender, new AttemptLimiter());

        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-send@example.com");

        Assert.AreEqual(1, sender.SentMessages.Count);
        Assert.AreEqual(challenge.Email, sender.SentMessages[0].Email);
        Assert.AreEqual(challenge.Code, sender.SentMessages[0].Code);
        Assert.AreEqual(challenge.ExpiresAt, sender.SentMessages[0].ExpiresAt);
    }

    /// <summary>
    /// 目的: Verify Email Challenge / Returns Step Up Grant の仕様を検証する。
    /// 入力値: Verify Email Challenge / Returns Step Up Grant を確認するためにテスト内で作成したデータ。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_ReturnsStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa@example.com");
        StepUpGrant grant = stepUp.VerifyEmailChallenge("mfa@example.com", challenge.Code);

        Assert.AreEqual("email_code", grant.Method);
        Assert.IsTrue(grant.StepUpToken.StartsWith("sup_"));
    }

    /// <summary>
    /// 目的: Verify Email Challenge / Rejects Wrong Code の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_RejectsWrongCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-wrong@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        stepUp.StartEmailChallenge("mfa-wrong@example.com");

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-wrong@example.com", "000000"));
    }

    /// <summary>
    /// 目的: Verify Email Challenge / Blocks After Repeated Wrong Codes の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_BlocksAfterRepeatedWrongCodes()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-limit@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var sendCooldown = new EmailSendCooldown(TimeSpan.FromMinutes(1), clock, null);
        var stepUp = new StepUpService(users, new RecordingEmailSender(), new AttemptLimiter(1, TimeSpan.FromMinutes(5)), sendCooldown, null);
        stepUp.StartEmailChallenge("mfa-limit@example.com");
        Assert.ThrowsExactly<ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-limit@example.com", "000000"));
        clock.Advance(TimeSpan.FromMinutes(1));
        MfaEmailChallenge secondChallenge = stepUp.StartEmailChallenge("mfa-limit@example.com");

        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-limit@example.com", secondChallenge.Code));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Verify Email Challenge / Rejects Expired Code の仕様を検証する。
    /// 入力値: 期限切れに変更したテストデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_RejectsExpiredCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-expired@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        EmailChallenges(stepUp)["mfa-expired@example.com"] = new MfaEmailChallenge(
            "mfa-expired@example.com",
            "123456",
            DateTimeOffset.UtcNow.AddSeconds(-1));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-expired@example.com", "123456"));
    }

    /// <summary>
    /// 目的: Setup Authenticator / Returns Setup With Valid Step Up の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: Setup Authenticator / Returns Setup With Valid Step Up の期待結果になること。
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsSetupWithValidStepUp()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-setup@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "totp-setup@example.com");

        AuthenticatorSetup setup = stepUp.SetupAuthenticator("totp-setup@example.com", grant.StepUpToken);

        Assert.AreEqual("totp-setup@example.com", setup.Email);
        Assert.IsFalse(string.IsNullOrWhiteSpace(setup.Secret));
        Assert.IsTrue(setup.OtpAuthUri.StartsWith("otpauth://totp/", StringComparison.Ordinal));
    }

    /// <summary>
    /// 目的: Setup Authenticator / Rejects Unknown Step Up Token の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_RejectsUnknownStepUpToken()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-unknown-token@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        Assert.ThrowsExactly<ApiException>(
            () => stepUp.SetupAuthenticator("totp-unknown-token@example.com", "sup_missing"));
    }

    /// <summary>
    /// 目的: Setup Authenticator / Rejects Step Up Subject Mismatch の仕様を検証する。
    /// 入力値: Setup Authenticator / Rejects Step Up Subject Mismatch を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_RejectsStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-owner@example.com", "Passw0rd!", "Totp Owner", new DateOnly(2000, 1, 1));
        users.CreateUser("totp-other@example.com", "Passw0rd!", "Totp Other", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "totp-other@example.com");

        Assert.ThrowsExactly<ApiException>(
            () => stepUp.SetupAuthenticator("totp-owner@example.com", grant.StepUpToken));
    }

    /// <summary>
    /// 目的: Verify Authenticator / Returns Step Up Grant の仕様を検証する。
    /// 入力値: Verify Authenticator / Returns Step Up Grant を確認するためにテスト内で作成したデータ。
    /// 期待値: Verify Authenticator / Returns Step Up Grant の期待結果になること。
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant setupGrant = IssueEmailStepUp(stepUp, "totp@example.com");

        AuthenticatorSetup setup = stepUp.SetupAuthenticator("totp@example.com", setupGrant.StepUpToken);
        string code = AuthFoundation.Common.TotpUtil.GenerateCode(setup.Secret, DateTimeOffset.UtcNow);
        StepUpGrant grant = stepUp.VerifyAuthenticator("totp@example.com", code);

        Assert.AreEqual("totp", grant.Method);
    }

    /// <summary>
    /// 目的: Verify Authenticator / Rejects Missing Setup の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_RejectsMissingSetup()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-missing@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyAuthenticator("totp-missing@example.com", "000000"));
    }

    /// <summary>
    /// TOTP検証が連続失敗後に正しいコードも拒否することを確認する。
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_BlocksAfterRepeatedWrongCodes()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-limit@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users, new RecordingEmailSender(), new AttemptLimiter(1, TimeSpan.FromMinutes(5)));
        StepUpGrant setupGrant = IssueEmailStepUp(stepUp, "totp-limit@example.com");
        AuthenticatorSetup setup = stepUp.SetupAuthenticator("totp-limit@example.com", setupGrant.StepUpToken);
        Assert.ThrowsExactly<ApiException>(
            () => stepUp.VerifyAuthenticator("totp-limit@example.com", "000000"));
        string validCode = TotpUtil.GenerateCode(setup.Secret, DateTimeOffset.UtcNow);

        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => stepUp.VerifyAuthenticator("totp-limit@example.com", validCode));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Validate Step Up Token / Returns Known Grant の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: トークンレスポンスと保存状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_ReturnsKnownGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-token@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-token@example.com");
        StepUpGrant grant = stepUp.VerifyEmailChallenge("mfa-token@example.com", challenge.Code);

        StepUpGrant found = stepUp.ValidateStepUpToken(grant.StepUpToken);

        Assert.AreEqual(grant.StepUpToken, found.StepUpToken);
    }

    /// <summary>
    /// メールコード検証で発行した強化認可トークンを、別アプリケーションインスタンスからRedis共有状態で検証できることを確認する。
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_UsesSharedRedisGrantAcrossInstances()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-redis-token@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var redis = new FakeRedisStringStore();
        var sender = new RecordingEmailSender();
        var issuer = new StepUpService(users, sender, new AttemptLimiter(), redis);
        var verifier = new StepUpService(users, sender, new AttemptLimiter(), redis);

        MfaEmailChallenge challenge = issuer.StartEmailChallenge("mfa-redis-token@example.com");
        StepUpGrant grant = issuer.VerifyEmailChallenge("mfa-redis-token@example.com", challenge.Code);
        StepUpGrant found = verifier.ValidateStepUpToken(grant.StepUpToken);

        Assert.AreEqual(grant.StepUpToken, found.StepUpToken);
        Assert.AreEqual(grant.Subject, found.Subject);
        Assert.AreEqual("email_code", found.Method);
    }

    /// <summary>
    /// 目的: Validate Step Up Token / Rejects Unknown Token の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_RejectsUnknownToken()
    {
        var stepUp = new StepUpService(new InMemoryUserStore());

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.ValidateStepUpToken("sup_missing"));
    }

    /// <summary>
    /// 目的: Validate Step Up Token / Rejects Expired Token の仕様を検証する。
    /// 入力値: 期限切れに変更したテストデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_RejectsExpiredToken()
    {
        var stepUp = new StepUpService(new InMemoryUserStore());
        StepUpGrants(stepUp)["sup_expired"] = new StepUpGrant(
            "sup_expired",
            "expired_subject",
            "email_code",
            DateTimeOffset.UtcNow.AddSeconds(-1));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.ValidateStepUpToken("sup_expired"));
    }

    private static ConcurrentDictionary<string, MfaEmailChallenge> EmailChallenges(StepUpService service)
    {
        return GetField<ConcurrentDictionary<string, MfaEmailChallenge>>(service, "_emailChallenges");
    }

    private static ConcurrentDictionary<string, StepUpGrant> StepUpGrants(StepUpService service)
    {
        return GetField<ConcurrentDictionary<string, StepUpGrant>>(service, "_stepUpGrants");
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }

    private static T GetField<T>(StepUpService service, string name)
    {
        FieldInfo? field = typeof(StepUpService).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.IsNotNull(field);
        object? value = field.GetValue(service);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }

    private sealed class RecordingEmailSender : IEmailSender
    {
        public List<SentMfaCode> SentMessages { get; } = new();

        public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
        {
            SentMessages.Add(new SentMfaCode(email, code, expiresAt));
        }
    }

    private sealed record SentMfaCode(string Email, string Code, DateTimeOffset ExpiresAt);

    private sealed class ManualTimeProvider : TimeProvider
    {
        private DateTimeOffset _utcNow;

        public ManualTimeProvider(DateTimeOffset utcNow)
        {
            _utcNow = utcNow;
        }

        public override DateTimeOffset GetUtcNow()
        {
            return _utcNow;
        }

        public void Advance(TimeSpan duration)
        {
            _utcNow = _utcNow.Add(duration);
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
