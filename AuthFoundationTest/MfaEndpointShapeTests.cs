using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class MfaEndpointShapeTests
{
    private const string MfaEmail = "mfa-endpoint@example.com";
    private const string MfaPassword = "Passw0rd!";

    /// <summary>
    /// 目的: Start Email / Returns Challenge Without Code Exposure の仕様を検証する。
    /// 入力値: Start Email / Returns Challenge Without Code Exposure を確認するためにテスト内で作成したデータ。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void StartEmail_ReturnsChallengeWithoutCodeExposure()
    {
        var controller = CreateController(CreateUsers(MfaEmail));

        var ok = EndpointTestHelper.AssertOk(controller.StartEmail(new EmailRequest(MfaEmail)));

        Assert.IsNotNull(ok.Value);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("challenge_created", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("email", EndpointTestHelper.ReadProperty<string>(ok.Value, "delivery"));
        Assert.AreEqual(MfaEmail, EndpointTestHelper.ReadProperty<string>(ok.Value, "email"));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<DateTimeOffset>(ok.Value, "expires_at") > DateTimeOffset.UtcNow);
        Assert.IsNull(ok.Value.GetType().GetProperty("code"));
    }

    /// <summary>
    /// 目的: Start Email / Returns Bad Request For Invalid Email の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void StartEmail_ReturnsBadRequestForInvalidEmail()
    {
        var controller = CreateController();

        ErrorOutput error = EndpointTestHelper.AssertError(controller.StartEmail(new EmailRequest("invalid")), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Verify Email / Returns Step Up Token For Challenge Code の仕様を検証する。
    /// 入力値: Verify Email / Returns Step Up Token For Challenge Code を確認するためにテスト内で作成したデータ。
    /// 期待値: メールコード関連のレスポンスと状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void VerifyEmail_ReturnsStepUpTokenForChallengeCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(MfaEmail);

        var ok = EndpointTestHelper.AssertOk(controller.VerifyEmail(new VerifyRequest(MfaEmail, challenge.Code)));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "step_up_token").StartsWith("sup_", StringComparison.Ordinal));
        Assert.AreEqual("StepUp", EndpointTestHelper.ReadProperty<string>(ok.Value, "token_type"));
        Assert.AreEqual("email_code", EndpointTestHelper.ReadProperty<string>(ok.Value, "method"));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<DateTimeOffset>(ok.Value, "expires_at") > DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 目的: Verify Email / Returns Unauthorized For Wrong Code の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void VerifyEmail_ReturnsUnauthorizedForWrongCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        stepUp.StartEmailChallenge(MfaEmail);

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.VerifyEmail(new VerifyRequest(MfaEmail, "000000")),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Setup Authenticator / Returns Secret And Otp Auth Uri の仕様を検証する。
    /// 入力値: Setup Authenticator / Returns Secret And Otp Auth Uri を確認するためにテスト内で作成したデータ。
    /// 期待値: Setup Authenticator / Returns Secret And Otp Auth Uri の期待結果になること。
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsSecretAndOtpAuthUri()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        StepUpGrant grant = IssueEmailStepUp(stepUp, MfaEmail);

        var ok = EndpointTestHelper.AssertOk(controller.SetupAuthenticator(
            new SetupAuthenticatorRequest(MfaEmail, grant.StepUpToken)));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual(MfaEmail, EndpointTestHelper.ReadProperty<string>(ok.Value, "email"));
        Assert.IsFalse(string.IsNullOrWhiteSpace(EndpointTestHelper.ReadProperty<string>(ok.Value, "secret")));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "otpauth_uri").StartsWith("otpauth://totp/", StringComparison.Ordinal));
    }

    /// <summary>
    /// 目的: Setup Authenticator / Returns Bad Request For Invalid Email の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsBadRequestForInvalidEmail()
    {
        var controller = CreateController();

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.SetupAuthenticator(new SetupAuthenticatorRequest("invalid", "sup_missing")),
            400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Setup Authenticator / Returns Bad Request For Missing Step Up Token の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 400 Bad Request 相当のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsBadRequestForMissingStepUpToken()
    {
        var controller = CreateController(CreateUsers(MfaEmail));

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.SetupAuthenticator(new SetupAuthenticatorRequest(MfaEmail, string.Empty)),
            400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("step_up_token is required", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Setup Authenticator / Returns Unauthorized For Step Up Subject Mismatch の仕様を検証する。
    /// 入力値: Setup Authenticator / Returns Unauthorized For Step Up Subject Mismatch を確認するためにテスト内で作成したデータ。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsUnauthorizedForStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-owner@example.com", "Passw0rd!", "Totp Owner", new DateOnly(2000, 1, 1));
        users.CreateUser("totp-other@example.com", "Passw0rd!", "Totp Other", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        StepUpGrant grant = IssueEmailStepUp(stepUp, "totp-other@example.com");

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.SetupAuthenticator(new SetupAuthenticatorRequest("totp-owner@example.com", grant.StepUpToken)),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Verify Authenticator / Returns Step Up Token For Valid Totp の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: トークンレスポンスと保存状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsStepUpTokenForValidTotp()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        StepUpGrant grant = IssueEmailStepUp(stepUp, MfaEmail);
        AuthenticatorSetup setup = stepUp.SetupAuthenticator(MfaEmail, grant.StepUpToken);
        string code = TotpUtil.GenerateCode(setup.Secret, DateTimeOffset.UtcNow);

        var ok = EndpointTestHelper.AssertOk(controller.VerifyAuthenticator(new VerifyRequest(MfaEmail, code)));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "step_up_token").StartsWith("sup_", StringComparison.Ordinal));
        Assert.AreEqual("totp", EndpointTestHelper.ReadProperty<string>(ok.Value, "method"));
    }

    /// <summary>
    /// 目的: Verify Authenticator / Returns Unauthorized When Not Setup の仕様を検証する。
    /// 入力値: Verify Authenticator / Returns Unauthorized When Not Setup を確認するためにテスト内で作成したデータ。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsUnauthorizedWhenNotSetup()
    {
        var controller = CreateController(CreateUsers(MfaEmail));

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.VerifyAuthenticator(new VerifyRequest(MfaEmail, "000000")),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Verify Authenticator / Returns Unauthorized For Wrong Code の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsUnauthorizedForWrongCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        StepUpGrant grant = IssueEmailStepUp(stepUp, MfaEmail);
        stepUp.SetupAuthenticator(MfaEmail, grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.VerifyAuthenticator(new VerifyRequest(MfaEmail, "000000")),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// Purpose: prevent repeated MFA email sends within the cooldown window.
    /// Input: the same login email is submitted to the MFA email start endpoint twice.
    /// Expected: the second request returns 429 slow_down.
    /// </summary>
    [TestMethod]
    public void StartEmail_ReturnsTooManyRequestsWhenRepeated()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(
            users,
            new DevelopmentEmailSender(),
            new AttemptLimiter(),
            new EmailSendCooldown(TimeSpan.FromMinutes(1)),
            null);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));

        _ = EndpointTestHelper.AssertOk(controller.StartEmail(new EmailRequest(MfaEmail)));
        ErrorOutput error = EndpointTestHelper.AssertError(controller.StartEmail(new EmailRequest(MfaEmail)), 429);

        Assert.AreEqual("00010", error.ResponseCode);
        Assert.AreEqual("slow_down", error.Error);
    }

    private static MfaController CreateController(InMemoryUserStore? users = null)
    {
        return EndpointTestHelper.WithHttpContext(new MfaController(new StepUpService(users ?? new InMemoryUserStore())));
    }

    private static InMemoryUserStore CreateUsers(params string[] emails)
    {
        var users = new InMemoryUserStore();
        foreach (string email in emails)
        {
            string subject = "subject_" + email.Replace("@", "_", StringComparison.Ordinal).Replace(".", "_", StringComparison.Ordinal);
            users.CreateUser(email, MfaPassword, "Mfa User", new DateOnly(2000, 1, 1), subject);
        }

        return users;
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }
}
