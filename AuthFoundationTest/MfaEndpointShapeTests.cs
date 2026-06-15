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
    /// 逶ｮ逧・ Start Email / Returns Challenge Without Code Exposure 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Start Email / Returns Challenge Without Code Exposure 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝蛾未騾｣縺ｮ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ迥ｶ諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
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
    /// 逶ｮ逧・ Start Email / Returns Bad Request For Invalid Email 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Verify Email / Returns Step Up Token For Challenge Code 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Verify Email / Returns Step Up Token For Challenge Code 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝蛾未騾｣縺ｮ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ迥ｶ諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void VerifyEmail_ReturnsStepUpTokenForChallengeCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = TestServices.CreateStepUpService(users);
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
    /// 逶ｮ逧・ Verify Email / Returns Unauthorized For Wrong Code 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyEmail_ReturnsUnauthorizedForWrongCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = TestServices.CreateStepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        stepUp.StartEmailChallenge(MfaEmail);

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.VerifyEmail(new VerifyRequest(MfaEmail, "000000")),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Setup Authenticator / Returns Secret And Otp Auth Uri 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Setup Authenticator / Returns Secret And Otp Auth Uri 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Setup Authenticator / Returns Secret And Otp Auth Uri 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsSecretAndOtpAuthUri()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = TestServices.CreateStepUpService(users);
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
    /// 逶ｮ逧・ Setup Authenticator / Returns Bad Request For Invalid Email 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Setup Authenticator / Returns Bad Request For Missing Step Up Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Setup Authenticator / Returns Unauthorized For Step Up Subject Mismatch 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Setup Authenticator / Returns Unauthorized For Step Up Subject Mismatch 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsUnauthorizedForStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-owner@example.com", "Passw0rd!", "Totp Owner", new DateOnly(2000, 1, 1));
        users.CreateUser("totp-other@example.com", "Passw0rd!", "Totp Other", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        StepUpGrant grant = IssueEmailStepUp(stepUp, "totp-other@example.com");

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.SetupAuthenticator(new SetupAuthenticatorRequest("totp-owner@example.com", grant.StepUpToken)),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Authenticator / Returns Step Up Token For Valid Totp 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝茨ｿｽE繧ｯ繝ｳ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ菫晏ｭ倡憾諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsStepUpTokenForValidTotp()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = TestServices.CreateStepUpService(users);
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
    /// 逶ｮ逧・ Verify Authenticator / Returns Unauthorized When Not Setup 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Verify Authenticator / Returns Unauthorized When Not Setup 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
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
    /// 逶ｮ逧・ Verify Authenticator / Returns Unauthorized For Wrong Code 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsUnauthorizedForWrongCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = TestServices.CreateStepUpService(users);
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
        var redis = TestServices.CreateRedis();
        var stepUp = TestServices.CreateStepUpService(
            users,
            new DevelopmentEmailSender(),
            TestServices.CreateAttemptLimiter(),
            TestServices.CreateEmailSendCooldown(TimeSpan.FromMinutes(1)),
            redis);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));

        _ = EndpointTestHelper.AssertOk(controller.StartEmail(new EmailRequest(MfaEmail)));
        ErrorOutput error = EndpointTestHelper.AssertError(controller.StartEmail(new EmailRequest(MfaEmail)), 429);

        Assert.AreEqual("00010", error.ResponseCode);
        Assert.AreEqual("slow_down", error.Error);
    }

    private static MfaController CreateController(InMemoryUserStore? users = null)
    {
        return EndpointTestHelper.WithHttpContext(new MfaController(TestServices.CreateStepUpService(users ?? new InMemoryUserStore())));
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
