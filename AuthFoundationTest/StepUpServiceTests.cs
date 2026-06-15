using AuthFoundation.Services;
using AuthFoundation.Common;
using AuthFoundation.Session;

namespace AuthFoundationTest;

[TestClass]
public sealed class StepUpServiceTests
{
    /// <summary>
    /// 逶ｮ逧・ Start Email Challenge / Returns Six Digit Code 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Start Email Challenge / Returns Six Digit Code 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝蛾未騾｣縺ｮ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ迥ｶ諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void StartEmailChallenge_ReturnsSixDigitCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-code@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);

        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-code@example.com");

        Assert.AreEqual(6, challenge.Code.Length);
        StringAssert.Matches(challenge.Code, new System.Text.RegularExpressions.Regex("^[0-9]{6}$"));
    }

    /// <summary>
    /// 逶ｮ逧・ Start Email Challenge / Sends Mfa Code 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Start Email Challenge / Sends Mfa Code 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝蛾未騾｣縺ｮ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ迥ｶ諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void StartEmailChallenge_SendsMfaCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-send@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var sender = new RecordingEmailSender();
        var stepUp = TestServices.CreateStepUpService(users, sender);

        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-send@example.com");

        Assert.AreEqual(1, sender.SentMessages.Count);
        Assert.AreEqual(challenge.Email, sender.SentMessages[0].Email);
        Assert.AreEqual(challenge.Code, sender.SentMessages[0].Code);
        Assert.AreEqual(challenge.ExpiresAt, sender.SentMessages[0].ExpiresAt);
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Email Challenge / Returns Step Up Grant 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Verify Email Challenge / Returns Step Up Grant 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝蛾未騾｣縺ｮ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ迥ｶ諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_ReturnsStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);

        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa@example.com");
        StepUpGrant grant = stepUp.VerifyEmailChallenge("mfa@example.com", challenge.Code);

        Assert.AreEqual("email_code", grant.Method);
        Assert.IsTrue(grant.StepUpToken.StartsWith("sup_"));
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Email Challenge / Rejects Wrong Code 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_RejectsWrongCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-wrong@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        stepUp.StartEmailChallenge("mfa-wrong@example.com");

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-wrong@example.com", "000000"));
    }

    [TestMethod]
    public void VerifyEmailChallenge_AllowsCorrectCodeAfterWrongAttempt()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-retry@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-retry@example.com");

        Assert.ThrowsExactly<ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-retry@example.com", DifferentCode(challenge.Code)));
        StepUpGrant grant = stepUp.VerifyEmailChallenge("mfa-retry@example.com", challenge.Code);

        Assert.AreEqual("email_code", grant.Method);
    }

    [TestMethod]
    public void VerifyPasswordResetChallenge_AllowsCorrectCodeAfterWrongAttempt()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-retry@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 1));
        var sender = new RecordingEmailSender();
        var stepUp = TestServices.CreateStepUpService(users, sender);

        Assert.IsTrue(stepUp.TryStartPasswordResetChallenge("reset-retry@example.com", new DateOnly(2000, 1, 1)));
        string code = sender.SentMessages[0].Code;

        Assert.ThrowsExactly<ApiException>(
            () => stepUp.VerifyPasswordResetChallenge("reset-retry@example.com", DifferentCode(code)));
        stepUp.VerifyPasswordResetChallenge("reset-retry@example.com", code);
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Email Challenge / Blocks After Repeated Wrong Codes 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝蛾未騾｣縺ｮ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ迥ｶ諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_BlocksAfterRepeatedWrongCodes()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-limit@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var redis = TestServices.CreateRedis();
        var sendCooldown = TestServices.CreateEmailSendCooldown(TimeSpan.FromMilliseconds(1));
        var stepUp = TestServices.CreateStepUpService(
            users,
            new RecordingEmailSender(),
            TestServices.CreateAttemptLimiter(1, TimeSpan.FromMinutes(5)),
            sendCooldown,
            redis);
        stepUp.StartEmailChallenge("mfa-limit@example.com");
        Assert.ThrowsExactly<ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-limit@example.com", "000000"));
        Thread.Sleep(10);
        MfaEmailChallenge secondChallenge = stepUp.StartEmailChallenge("mfa-limit@example.com");

        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-limit@example.com", secondChallenge.Code));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Email Challenge / Rejects Expired Code 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 譛滄剞蛻・・ｽ・ｽ縺ｫ螟画峩縺励◆繝・・ｽ・ｽ繝医ョ繝ｼ繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_RejectsExpiredCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-expired@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var redis = TestServices.CreateRedis();
        redis.SetString(
            MfaEmailChallengeSession.GetRedisKey("mfa-expired@example.com"),
            RedisSessionJson.Serialize(new MfaEmailChallengeSession
            {
                Email = "mfa-expired@example.com",
                Code = "123456",
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1)
            }),
            TimeSpan.FromMinutes(1));
        var stepUp = TestServices.CreateStepUpService(
            users,
            new RecordingEmailSender(),
            TestServices.CreateAttemptLimiter(),
            redis);

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-expired@example.com", "123456"));
    }

    /// <summary>
    /// 逶ｮ逧・ Setup Authenticator / Returns Setup With Valid Step Up 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Setup Authenticator / Returns Setup With Valid Step Up 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsSetupWithValidStepUp()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-setup@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "totp-setup@example.com");

        AuthenticatorSetup setup = stepUp.SetupAuthenticator("totp-setup@example.com", grant.StepUpToken);

        Assert.AreEqual("totp-setup@example.com", setup.Email);
        Assert.IsFalse(string.IsNullOrWhiteSpace(setup.Secret));
        Assert.IsTrue(setup.OtpAuthUri.StartsWith("otpauth://totp/", StringComparison.Ordinal));
    }

    /// <summary>
    /// 逶ｮ逧・ Setup Authenticator / Rejects Unknown Step Up Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_RejectsUnknownStepUpToken()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-unknown-token@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);

        Assert.ThrowsExactly<ApiException>(
            () => stepUp.SetupAuthenticator("totp-unknown-token@example.com", "sup_missing"));
    }

    /// <summary>
    /// 逶ｮ逧・ Setup Authenticator / Rejects Step Up Subject Mismatch 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Setup Authenticator / Rejects Step Up Subject Mismatch 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_RejectsStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-owner@example.com", "Passw0rd!", "Totp Owner", new DateOnly(2000, 1, 1));
        users.CreateUser("totp-other@example.com", "Passw0rd!", "Totp Other", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "totp-other@example.com");

        Assert.ThrowsExactly<ApiException>(
            () => stepUp.SetupAuthenticator("totp-owner@example.com", grant.StepUpToken));
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Authenticator / Returns Step Up Grant 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Verify Authenticator / Returns Step Up Grant 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Verify Authenticator / Returns Step Up Grant 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant setupGrant = IssueEmailStepUp(stepUp, "totp@example.com");

        AuthenticatorSetup setup = stepUp.SetupAuthenticator("totp@example.com", setupGrant.StepUpToken);
        string code = AuthFoundation.Common.TotpUtil.GenerateCode(setup.Secret, DateTimeOffset.UtcNow);
        StepUpGrant grant = stepUp.VerifyAuthenticator("totp@example.com", code);

        Assert.AreEqual("totp", grant.Method);
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Authenticator / Rejects Missing Setup 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_RejectsMissingSetup()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-missing@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyAuthenticator("totp-missing@example.com", "000000"));
    }

    /// <summary>
    /// TOTP讀懆ｨｼ縺碁｣邯壼､ｱ謨怜ｾ後↓豁｣縺励＞繧ｳ繝ｼ繝峨ｂ諡貞凄縺吶ｋ縺薙→繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_BlocksAfterRepeatedWrongCodes()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-limit@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(
            users,
            new RecordingEmailSender(),
            TestServices.CreateAttemptLimiter(1, TimeSpan.FromMinutes(5)));
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
    /// 逶ｮ逧・ Validate Step Up Token / Returns Known Grant 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝茨ｿｽE繧ｯ繝ｳ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ菫晏ｭ倡憾諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_ReturnsKnownGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-token@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-token@example.com");
        StepUpGrant grant = stepUp.VerifyEmailChallenge("mfa-token@example.com", challenge.Code);

        StepUpGrant found = stepUp.ValidateStepUpToken(grant.StepUpToken);

        Assert.AreEqual(grant.StepUpToken, found.StepUpToken);
    }

    /// <summary>
    /// 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝画､懆ｨｼ縺ｧ逋ｺ陦後＠縺溷ｼｷ蛹冶ｪ榊庄繝茨ｿｽE繧ｯ繝ｳ繧偵∝挨繧｢繝励Μ繧ｱ繝ｼ繧ｷ繝ｧ繝ｳ繧､繝ｳ繧ｹ繧ｿ繝ｳ繧ｹ縺九ｉRedis蜈ｱ譛臥憾諷九〒讀懆ｨｼ縺ｧ縺阪ｋ縺薙→繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_UsesSharedRedisGrantAcrossInstances()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-redis-token@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var redis = new FakeRedisStringStore();
        var sender = new RecordingEmailSender();
        var issuer = TestServices.CreateStepUpService(users, sender, TestServices.CreateAttemptLimiter(), redis);
        var verifier = TestServices.CreateStepUpService(users, sender, TestServices.CreateAttemptLimiter(), redis);

        MfaEmailChallenge challenge = issuer.StartEmailChallenge("mfa-redis-token@example.com");
        StepUpGrant grant = issuer.VerifyEmailChallenge("mfa-redis-token@example.com", challenge.Code);
        StepUpGrant found = verifier.ValidateStepUpToken(grant.StepUpToken);

        Assert.AreEqual(grant.StepUpToken, found.StepUpToken);
        Assert.AreEqual(grant.Subject, found.Subject);
        Assert.AreEqual("email_code", found.Method);
    }

    /// <summary>
    /// 逶ｮ逧・ Validate Step Up Token / Rejects Unknown Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_RejectsUnknownToken()
    {
        var stepUp = TestServices.CreateStepUpService(new InMemoryUserStore());

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.ValidateStepUpToken("sup_missing"));
    }

    /// <summary>
    /// 逶ｮ逧・ Validate Step Up Token / Rejects Expired Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 譛滄剞蛻・・ｽ・ｽ縺ｫ螟画峩縺励◆繝・・ｽ・ｽ繝医ョ繝ｼ繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_RejectsExpiredToken()
    {
        var redis = TestServices.CreateRedis();
        redis.SetString(
            StepUpGrantSession.GetRedisKey("sup_expired"),
            RedisSessionJson.Serialize(new StepUpGrantSession
            {
                StepUpToken = "sup_expired",
                Subject = "expired_subject",
                Method = "email_code",
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1)
            }),
            TimeSpan.FromMinutes(1));
        var stepUp = TestServices.CreateStepUpService(
            new InMemoryUserStore(),
            new RecordingEmailSender(),
            TestServices.CreateAttemptLimiter(),
            redis);

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.ValidateStepUpToken("sup_expired"));
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }

    private static string DifferentCode(string code)
    {
        return string.Equals(code, "000000", StringComparison.Ordinal) ? "111111" : "000000";
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
