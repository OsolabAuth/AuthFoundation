using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetEndpointShapeTests
{
    /// <summary>
    /// 逶ｮ逧・ 繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ髢句ｧ区凾縺ｫ縲√Γ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｨ逕溷ｹｴ譛域律縺御ｸ閾ｴ縺吶ｋ蛻ｩ逕ｨ閠・・ｽ・ｽ隱崎ｨｼ繧ｳ繝ｼ繝峨ｒ騾∽ｿ｡縺吶ｋ縺薙→繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 逋ｻ骭ｲ貂医∩繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縲∫匳骭ｲ貂医∩逕溷ｹｴ譛域律縲・
    /// 譛溷ｾ・・ｽ・ｽ: 200 OK 縺ｨ reset_challenge_started 繧定ｿ斐＠縲∬ｪ崎ｨｼ繧ｳ繝ｼ繝峨ｒ1騾壹□縺鷹∽ｿ｡縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void StartReset_SendsEmailCodeWhenEmailAndBirthDateMatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-start@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var controller = CreateController(users, TestServices.CreateStepUpService(users, emailSender));
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
    /// 逶ｮ逧・ 逕溷ｹｴ譛域律縺御ｸ閾ｴ縺励↑縺・・ｽ・ｽ繧ｹ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ髢句ｧ玖ｦ∵ｱゅ〒縲√い繧ｫ繧ｦ繝ｳ繝育憾諷九ｒ髴ｲ蜃ｺ縺励↑縺・・ｽ・ｽ縺ｨ繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 逋ｻ骭ｲ貂医∩繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縲∽ｸ堺ｸ閾ｴ縺ｮ逕溷ｹｴ譛域律縲・
    /// 譛溷ｾ・・ｽ・ｽ: 200 OK 縺ｨ騾壼ｸｸ縺ｮ髢句ｧ九Ξ繧ｹ繝昴Φ繧ｹ繧定ｿ斐☆縺後∬ｪ崎ｨｼ繧ｳ繝ｼ繝峨ｒ騾∽ｿ｡縺励↑縺・・ｽ・ｽ縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void StartReset_DoesNotSendEmailCodeForMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-start-mismatch@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var controller = CreateController(users, TestServices.CreateStepUpService(users, emailSender));
        var request = new ResetPasswordStartRequest("reset-start-mismatch@example.com", "2001-01-02");

        var ok = EndpointTestHelper.AssertOk(controller.StartReset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("reset_challenge_started", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual(0, emailSender.SentCodes.Count);
    }

    /// <summary>
    /// 逶ｮ逧・ 蟄伜惠縺励↑縺・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｮ繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ髢句ｧ玖ｦ∵ｱゅ〒縲√い繧ｫ繧ｦ繝ｳ繝域怏辟｡繧帝愆蜃ｺ縺励↑縺・・ｽ・ｽ縺ｨ繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 譛ｪ逋ｻ骭ｲ繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縲∫函蟷ｴ譛域律縲・
    /// 譛溷ｾ・・ｽ・ｽ: 200 OK 縺ｨ騾壼ｸｸ縺ｮ髢句ｧ九Ξ繧ｹ繝昴Φ繧ｹ繧定ｿ斐☆縺後∬ｪ崎ｨｼ繧ｳ繝ｼ繝峨ｒ騾∽ｿ｡縺励↑縺・・ｽ・ｽ縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void StartReset_DoesNotRevealUnknownEmail()
    {
        var users = new InMemoryUserStore();
        var emailSender = new RecordingEmailSender();
        var controller = CreateController(users, TestServices.CreateStepUpService(users, emailSender));
        var request = new ResetPasswordStartRequest("unknown-reset@example.com", "2001-01-02");

        var ok = EndpointTestHelper.AssertOk(controller.StartReset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("reset_challenge_started", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual(0, emailSender.SentCodes.Count);
    }

    /// <summary>
    /// Purpose: prevent repeated password reset email sends within the cooldown window.
    /// Input: the same login email and matching birth date are submitted twice.
    /// Expected: the second request returns 429 slow_down and no second email is sent.
    /// </summary>
    [TestMethod]
    public void StartReset_ReturnsTooManyRequestsWhenRepeated()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-repeat@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var redis = TestServices.CreateRedis();
        var stepUp = TestServices.CreateStepUpService(
            users,
            emailSender,
            TestServices.CreateAttemptLimiter(),
            TestServices.CreateEmailSendCooldown(TimeSpan.FromMinutes(1)),
            redis);
        var controller = CreateController(users, stepUp);
        var request = new ResetPasswordStartRequest("reset-repeat@example.com", "2000-01-02");

        _ = EndpointTestHelper.AssertOk(controller.StartReset(request));
        ErrorOutput error = EndpointTestHelper.AssertError(controller.StartReset(request), 429);

        Assert.AreEqual("00010", error.ResponseCode);
        Assert.AreEqual("slow_down", error.Error);
        Assert.AreEqual(1, emailSender.SentCodes.Count);
    }

    /// <summary>
    /// 逶ｮ逧・ 繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ髢句ｧ玖ｦ∵ｱゑｿｽE逕溷ｹｴ譛域律蠖｢蠑乗､懆ｨｼ繧堤｢ｺ隱阪☆繧九・
    /// 蜈･蜉帛､: yyyy-MM-dd 縺ｧ縺ｯ縺ｪ縺・・ｽ・ｽ蟷ｴ譛域律縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 縺ｨ invalid_request 繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void StartReset_ReturnsBadRequestForInvalidBirthDateFormat()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, TestServices.CreateStepUpService(users));
        var request = new ResetPasswordStartRequest("reset-format@example.com", "2000-13-40");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.StartReset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("some of the input values are incorrect", error.ErrorDescription);
    }

    /// <summary>
    /// 逶ｮ逧・ 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨→逕溷ｹｴ譛域律縺御ｸ閾ｴ縺吶ｋ蝣ｴ蜷医↓縲√ヱ繧ｹ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ縺悟ｮ御ｺ・・ｽ・ｽ繧九％縺ｨ繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 逋ｻ骭ｲ貂医∩繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縲∫匳骭ｲ貂医∩逕溷ｹｴ譛域律縲∫匱陦梧ｸ医∩繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨∵眠縺励＞繝代せ繝ｯ繝ｼ繝峨・
    /// 譛溷ｾ・・ｽ・ｽ: 200 OK 縺ｨ password_reset 繧定ｿ斐＠縲∵眠縺励＞繝代せ繝ｯ繝ｼ繝峨〒隱崎ｨｼ縺ｧ縺阪ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsPasswordResetForMatchingBirthDateAndEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-endpoint@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var stepUp = TestServices.CreateStepUpService(users, emailSender);
        var controller = CreateController(users, stepUp);
        _ = EndpointTestHelper.AssertOk(controller.StartReset(new ResetPasswordStartRequest("reset-endpoint@example.com", "2000-01-02")));
        var request = new ResetPasswordRequest("reset-endpoint@example.com", "2000-01-02", emailSender.SentCodes[0].Code, "Newpass1!");

        var ok = EndpointTestHelper.AssertOk(controller.Reset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("password_reset", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("Reset User", users.Authenticate("reset-endpoint@example.com", "Newpass1!").Name);
    }

    /// <summary>
    /// 繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ髢句ｧ九→螳御ｺ・・ｽ・ｽ蛻･繧｢繝励Μ繧ｱ繝ｼ繧ｷ繝ｧ繝ｳ繧､繝ｳ繧ｹ繧ｿ繝ｳ繧ｹ縺ｧ蜃ｦ逅・・ｽ・ｽ繧後※繧ゅヽedis蜈ｱ譛臥憾諷九↓繧医ｊ繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨ｒ讀懆ｨｼ縺ｧ縺阪ｋ縺薙→繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void Reset_UsesSharedRedisEmailChallengeAcrossInstances()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-redis@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var redis = new FakeRedisStringStore();
        var sender = new RecordingEmailSender();
        var startController = CreateController(users, TestServices.CreateStepUpService(users, sender, TestServices.CreateAttemptLimiter(), redis));
        var resetController = CreateController(users, TestServices.CreateStepUpService(users, sender, TestServices.CreateAttemptLimiter(), redis));

        _ = EndpointTestHelper.AssertOk(startController.StartReset(new ResetPasswordStartRequest("reset-redis@example.com", "2000-01-02")));
        var request = new ResetPasswordRequest("reset-redis@example.com", "2000-01-02", sender.SentCodes[0].Code, "Newpass1!");

        var ok = EndpointTestHelper.AssertOk(resetController.Reset(request));

        Assert.AreEqual("password_reset", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("Reset User", users.Authenticate("reset-redis@example.com", "Newpass1!").Name);
    }

    /// <summary>
    /// 逶ｮ逧・ MFA逕ｨ繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨ｒ繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ逕ｨ繧ｳ繝ｼ繝峨→縺励※豬∫畑縺ｧ縺阪↑縺・・ｽ・ｽ縺ｨ繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: MFA髢句ｧ九〒逋ｺ陦後＆繧後◆繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨∫匳骭ｲ貂医∩繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縲∫函蟷ｴ譛域律縲∵眠縺励＞繝代せ繝ｯ繝ｼ繝峨・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 繧定ｿ斐＠縲∵里蟄倥ヱ繧ｹ繝ｯ繝ｼ繝峨′邯ｭ謖√＆繧後ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Reset_RejectsMfaEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-mfa-code@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = TestServices.CreateStepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-mfa-code@example.com");
        var request = new ResetPasswordRequest("reset-mfa-code@example.com", "2000-01-02", challenge.Code, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-mfa-code@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// 逶ｮ逧・ 繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ螳御ｺ・・ｽ・ｽ豎ゑｿｽE逕溷ｹｴ譛域律蠖｢蠑乗､懆ｨｼ繧堤｢ｺ隱阪☆繧九・
    /// 蜈･蜉帛､: yyyy-MM-dd 縺ｧ縺ｯ縺ｪ縺・・ｽ・ｽ蟷ｴ譛域律縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 縺ｨ invalid_request 繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForInvalidBirthDateFormat()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, TestServices.CreateStepUpService(users));
        var request = new ResetPasswordRequest("reset-format@example.com", "2000-13-40", "123456", "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("some of the input values are incorrect", error.ErrorDescription);
    }

    /// <summary>
    /// 逶ｮ逧・ 繝代せ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ螳御ｺ・・ｽ・ｽ豎ゅ〒繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨′蠢・・ｽ・ｽ縺ｧ縺ゅｋ縺薙→繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 遨ｺ縺ｮ繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 縺ｨ email_code is required 繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForMissingEmailCode()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, TestServices.CreateStepUpService(users));
        var request = new ResetPasswordRequest("reset-missing-code@example.com", "1990-01-01", string.Empty, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email_code is required", error.ErrorDescription);
    }

    /// <summary>
    /// 逶ｮ逧・ 逕溷ｹｴ譛域律縺御ｸ閾ｴ縺励↑縺・・ｽ・ｽ蜷医↓縲√ヱ繧ｹ繝ｯ繝ｼ繝峨′螟画峩縺輔ｌ縺ｪ縺・・ｽ・ｽ縺ｨ繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 逋ｻ骭ｲ貂医∩繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縲∽ｸ堺ｸ閾ｴ縺ｮ逕溷ｹｴ譛域律縲∵ｭ｣縺励＞繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨∵眠縺励＞繝代せ繝ｯ繝ｼ繝峨・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 繧定ｿ斐＠縲∵立繝代せ繝ｯ繝ｼ繝峨〒蠑輔″邯壹″隱崎ｨｼ縺ｧ縺阪ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsUnauthorizedForMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-mismatch@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var stepUp = TestServices.CreateStepUpService(users, emailSender);
        var controller = CreateController(users, stepUp);
        _ = EndpointTestHelper.AssertOk(controller.StartReset(new ResetPasswordStartRequest("reset-mismatch@example.com", "2000-01-02")));
        var request = new ResetPasswordRequest("reset-mismatch@example.com", "2001-01-02", emailSender.SentCodes[0].Code, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-mismatch@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// 逶ｮ逧・ 繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨′荳閾ｴ縺励↑縺・・ｽ・ｽ蜷医↓縲√ヱ繧ｹ繝ｯ繝ｼ繝峨′螟画峩縺輔ｌ縺ｪ縺・・ｽ・ｽ縺ｨ繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 逋ｻ骭ｲ貂医∩繝｡繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縲∫匳骭ｲ貂医∩逕溷ｹｴ譛域律縲∽ｸ堺ｸ閾ｴ縺ｮ繝｡繝ｼ繝ｫ繧ｳ繝ｼ繝峨∵眠縺励＞繝代せ繝ｯ繝ｼ繝峨・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 繧定ｿ斐＠縲∵立繝代せ繝ｯ繝ｼ繝峨〒蠑輔″邯壹″隱崎ｨｼ縺ｧ縺阪ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsUnauthorizedForWrongEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-wrong-code@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var emailSender = new RecordingEmailSender();
        var stepUp = TestServices.CreateStepUpService(users, emailSender);
        var controller = CreateController(users, stepUp);
        _ = EndpointTestHelper.AssertOk(controller.StartReset(new ResetPasswordStartRequest("reset-wrong-code@example.com", "2000-01-02")));
        var request = new ResetPasswordRequest("reset-wrong-code@example.com", "2000-01-02", DifferentCode(emailSender.SentCodes[0].Code), "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-wrong-code@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// 逶ｮ逧・ 譁ｰ縺励＞繝代せ繝ｯ繝ｼ繝峨′繝昴Μ繧ｷ繝ｼ繧呈ｺ縺溘＆縺ｪ縺・・ｽ・ｽ蜷医↓縲√ヱ繧ｹ繝ｯ繝ｼ繝峨Μ繧ｻ繝・・ｽ・ｽ繧呈拠蜷ｦ縺吶ｋ縺薙→繧呈､懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠑ｱ縺・・ｽ・ｽ繝代せ繝ｯ繝ｼ繝峨・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 縺ｨ password is invalid 繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsBadRequestForWeakNewPassword()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, TestServices.CreateStepUpService(users));
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
