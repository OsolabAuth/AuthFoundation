using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AccountPasswordEndpointShapeTests
{
    /// <summary>
    /// 逶ｮ逧・ Change Password / Returns Password Changed With Valid Step Up 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Change Password / Returns Password Changed With Valid Step Up 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void ChangePassword_ReturnsPasswordChangedWithValidStepUp()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-endpoint@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1), "change_subject");
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "change-endpoint@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new ChangePasswordRequest("change-endpoint@example.com", "Passw0rd!", "Newpass1!", grant.StepUpToken);

        var ok = EndpointTestHelper.AssertOk(controller.ChangePassword(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("password_changed", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("change_subject", users.Authenticate("change-endpoint@example.com", "Newpass1!").Subject);
    }

    /// <summary>
    /// 逶ｮ逧・ Change Password / Returns Unauthorized For Missing Step Up Grant 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void ChangePassword_ReturnsUnauthorizedForMissingStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-no-step@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1));
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, TestServices.CreateStepUpService(users)));
        var request = new ChangePasswordRequest("change-no-step@example.com", "Passw0rd!", "Newpass1!", "sup_missing");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.ChangePassword(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Change Password / Returns Unauthorized For Wrong Current Password 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void ChangePassword_ReturnsUnauthorizedForWrongCurrentPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-wrong-password@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "change-wrong-password@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new ChangePasswordRequest("change-wrong-password@example.com", "WrongPassw0rd!", "Newpass1!", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.ChangePassword(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Change Password / Returns Unauthorized For Step Up Subject Mismatch 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Change Password / Returns Unauthorized For Step Up Subject Mismatch 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void ChangePassword_ReturnsUnauthorizedForStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-owner@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1), "change_owner");
        users.CreateUser("change-other@example.com", "Passw0rd!", "Other User", new DateOnly(2000, 1, 1), "change_other");
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "change-other@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new ChangePasswordRequest("change-owner@example.com", "Passw0rd!", "Newpass1!", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.ChangePassword(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Change Password / Returns Bad Request For Weak New Password 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Change Password / Returns Bad Request For Weak New Password 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void ChangePassword_ReturnsBadRequestForWeakNewPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-weak@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "change-weak@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new ChangePasswordRequest("change-weak@example.com", "Passw0rd!", "weak", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.ChangePassword(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("password is invalid", error.ErrorDescription);
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }
}
