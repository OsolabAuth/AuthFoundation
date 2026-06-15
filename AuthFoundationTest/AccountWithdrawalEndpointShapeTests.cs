using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AccountWithdrawalEndpointShapeTests
{
    /// <summary>
    /// 逶ｮ逧・ Withdraw / Returns Account Withdrawn With Valid Step Up 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Withdraw / Returns Account Withdrawn With Valid Step Up 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsAccountWithdrawnWithValidStepUp()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-endpoint@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1), "withdraw_subject");
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "withdraw-endpoint@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new WithdrawalRequest("withdraw-endpoint@example.com", "Passw0rd!", grant.StepUpToken);

        var ok = EndpointTestHelper.AssertOk(controller.Withdraw(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("account_withdrawn", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.ThrowsExactly<ApiException>(() => users.FindByEmail("withdraw-endpoint@example.com"));
    }

    /// <summary>
    /// 逶ｮ逧・ Withdraw / Returns Unauthorized For Missing Step Up Grant 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsUnauthorizedForMissingStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-no-step@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1));
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, TestServices.CreateStepUpService(users)));
        var request = new WithdrawalRequest("withdraw-no-step@example.com", "Passw0rd!", "sup_missing");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Withdraw(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Withdraw / Returns Unauthorized For Wrong Password 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsUnauthorizedForWrongPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-wrong-password@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "withdraw-wrong-password@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new WithdrawalRequest("withdraw-wrong-password@example.com", "WrongPassw0rd!", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Withdraw(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Withdraw / Returns Unauthorized For Step Up Subject Mismatch 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Withdraw / Returns Unauthorized For Step Up Subject Mismatch 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsUnauthorizedForStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-owner@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1), "withdraw_owner");
        users.CreateUser("withdraw-other@example.com", "Passw0rd!", "Other User", new DateOnly(2000, 1, 1), "withdraw_other");
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "withdraw-other@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new WithdrawalRequest("withdraw-owner@example.com", "Passw0rd!", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Withdraw(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Withdraw / Returns Bad Request For Missing Password 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Withdraw_ReturnsBadRequestForMissingPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw-missing-password@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1));
        var stepUp = TestServices.CreateStepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "withdraw-missing-password@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp));
        var request = new WithdrawalRequest("withdraw-missing-password@example.com", string.Empty, grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Withdraw(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("password is required", error.ErrorDescription);
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }
}
