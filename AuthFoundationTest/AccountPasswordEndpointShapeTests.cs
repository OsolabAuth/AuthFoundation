using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AccountPasswordEndpointShapeTests
{
    [TestMethod]
    public void ChangePassword_ReturnsPasswordChangedWithValidStepUp()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-endpoint@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1), "change_subject");
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "change-endpoint@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp, new AuditLogService()));
        var request = new ChangePasswordRequest("change-endpoint@example.com", "Passw0rd!", "Newpass1!", grant.StepUpToken);

        var ok = EndpointTestHelper.AssertOk(controller.ChangePassword(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("password_changed", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("change_subject", users.Authenticate("change-endpoint@example.com", "Newpass1!").Subject);
    }

    [TestMethod]
    public void ChangePassword_ReturnsUnauthorizedForMissingStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-no-step@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1));
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, new StepUpService(users), new AuditLogService()));
        var request = new ChangePasswordRequest("change-no-step@example.com", "Passw0rd!", "Newpass1!", "sup_missing");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.ChangePassword(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    [TestMethod]
    public void ChangePassword_ReturnsUnauthorizedForWrongCurrentPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-wrong-password@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "change-wrong-password@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp, new AuditLogService()));
        var request = new ChangePasswordRequest("change-wrong-password@example.com", "WrongPassw0rd!", "Newpass1!", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.ChangePassword(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    [TestMethod]
    public void ChangePassword_ReturnsUnauthorizedForStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-owner@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1), "change_owner");
        users.CreateUser("change-other@example.com", "Passw0rd!", "Other User", new DateOnly(2000, 1, 1), "change_other");
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "change-other@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp, new AuditLogService()));
        var request = new ChangePasswordRequest("change-owner@example.com", "Passw0rd!", "Newpass1!", grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.ChangePassword(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    [TestMethod]
    public void ChangePassword_ReturnsBadRequestForWeakNewPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change-weak@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "change-weak@example.com");
        var controller = EndpointTestHelper.WithHttpContext(new AccountController(users, stepUp, new AuditLogService()));
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
