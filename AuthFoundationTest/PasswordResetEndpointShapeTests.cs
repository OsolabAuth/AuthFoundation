using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetEndpointShapeTests
{
    /// <summary>
    /// Purpose: verify password reset succeeds only when birth date and email code both match.
    /// Input: registered email, matching birth_date, valid email_code, and strong new_password.
    /// Expected: 200 password_reset and the new password authenticates.
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsPasswordResetForMatchingBirthDateAndEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-endpoint@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = new StepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-endpoint@example.com");
        var request = new ResetPasswordRequest("reset-endpoint@example.com", "2000-01-02", challenge.Code, "Newpass1!");

        var ok = EndpointTestHelper.AssertOk(controller.Reset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("password_reset", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("Reset User", users.Authenticate("reset-endpoint@example.com", "Newpass1!").Name);
    }

    /// <summary>
    /// Purpose: verify password reset rejects malformed birth dates before resetting the password.
    /// Input: invalid birth_date=2000-13-40 with 6-digit email_code.
    /// Expected: 400 invalid_request.
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
    /// Purpose: verify password reset rejects missing email code.
    /// Input: matching birth_date, empty email_code, and strong new_password.
    /// Expected: 400 invalid_request with email_code validation message.
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
    /// Purpose: verify password reset rejects mismatched registered birth date.
    /// Input: registered email, wrong birth_date, valid email_code, and strong new_password.
    /// Expected: 401 invalid_token and the old password remains valid.
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsUnauthorizedForMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-mismatch@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = new StepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-mismatch@example.com");
        var request = new ResetPasswordRequest("reset-mismatch@example.com", "2001-01-02", challenge.Code, "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-mismatch@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// Purpose: verify password reset consumes the email code before rejecting a mismatched birth date.
    /// Input: registered email, wrong birth_date with valid email_code, then matching birth_date with the same email_code.
    /// Expected: both attempts return 401 and the old password remains valid.
    /// </summary>
    [TestMethod]
    public void Reset_ConsumesEmailCodeBeforeRejectingMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-consume-code@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = new StepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-consume-code@example.com");
        var wrongBirthDateRequest = new ResetPasswordRequest("reset-consume-code@example.com", "2001-01-02", challenge.Code, "Newpass1!");
        var matchingBirthDateRetry = new ResetPasswordRequest("reset-consume-code@example.com", "2000-01-02", challenge.Code, "Newpass1!");

        ErrorOutput firstError = EndpointTestHelper.AssertError(controller.Reset(wrongBirthDateRequest), 401);
        ErrorOutput retryError = EndpointTestHelper.AssertError(controller.Reset(matchingBirthDateRetry), 401);

        Assert.AreEqual("00008", firstError.ResponseCode);
        Assert.AreEqual("invalid_token", firstError.Error);
        Assert.AreEqual("00008", retryError.ResponseCode);
        Assert.AreEqual("invalid_token", retryError.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-consume-code@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// Purpose: verify password reset rejects an incorrect email code.
    /// Input: registered email, matching birth_date, wrong email_code, and strong new_password.
    /// Expected: 401 invalid_token and the old password remains valid.
    /// </summary>
    [TestMethod]
    public void Reset_ReturnsUnauthorizedForWrongEmailCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-wrong-code@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var stepUp = new StepUpService(users);
        var controller = CreateController(users, stepUp);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("reset-wrong-code@example.com");
        var request = new ResetPasswordRequest("reset-wrong-code@example.com", "2000-01-02", DifferentCode(challenge.Code), "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
        Assert.AreEqual("Reset User", users.Authenticate("reset-wrong-code@example.com", "Passw0rd!").Name);
    }

    /// <summary>
    /// Purpose: verify password reset rejects weak new passwords before changing credentials.
    /// Input: matching birth_date, valid-looking email_code, and weak new_password.
    /// Expected: 400 invalid_request with password validation message.
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
}
