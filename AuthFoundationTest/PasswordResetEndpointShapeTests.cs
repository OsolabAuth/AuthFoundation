using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetEndpointShapeTests
{
    [TestMethod]
    public void Reset_ReturnsPasswordResetForMatchingBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-endpoint@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var controller = EndpointTestHelper.WithHttpContext(new PasswordController(users));
        var request = new ResetPasswordRequest("reset-endpoint@example.com", "2000-01-02", "Newpass1!");

        var ok = EndpointTestHelper.AssertOk(controller.Reset(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("password_reset", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("Reset User", users.Authenticate("reset-endpoint@example.com", "Newpass1!").Name);
    }

    [TestMethod]
    public void Reset_ReturnsBadRequestForInvalidBirthDateFormat()
    {
        var controller = EndpointTestHelper.WithHttpContext(new PasswordController(new InMemoryUserStore()));
        var request = new ResetPasswordRequest("reset-format@example.com", "2000-13-40", "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("some of the input values are incorrect", error.ErrorDescription);
    }

    [TestMethod]
    public void Reset_ReturnsUnauthorizedForMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-mismatch@example.com", "Passw0rd!", "Reset User", new DateOnly(2000, 1, 2));
        var controller = EndpointTestHelper.WithHttpContext(new PasswordController(users));
        var request = new ResetPasswordRequest("reset-mismatch@example.com", "2001-01-02", "Newpass1!");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    [TestMethod]
    public void Reset_ReturnsBadRequestForWeakNewPassword()
    {
        var controller = EndpointTestHelper.WithHttpContext(new PasswordController(new InMemoryUserStore()));
        var request = new ResetPasswordRequest("reset-weak@example.com", "2000-01-02", "weak");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Reset(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("password is invalid", error.ErrorDescription);
    }
}
