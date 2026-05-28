using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class SignupEndpointShapeTests
{
    [TestMethod]
    public void Post_ReturnsCreatedUserProfile()
    {
        var users = new InMemoryUserStore();
        var controller = EndpointTestHelper.WithHttpContext(new SignupController(users, new TermsService()));
        var request = new SignupRequest(
            "signup-success@example.com",
            "Passw0rd!",
            "Signup User",
            "2001-02-03",
            true);

        var ok = EndpointTestHelper.AssertOk(controller.Post(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        string sub = EndpointTestHelper.ReadProperty<string>(ok.Value, "sub");
        Assert.IsTrue(sub.StartsWith("user_", StringComparison.Ordinal));
        Assert.AreEqual("signup-success@example.com", EndpointTestHelper.ReadProperty<string>(ok.Value, "email"));
        Assert.AreEqual("Signup User", EndpointTestHelper.ReadProperty<string>(ok.Value, "name"));
        Assert.AreEqual("2001-02-03", EndpointTestHelper.ReadProperty<string>(ok.Value, "birth_date"));
        Assert.AreEqual(sub, users.Authenticate("signup-success@example.com", "Passw0rd!").Subject);
    }

    [TestMethod]
    public void Post_ReturnsBadRequestForInvalidEmail()
    {
        var controller = EndpointTestHelper.WithHttpContext(new SignupController(new InMemoryUserStore(), new TermsService()));
        var request = new SignupRequest("invalid", "Passw0rd!", "Signup User", "2001-02-03", true);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Post(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    [TestMethod]
    public void Post_ReturnsBadRequestForInvalidBirthDate()
    {
        var controller = EndpointTestHelper.WithHttpContext(new SignupController(new InMemoryUserStore(), new TermsService()));
        var request = new SignupRequest("signup-birth@example.com", "Passw0rd!", "Signup User", "2001-13-40", true);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Post(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("some of the input values are incorrect", error.ErrorDescription);
    }
}
