using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class TermsEndpointShapeTests
{
    [TestMethod]
    public void Current_ReturnsCurrentTermsContract()
    {
        var controller = EndpointTestHelper.WithHttpContext(new TermsController(new TermsService()));

        var ok = EndpointTestHelper.AssertOk(controller.Current());

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual(TermsService.CurrentTermsId, EndpointTestHelper.ReadProperty<string>(ok.Value, "terms_id"));
        Assert.AreEqual(TermsService.CurrentVersion, EndpointTestHelper.ReadProperty<string>(ok.Value, "version"));
        Assert.AreEqual("OsolabAuth Terms", EndpointTestHelper.ReadProperty<string>(ok.Value, "title"));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "body").Contains("OsolabAuth", StringComparison.Ordinal));
        Assert.AreEqual(AppConfig.DevelopmentClientId, EndpointTestHelper.ReadProperty<string>(ok.Value, "client_id"));
    }

    [TestMethod]
    public void Signup_ReturnsAcceptedTermsIdWhenTermsAreAccepted()
    {
        var controller = EndpointTestHelper.WithHttpContext(
            new SignupController(new InMemoryUserStore(), new TermsService()));
        var request = new SignupRequest(
            "terms-signup@example.com",
            "Passw0rd!",
            "Terms User",
            "2001-02-03",
            true);

        var ok = EndpointTestHelper.AssertOk(controller.Post(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual(TermsService.CurrentTermsId, EndpointTestHelper.ReadProperty<string>(ok.Value, "accepted_terms_id"));
    }

    [TestMethod]
    public void Signup_ReturnsBadRequestWhenTermsAreNotAccepted()
    {
        var controller = EndpointTestHelper.WithHttpContext(
            new SignupController(new InMemoryUserStore(), new TermsService()));
        var request = new SignupRequest(
            "terms-reject@example.com",
            "Passw0rd!",
            "Terms User",
            "2001-02-03",
            false);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Post(request), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("terms consent is required", error.ErrorDescription);
    }
}
