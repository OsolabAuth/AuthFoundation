using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class TermsEndpointShapeTests
{
    /// <summary>
    /// 逶ｮ逧・ Current / Returns Current Terms Contract 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Current / Returns Current Terms Contract 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Current / Returns Current Terms Contract 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
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

    /// <summary>
    /// 逶ｮ逧・ Signup / Returns Accepted Terms Id When Terms Are Accepted 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Signup / Returns Accepted Terms Id When Terms Are Accepted 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Signup / Returns Accepted Terms Id When Terms Are Accepted 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Signup_ReturnsAcceptedTermsIdWhenTermsAreAccepted()
    {
        var sender = new CapturingEmailSender();
        var signupSessions = TestServices.CreateSignupSessionService(sender);
        SignupEmailChallenge challenge = signupSessions.StartEmailChallenge("terms-signup@example.com");
        SignupVerifiedSession verified = signupSessions.VerifyEmailChallenge(challenge.SessionId, sender.LastCode);
        var controller = EndpointTestHelper.WithHttpContext(
            new SignupController(new InMemoryUserStore(), new TermsService(), signupSessions));
        controller.Request.Headers.Cookie = $"AuthSignupSessionId={verified.SessionId}";
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

    /// <summary>
    /// 逶ｮ逧・ Signup / Returns Bad Request When Terms Are Not Accepted 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Signup / Returns Bad Request When Terms Are Not Accepted 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 400 Bad Request 逶ｸ蠖難ｿｽE繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Signup_ReturnsBadRequestWhenTermsAreNotAccepted()
    {
        var controller = EndpointTestHelper.WithHttpContext(
            new SignupController(new InMemoryUserStore(), new TermsService(), TestServices.CreateSignupSessionService(new DevelopmentEmailSender())));
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

    private sealed class CapturingEmailSender : IEmailSender
    {
        public string LastCode { get; private set; } = string.Empty;

        public void SendMfaCode(string email, string code, DateTimeOffset expiresAt)
        {
            LastCode = code;
        }
    }
}
