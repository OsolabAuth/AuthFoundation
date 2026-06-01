using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class MfaEndpointShapeTests
{
    private const string MfaEmail = "mfa-endpoint@example.com";
    private const string MfaPassword = "Passw0rd!";

    /// <summary>
    /// Purpose: verify email MFA challenge start does not expose the verification code in the response.
    /// Input: registered MFA test user email.
    /// Expected: 200 response with delivery=email, expires_at, and no code property.
    /// </summary>
    [TestMethod]
    public void StartEmail_ReturnsChallengeWithoutCodeExposure()
    {
        var controller = CreateController(CreateUsers(MfaEmail));

        var ok = EndpointTestHelper.AssertOk(controller.StartEmail(new EmailRequest(MfaEmail)));

        Assert.IsNotNull(ok.Value);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("challenge_created", EndpointTestHelper.ReadProperty<string>(ok.Value, "result"));
        Assert.AreEqual("email", EndpointTestHelper.ReadProperty<string>(ok.Value, "delivery"));
        Assert.AreEqual(MfaEmail, EndpointTestHelper.ReadProperty<string>(ok.Value, "email"));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<DateTimeOffset>(ok.Value, "expires_at") > DateTimeOffset.UtcNow);
        Assert.IsNull(ok.Value.GetType().GetProperty("code"));
    }

    /// <summary>
    /// Purpose: verify email MFA challenge start rejects malformed email.
    /// Input: email=invalid.
    /// Expected: 400 invalid_request with email validation message.
    /// </summary>
    [TestMethod]
    public void StartEmail_ReturnsBadRequestForInvalidEmail()
    {
        var controller = CreateController();

        ErrorOutput error = EndpointTestHelper.AssertError(controller.StartEmail(new EmailRequest("invalid")), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    /// <summary>
    /// Purpose: verify email MFA code verification issues a step-up token.
    /// Input: registered email and generated challenge code.
    /// Expected: 200 response with step_up_token and method=email_code.
    /// </summary>
    [TestMethod]
    public void VerifyEmail_ReturnsStepUpTokenForChallengeCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(MfaEmail);

        var ok = EndpointTestHelper.AssertOk(controller.VerifyEmail(new VerifyRequest(MfaEmail, challenge.Code)));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "step_up_token").StartsWith("sup_", StringComparison.Ordinal));
        Assert.AreEqual("StepUp", EndpointTestHelper.ReadProperty<string>(ok.Value, "token_type"));
        Assert.AreEqual("email_code", EndpointTestHelper.ReadProperty<string>(ok.Value, "method"));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<DateTimeOffset>(ok.Value, "expires_at") > DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Purpose: verify email MFA verification rejects an incorrect code.
    /// Input: registered email with active challenge, code=000000.
    /// Expected: 401 invalid_token.
    /// </summary>
    [TestMethod]
    public void VerifyEmail_ReturnsUnauthorizedForWrongCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        stepUp.StartEmailChallenge(MfaEmail);

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.VerifyEmail(new VerifyRequest(MfaEmail, "000000")),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// Purpose: verify authenticator setup returns a TOTP secret and otpauth URI.
    /// Input: registered MFA test user email.
    /// Expected: 200 response with non-empty secret and otpauth URI.
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsSecretAndOtpAuthUri()
    {
        var controller = CreateController(CreateUsers(MfaEmail));

        var ok = EndpointTestHelper.AssertOk(controller.SetupAuthenticator(new EmailRequest(MfaEmail)));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual(MfaEmail, EndpointTestHelper.ReadProperty<string>(ok.Value, "email"));
        Assert.IsFalse(string.IsNullOrWhiteSpace(EndpointTestHelper.ReadProperty<string>(ok.Value, "secret")));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "otpauth_uri").StartsWith("otpauth://totp/", StringComparison.Ordinal));
    }

    /// <summary>
    /// Purpose: verify authenticator setup rejects malformed email.
    /// Input: email=invalid.
    /// Expected: 400 invalid_request with email validation message.
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsBadRequestForInvalidEmail()
    {
        var controller = CreateController();

        ErrorOutput error = EndpointTestHelper.AssertError(controller.SetupAuthenticator(new EmailRequest("invalid")), 400);

        Assert.AreEqual("00001", error.ResponseCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    /// <summary>
    /// Purpose: verify authenticator verification issues a step-up token for a valid TOTP code.
    /// Input: generated TOTP secret and current code.
    /// Expected: 200 response with method=totp.
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsStepUpTokenForValidTotp()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        AuthenticatorSetup setup = stepUp.SetupAuthenticator(MfaEmail);
        string code = TotpUtil.GenerateCode(setup.Secret, DateTimeOffset.UtcNow);

        var ok = EndpointTestHelper.AssertOk(controller.VerifyAuthenticator(new VerifyRequest(MfaEmail, code)));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "step_up_token").StartsWith("sup_", StringComparison.Ordinal));
        Assert.AreEqual("totp", EndpointTestHelper.ReadProperty<string>(ok.Value, "method"));
    }

    /// <summary>
    /// Purpose: verify authenticator verification rejects users without a TOTP setup.
    /// Input: registered email without setup, code=000000.
    /// Expected: 401 invalid_token.
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsUnauthorizedWhenNotSetup()
    {
        var controller = CreateController(CreateUsers(MfaEmail));

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.VerifyAuthenticator(new VerifyRequest(MfaEmail, "000000")),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// Purpose: verify authenticator verification rejects an incorrect TOTP code.
    /// Input: registered email with TOTP setup, code=000000.
    /// Expected: 401 invalid_token.
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsUnauthorizedForWrongCode()
    {
        var users = CreateUsers(MfaEmail);
        var stepUp = new StepUpService(users);
        var controller = EndpointTestHelper.WithHttpContext(new MfaController(stepUp));
        stepUp.SetupAuthenticator(MfaEmail);

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.VerifyAuthenticator(new VerifyRequest(MfaEmail, "000000")),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    private static MfaController CreateController(InMemoryUserStore? users = null)
    {
        return EndpointTestHelper.WithHttpContext(new MfaController(new StepUpService(users ?? new InMemoryUserStore())));
    }

    private static InMemoryUserStore CreateUsers(params string[] emails)
    {
        var users = new InMemoryUserStore();
        foreach (string email in emails)
        {
            string subject = "subject_" + email.Replace("@", "_", StringComparison.Ordinal).Replace(".", "_", StringComparison.Ordinal);
            users.CreateUser(email, MfaPassword, "Mfa User", new DateOnly(2000, 1, 1), subject);
        }

        return users;
    }
}
