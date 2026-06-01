using AuthFoundation.Services;
using AuthFoundation.Common;
using System.Collections.Concurrent;
using System.Reflection;

namespace AuthFoundationTest;

[TestClass]
public sealed class StepUpServiceTests
{
    /// <summary>
    /// Purpose: verify email MFA challenge creation generates a fixed-width verification code.
    /// Input: existing user email.
    /// Expected: generated code has 6 numeric characters.
    /// </summary>
    [TestMethod]
    public void StartEmailChallenge_ReturnsSixDigitCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-code@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-code@example.com");

        Assert.AreEqual(6, challenge.Code.Length);
        StringAssert.Matches(challenge.Code, new System.Text.RegularExpressions.Regex("^[0-9]{6}$"));
    }

    /// <summary>
    /// Purpose: verify email MFA challenge verification issues a step-up grant.
    /// Input: generated email challenge code.
    /// Expected: step-up grant method is email_code and token starts with sup_.
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_ReturnsStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa@example.com");
        StepUpGrant grant = stepUp.VerifyEmailChallenge("mfa@example.com", challenge.Code);

        Assert.AreEqual("email_code", grant.Method);
        Assert.IsTrue(grant.StepUpToken.StartsWith("sup_"));
    }

    /// <summary>
    /// Purpose: verify email MFA challenge verification rejects an incorrect code.
    /// Input: generated challenge, code=000000.
    /// Expected: ApiException.
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_RejectsWrongCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-wrong@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        stepUp.StartEmailChallenge("mfa-wrong@example.com");

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-wrong@example.com", "000000"));
    }

    /// <summary>
    /// Purpose: verify expired email MFA challenge is rejected.
    /// Input: challenge with expires_at in the past.
    /// Expected: ApiException.
    /// </summary>
    [TestMethod]
    public void VerifyEmailChallenge_RejectsExpiredCode()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-expired@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        EmailChallenges(stepUp)["mfa-expired@example.com"] = new MfaEmailChallenge(
            "mfa-expired@example.com",
            "123456",
            DateTimeOffset.UtcNow.AddSeconds(-1));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyEmailChallenge("mfa-expired@example.com", "123456"));
    }

    /// <summary>
    /// Purpose: verify authenticator setup requires a valid step-up grant for the same user.
    /// Input: existing user email and email MFA step-up token.
    /// Expected: authenticator setup returns a secret and otpauth URI.
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_ReturnsSetupWithValidStepUp()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-setup@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "totp-setup@example.com");

        AuthenticatorSetup setup = stepUp.SetupAuthenticator("totp-setup@example.com", grant.StepUpToken);

        Assert.AreEqual("totp-setup@example.com", setup.Email);
        Assert.IsFalse(string.IsNullOrWhiteSpace(setup.Secret));
        Assert.IsTrue(setup.OtpAuthUri.StartsWith("otpauth://totp/", StringComparison.Ordinal));
    }

    /// <summary>
    /// Purpose: verify authenticator setup rejects unknown step-up tokens.
    /// Input: existing user email and token=sup_missing.
    /// Expected: ApiException.
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_RejectsUnknownStepUpToken()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-unknown-token@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        Assert.ThrowsExactly<ApiException>(
            () => stepUp.SetupAuthenticator("totp-unknown-token@example.com", "sup_missing"));
    }

    /// <summary>
    /// Purpose: verify authenticator setup rejects step-up tokens issued for another user.
    /// Input: setup user email and another user's step-up token.
    /// Expected: ApiException.
    /// </summary>
    [TestMethod]
    public void SetupAuthenticator_RejectsStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-owner@example.com", "Passw0rd!", "Totp Owner", new DateOnly(2000, 1, 1));
        users.CreateUser("totp-other@example.com", "Passw0rd!", "Totp Other", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "totp-other@example.com");

        Assert.ThrowsExactly<ApiException>(
            () => stepUp.SetupAuthenticator("totp-owner@example.com", grant.StepUpToken));
    }

    /// <summary>
    /// Purpose: verify authenticator verification issues a step-up grant for a valid TOTP code.
    /// Input: generated TOTP secret and current TOTP code.
    /// Expected: step-up grant method is totp.
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_ReturnsStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant setupGrant = IssueEmailStepUp(stepUp, "totp@example.com");

        AuthenticatorSetup setup = stepUp.SetupAuthenticator("totp@example.com", setupGrant.StepUpToken);
        string code = AuthFoundation.Common.TotpUtil.GenerateCode(setup.Secret, DateTimeOffset.UtcNow);
        StepUpGrant grant = stepUp.VerifyAuthenticator("totp@example.com", code);

        Assert.AreEqual("totp", grant.Method);
    }

    /// <summary>
    /// Purpose: verify authenticator verification rejects users without setup.
    /// Input: existing user without TOTP secret.
    /// Expected: ApiException.
    /// </summary>
    [TestMethod]
    public void VerifyAuthenticator_RejectsMissingSetup()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-missing@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyAuthenticator("totp-missing@example.com", "000000"));
    }

    /// <summary>
    /// Purpose: verify known step-up token can be retrieved.
    /// Input: token issued by email MFA verification.
    /// Expected: same token is returned by ValidateStepUpToken.
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_ReturnsKnownGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("mfa-token@example.com", "Passw0rd!", "Mfa User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge("mfa-token@example.com");
        StepUpGrant grant = stepUp.VerifyEmailChallenge("mfa-token@example.com", challenge.Code);

        StepUpGrant found = stepUp.ValidateStepUpToken(grant.StepUpToken);

        Assert.AreEqual(grant.StepUpToken, found.StepUpToken);
    }

    /// <summary>
    /// Purpose: verify unknown step-up token is rejected.
    /// Input: token=sup_missing.
    /// Expected: ApiException.
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_RejectsUnknownToken()
    {
        var stepUp = new StepUpService(new InMemoryUserStore());

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.ValidateStepUpToken("sup_missing"));
    }

    /// <summary>
    /// Purpose: verify expired step-up token is rejected.
    /// Input: token with expires_at in the past.
    /// Expected: ApiException.
    /// </summary>
    [TestMethod]
    public void ValidateStepUpToken_RejectsExpiredToken()
    {
        var stepUp = new StepUpService(new InMemoryUserStore());
        StepUpGrants(stepUp)["sup_expired"] = new StepUpGrant(
            "sup_expired",
            "expired_subject",
            "email_code",
            DateTimeOffset.UtcNow.AddSeconds(-1));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.ValidateStepUpToken("sup_expired"));
    }

    private static ConcurrentDictionary<string, MfaEmailChallenge> EmailChallenges(StepUpService service)
    {
        return GetField<ConcurrentDictionary<string, MfaEmailChallenge>>(service, "_emailChallenges");
    }

    private static ConcurrentDictionary<string, StepUpGrant> StepUpGrants(StepUpService service)
    {
        return GetField<ConcurrentDictionary<string, StepUpGrant>>(service, "_stepUpGrants");
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }

    private static T GetField<T>(StepUpService service, string name)
    {
        FieldInfo? field = typeof(StepUpService).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.IsNotNull(field);
        object? value = field.GetValue(service);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }
}
