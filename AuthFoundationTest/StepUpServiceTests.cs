using AuthFoundation.Services;
using AuthFoundation.Common;
using System.Collections.Concurrent;
using System.Reflection;

namespace AuthFoundationTest;

[TestClass]
public sealed class StepUpServiceTests
{
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

    [TestMethod]
    public void VerifyAuthenticator_ReturnsStepUpGrant()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        AuthenticatorSetup setup = stepUp.SetupAuthenticator("totp@example.com");
        string code = AuthFoundation.Common.TotpUtil.GenerateCode(setup.Secret, DateTimeOffset.UtcNow);
        StepUpGrant grant = stepUp.VerifyAuthenticator("totp@example.com", code);

        Assert.AreEqual("totp", grant.Method);
    }

    [TestMethod]
    public void VerifyAuthenticator_RejectsMissingSetup()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("totp-missing@example.com", "Passw0rd!", "Totp User", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.VerifyAuthenticator("totp-missing@example.com", "000000"));
    }

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

    [TestMethod]
    public void ValidateStepUpToken_RejectsUnknownToken()
    {
        var stepUp = new StepUpService(new InMemoryUserStore());

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => stepUp.ValidateStepUpToken("sup_missing"));
    }

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

    private static T GetField<T>(StepUpService service, string name)
    {
        FieldInfo? field = typeof(StepUpService).GetField(name, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.IsNotNull(field);
        object? value = field.GetValue(service);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }
}
