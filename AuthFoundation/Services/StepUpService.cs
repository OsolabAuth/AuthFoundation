using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class StepUpService
{
    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan StepUpLifetime = TimeSpan.FromMinutes(5);
    private readonly ConcurrentDictionary<string, MfaEmailChallenge> _emailChallenges = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _totpSecrets = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, StepUpGrant> _stepUpGrants = new();
    private readonly IUserStore _users;
    private readonly IEmailSender _emailSender;
    private readonly AttemptLimiter _attempts;

    public StepUpService(IUserStore users)
        : this(users, new DevelopmentEmailSender(), new AttemptLimiter())
    {
    }

    public StepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts)
    {
        _users = users;
        _emailSender = emailSender;
        _attempts = attempts;
    }

    public MfaEmailChallenge StartEmailChallenge(string email)
    {
        UserRecord user = _users.FindByEmail(email);
        string code = Helper.GenerateNumericCode(6);
        var challenge = new MfaEmailChallenge(user.Email, code, DateTimeOffset.UtcNow.Add(ChallengeLifetime));
        _emailChallenges[user.Email] = challenge;
        _emailSender.SendMfaCode(challenge.Email, challenge.Code, challenge.ExpiresAt);
        return challenge;
    }

    public StepUpGrant VerifyEmailChallenge(string email, string code)
    {
        UserRecord user = _users.FindByEmail(email);
        string attemptKey = $"mfa_email:{user.Email}";
        _attempts.EnsureAllowed(attemptKey);
        if (!_emailChallenges.TryRemove(user.Email, out MfaEmailChallenge? challenge)
            || challenge.ExpiresAt <= DateTimeOffset.UtcNow
            || !string.Equals(challenge.Code, code, StringComparison.Ordinal))
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        _attempts.Reset(attemptKey);
        return CreateGrant(user.Subject, "email_code");
    }

    public AuthenticatorSetup SetupAuthenticator(string email, string stepUpToken)
    {
        UserRecord user = _users.FindByEmail(email);
        StepUpGrant grant = ValidateStepUpToken(stepUpToken);
        if (!string.Equals(grant.Subject, user.Subject, StringComparison.Ordinal))
        {
            throw Code.UNAUTHORIZED;
        }

        string secret = TotpUtil.GenerateSecret();
        _totpSecrets[user.Email] = secret;
        string issuer = Uri.EscapeDataString("OsolabAuth");
        string account = Uri.EscapeDataString(user.Email);
        string uri = $"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30";
        return new AuthenticatorSetup(user.Email, secret, uri);
    }

    public StepUpGrant VerifyAuthenticator(string email, string code)
    {
        UserRecord user = _users.FindByEmail(email);
        string attemptKey = $"mfa_totp:{user.Email}";
        _attempts.EnsureAllowed(attemptKey);
        if (!_totpSecrets.TryGetValue(user.Email, out string? secret)
            || !TotpUtil.VerifyCode(secret, code, DateTimeOffset.UtcNow))
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        _attempts.Reset(attemptKey);
        return CreateGrant(user.Subject, "totp");
    }

    public StepUpGrant ValidateStepUpToken(string token)
    {
        string attemptKey = $"step_up:{token}";
        _attempts.EnsureAllowed(attemptKey);
        if (!_stepUpGrants.TryGetValue(token, out StepUpGrant? grant)
            || grant.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        _attempts.Reset(attemptKey);
        return grant;
    }

    private StepUpGrant CreateGrant(string subject, string method)
    {
        var grant = new StepUpGrant($"sup_{Helper.GenerateHex(48)}", subject, method, DateTimeOffset.UtcNow.Add(StepUpLifetime));
        _stepUpGrants[grant.StepUpToken] = grant;
        return grant;
    }
}

public sealed record MfaEmailChallenge(string Email, string Code, DateTimeOffset ExpiresAt);
public sealed record AuthenticatorSetup(string Email, string Secret, string OtpAuthUri);
public sealed record StepUpGrant(string StepUpToken, string Subject, string Method, DateTimeOffset ExpiresAt);
