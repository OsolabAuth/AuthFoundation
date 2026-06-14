using System.Collections.Concurrent;
using System.Text.Json;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class StepUpService
{
    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan StepUpLifetime = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions JsonOptions = new();
    private readonly ConcurrentDictionary<string, MfaEmailChallenge> _emailChallenges = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string> _totpSecrets = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, StepUpGrant> _stepUpGrants = new();
    private readonly IRedisStringStore? _redisStore;
    private readonly IUserStore _users;
    private readonly IEmailSender _emailSender;
    private readonly AttemptLimiter _attempts;

    public StepUpService(IUserStore users)
        : this(users, new DevelopmentEmailSender(), new AttemptLimiter())
    {
    }

    public StepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts)
        : this(users, emailSender, attempts, null)
    {
    }

    internal StepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts, IRedisStringStore? redisStore)
    {
        _users = users;
        _emailSender = emailSender;
        _attempts = attempts;
        _redisStore = redisStore;
    }

    public MfaEmailChallenge StartEmailChallenge(string email)
    {
        UserRecord user = _users.FindByEmail(email);
        return CreateEmailChallenge(user);
    }

    /// <summary>
    /// メールアドレスと生年月日が登録情報と一致する場合だけ、パスワードリセット用メールコードを発行する。
    /// </summary>
    public bool TryStartPasswordResetChallenge(string email, DateOnly birthDate)
    {
        try
        {
            UserRecord user = _users.FindByEmail(email);
            if (user.BirthDate != birthDate)
            {
                return false;
            }

            _ = CreateEmailChallenge(user);
            return true;
        }
        catch (ApiException)
        {
            return false;
        }
    }

    public StepUpGrant VerifyEmailChallenge(string email, string code)
    {
        UserRecord user = _users.FindByEmail(email);
        string attemptKey = $"mfa_email:{user.Email}";
        _attempts.EnsureAllowed(attemptKey);
        MfaEmailChallenge? challenge = TakeEmailChallenge(user.Email);
        if (challenge is null
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
        SetTotpSecret(user.Email, secret);
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
        string? secret = GetTotpSecret(user.Email);
        if (string.IsNullOrWhiteSpace(secret)
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
        StepUpGrant? grant = GetStepUpGrant(token);
        if (grant is null
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
        if (_redisStore is null)
        {
            _stepUpGrants[grant.StepUpToken] = grant;
        }
        else
        {
            _redisStore.SetString(StepUpGrantKey(grant.StepUpToken), JsonSerializer.Serialize(grant, JsonOptions), StepUpLifetime);
        }

        return grant;
    }

    private MfaEmailChallenge CreateEmailChallenge(UserRecord user)
    {
        string code = Helper.GenerateNumericCode(6);
        var challenge = new MfaEmailChallenge(user.Email, code, DateTimeOffset.UtcNow.Add(ChallengeLifetime));
        if (_redisStore is null)
        {
            _emailChallenges[user.Email] = challenge;
        }
        else
        {
            _redisStore.SetString(EmailChallengeKey(user.Email), JsonSerializer.Serialize(challenge, JsonOptions), ChallengeLifetime);
        }

        _emailSender.SendMfaCode(challenge.Email, challenge.Code, challenge.ExpiresAt);
        return challenge;
    }

    private MfaEmailChallenge? TakeEmailChallenge(string email)
    {
        if (_redisStore is null)
        {
            return _emailChallenges.TryRemove(email, out MfaEmailChallenge? challenge) ? challenge : null;
        }

        string? value = _redisStore.TakeString(EmailChallengeKey(email));
        return string.IsNullOrWhiteSpace(value) ? null : JsonSerializer.Deserialize<MfaEmailChallenge>(value, JsonOptions);
    }

    private StepUpGrant? GetStepUpGrant(string token)
    {
        if (_redisStore is null)
        {
            return _stepUpGrants.TryGetValue(token, out StepUpGrant? grant) ? grant : null;
        }

        string? value = _redisStore.GetString(StepUpGrantKey(token));
        return string.IsNullOrWhiteSpace(value) ? null : JsonSerializer.Deserialize<StepUpGrant>(value, JsonOptions);
    }

    private void SetTotpSecret(string email, string secret)
    {
        if (_redisStore is null)
        {
            _totpSecrets[email] = secret;
            return;
        }

        _redisStore.SetString(TotpSecretKey(email), secret, TimeSpan.FromDays(365));
    }

    private string? GetTotpSecret(string email)
    {
        if (_redisStore is null)
        {
            return _totpSecrets.TryGetValue(email, out string? secret) ? secret : null;
        }

        return _redisStore.GetString(TotpSecretKey(email));
    }

    private static string EmailChallengeKey(string email)
    {
        return $"auth:step_up:email_challenge:{email.ToLowerInvariant()}";
    }

    private static string StepUpGrantKey(string token)
    {
        return $"auth:step_up:grant:{token}";
    }

    private static string TotpSecretKey(string email)
    {
        return $"auth:step_up:totp_secret:{email.ToLowerInvariant()}";
    }
}

public sealed record MfaEmailChallenge(string Email, string Code, DateTimeOffset ExpiresAt);
public sealed record AuthenticatorSetup(string Email, string Secret, string OtpAuthUri);
public sealed record StepUpGrant(string StepUpToken, string Subject, string Method, DateTimeOffset ExpiresAt);
