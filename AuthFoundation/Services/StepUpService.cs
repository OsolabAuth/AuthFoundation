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
    private readonly EmailSendCooldown _sendCooldown;

    public StepUpService(IUserStore users)
        : this(users, new DevelopmentEmailSender(), new AttemptLimiter(), new EmailSendCooldown(), null)
    {
    }

    public StepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts)
        : this(users, emailSender, attempts, new EmailSendCooldown(), null)
    {
    }

    internal StepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts, IRedisStringStore? redisStore)
        : this(users, emailSender, attempts, new EmailSendCooldown(redisStore), redisStore)
    {
    }

    internal StepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts, EmailSendCooldown sendCooldown, IRedisStringStore? redisStore)
    {
        _users = users;
        _emailSender = emailSender;
        _attempts = attempts;
        _sendCooldown = sendCooldown;
        _redisStore = redisStore;
    }

    public MfaEmailChallenge StartEmailChallenge(string email)
    {
        UserRecord user = _users.FindByEmail(email);
        _sendCooldown.EnsureCanSend("mfa", user.Email);
        return CreateEmailChallenge(user, EmailChallengeKey(user.Email));
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

            _sendCooldown.EnsureCanSend("password_reset", user.Email);
            _ = CreateEmailChallenge(user, PasswordResetEmailChallengeKey(user.Email));
            return true;
        }
        catch (ApiException ex) when (ex.InternalCode != Code.TOO_MANY_REQUESTS.InternalCode)
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

    public void VerifyPasswordResetChallenge(string email, string code)
    {
        UserRecord user = _users.FindByEmail(email);
        string attemptKey = $"password_reset_email:{user.Email}";
        _attempts.EnsureAllowed(attemptKey);
        MfaEmailChallenge? challenge = TakePasswordResetEmailChallenge(user.Email);
        if (challenge is null
            || challenge.ExpiresAt <= DateTimeOffset.UtcNow
            || !string.Equals(challenge.Code, code, StringComparison.Ordinal))
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        _attempts.Reset(attemptKey);
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

    private MfaEmailChallenge CreateEmailChallenge(UserRecord user, string storageKey)
    {
        string code = Helper.GenerateNumericCode(6);
        var challenge = new MfaEmailChallenge(user.Email, code, DateTimeOffset.UtcNow.Add(ChallengeLifetime));
        if (_redisStore is null)
        {
            _emailChallenges[storageKey] = challenge;
        }
        else
        {
            _redisStore.SetString(storageKey, JsonSerializer.Serialize(challenge, JsonOptions), ChallengeLifetime);
        }

        _emailSender.SendMfaCode(challenge.Email, challenge.Code, challenge.ExpiresAt);
        return challenge;
    }

    private MfaEmailChallenge? TakeEmailChallenge(string email)
    {
        return TakeEmailChallengeByKey(EmailChallengeKey(email));
    }

    private MfaEmailChallenge? TakePasswordResetEmailChallenge(string email)
    {
        return TakeEmailChallengeByKey(PasswordResetEmailChallengeKey(email));
    }

    private MfaEmailChallenge? TakeEmailChallengeByKey(string storageKey)
    {
        if (_redisStore is null)
        {
            return _emailChallenges.TryRemove(storageKey, out MfaEmailChallenge? challenge) ? challenge : null;
        }

        string? value = _redisStore.TakeString(storageKey);
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

    private static string PasswordResetEmailChallengeKey(string email)
    {
        return $"auth:step_up:password_reset_challenge:{email.ToLowerInvariant()}";
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
