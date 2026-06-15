using AuthFoundation.Common;
using AuthFoundation.Session;

namespace AuthFoundation.Services;

public sealed class StepUpService
{
    private readonly IRedisStringStore _redisStore;
    private readonly IUserStore _users;
    private readonly IEmailSender _emailSender;
    private readonly AttemptLimiter _attempts;
    private readonly EmailSendCooldown _sendCooldown;

    internal StepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts, IRedisStringStore redisStore)
        : this(users, emailSender, attempts, new EmailSendCooldown(redisStore), redisStore)
    {
    }

    internal StepUpService(IUserStore users, IEmailSender emailSender, AttemptLimiter attempts, EmailSendCooldown sendCooldown, IRedisStringStore redisStore)
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

            _sendCooldown.EnsureCanSend("password_reset", user.Email);
            _ = CreatePasswordResetEmailChallenge(user);
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
        MfaEmailChallenge? challenge = GetEmailChallenge(user.Email);
        if (challenge is null
            || challenge.ExpiresAt <= DateTimeOffset.UtcNow
            || !string.Equals(challenge.Code, code, StringComparison.Ordinal))
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        _attempts.Reset(attemptKey);
        DeleteEmailChallenge(user.Email);
        return CreateGrant(user.Subject, "email_code");
    }

    public void VerifyPasswordResetChallenge(string email, string code)
    {
        UserRecord user = _users.FindByEmail(email);
        string attemptKey = $"password_reset_email:{user.Email}";
        _attempts.EnsureAllowed(attemptKey);
        MfaEmailChallenge? challenge = GetPasswordResetEmailChallenge(user.Email);
        if (challenge is null
            || challenge.ExpiresAt <= DateTimeOffset.UtcNow
            || !string.Equals(challenge.Code, code, StringComparison.Ordinal))
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        _attempts.Reset(attemptKey);
        DeletePasswordResetEmailChallenge(user.Email);
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
        var grant = new StepUpGrant($"sup_{Helper.GenerateHex(48)}", subject, method, DateTimeOffset.UtcNow.Add(StepUpGrantSession.Lifetime));
        var session = new StepUpGrantSession
        {
            StepUpToken = grant.StepUpToken,
            Subject = grant.Subject,
            Method = grant.Method,
            ExpiresAt = grant.ExpiresAt
        };
        _redisStore.SetString(
            StepUpGrantSession.GetRedisKey(grant.StepUpToken),
            RedisSessionJson.Serialize(session),
            StepUpGrantSession.Lifetime);

        return grant;
    }

    private MfaEmailChallenge CreateEmailChallenge(UserRecord user)
    {
        string code = Helper.GenerateNumericCode(6);
        var challenge = new MfaEmailChallenge(user.Email, code, DateTimeOffset.UtcNow.Add(MfaEmailChallengeSession.Lifetime));
        var session = new MfaEmailChallengeSession
        {
            Email = challenge.Email,
            Code = challenge.Code,
            ExpiresAt = challenge.ExpiresAt
        };
        _redisStore.SetString(
            MfaEmailChallengeSession.GetRedisKey(user.Email),
            RedisSessionJson.Serialize(session),
            MfaEmailChallengeSession.Lifetime);

        _emailSender.SendMfaCode(challenge.Email, challenge.Code, challenge.ExpiresAt);
        return challenge;
    }

    private MfaEmailChallenge CreatePasswordResetEmailChallenge(UserRecord user)
    {
        string code = Helper.GenerateNumericCode(6);
        var challenge = new MfaEmailChallenge(user.Email, code, DateTimeOffset.UtcNow.Add(PasswordResetEmailChallengeSession.Lifetime));
        var session = new PasswordResetEmailChallengeSession
        {
            Email = challenge.Email,
            Code = challenge.Code,
            ExpiresAt = challenge.ExpiresAt
        };
        _redisStore.SetString(
            PasswordResetEmailChallengeSession.GetRedisKey(user.Email),
            RedisSessionJson.Serialize(session),
            PasswordResetEmailChallengeSession.Lifetime);

        _emailSender.SendMfaCode(challenge.Email, challenge.Code, challenge.ExpiresAt);
        return challenge;
    }

    private MfaEmailChallenge? GetEmailChallenge(string email)
    {
        string? value = _redisStore.GetString(MfaEmailChallengeSession.GetRedisKey(email));
        MfaEmailChallengeSession? session = RedisSessionJson.Deserialize<MfaEmailChallengeSession>(value);
        return session is null ? null : new MfaEmailChallenge(session.Email, session.Code, session.ExpiresAt);
    }

    private void DeleteEmailChallenge(string email)
    {
        _redisStore.DeleteString(MfaEmailChallengeSession.GetRedisKey(email));
    }

    private MfaEmailChallenge? GetPasswordResetEmailChallenge(string email)
    {
        string? value = _redisStore.GetString(PasswordResetEmailChallengeSession.GetRedisKey(email));
        PasswordResetEmailChallengeSession? session = RedisSessionJson.Deserialize<PasswordResetEmailChallengeSession>(value);
        return session is null ? null : new MfaEmailChallenge(session.Email, session.Code, session.ExpiresAt);
    }

    private void DeletePasswordResetEmailChallenge(string email)
    {
        _redisStore.DeleteString(PasswordResetEmailChallengeSession.GetRedisKey(email));
    }

    private StepUpGrant? GetStepUpGrant(string token)
    {
        string? value = _redisStore.GetString(StepUpGrantSession.GetRedisKey(token));
        StepUpGrantSession? session = RedisSessionJson.Deserialize<StepUpGrantSession>(value);
        return session is null ? null : new StepUpGrant(session.StepUpToken, session.Subject, session.Method, session.ExpiresAt);
    }

    private void SetTotpSecret(string email, string secret)
    {
        var session = new TotpSecretSession
        {
            Email = email,
            Secret = secret
        };
        _redisStore.SetString(
            TotpSecretSession.GetRedisKey(email),
            RedisSessionJson.Serialize(session),
            TotpSecretSession.Lifetime);
    }

    private string? GetTotpSecret(string email)
    {
        string? value = _redisStore.GetString(TotpSecretSession.GetRedisKey(email));
        return RedisSessionJson.Deserialize<TotpSecretSession>(value)?.Secret;
    }
}

public sealed record MfaEmailChallenge(string Email, string Code, DateTimeOffset ExpiresAt);
public sealed record AuthenticatorSetup(string Email, string Secret, string OtpAuthUri);
public sealed record StepUpGrant(string StepUpToken, string Subject, string Method, DateTimeOffset ExpiresAt);
