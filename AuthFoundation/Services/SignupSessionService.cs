using AuthFoundation.Common;
using AuthFoundation.Session;

namespace AuthFoundation.Services;

public sealed class SignupSessionService
{
    private readonly IEmailSender _emailSender;
    private readonly AttemptLimiter _attempts;
    private readonly EmailSendCooldown _sendCooldown;
    private readonly IRedisStringStore _redisStore;

    internal SignupSessionService(IEmailSender emailSender, AttemptLimiter attempts, IRedisStringStore redisStore)
        : this(emailSender, attempts, new EmailSendCooldown(redisStore), redisStore)
    {
    }

    internal SignupSessionService(IEmailSender emailSender, AttemptLimiter attempts, EmailSendCooldown sendCooldown, IRedisStringStore redisStore)
    {
        _emailSender = emailSender;
        _attempts = attempts;
        _sendCooldown = sendCooldown;
        _redisStore = redisStore;
    }

    /// <summary>
    /// アカウント登録用のメール認証コードを発行する。
    /// </summary>
    public SignupEmailChallenge StartEmailChallenge(string email)
    {
        _sendCooldown.EnsureCanSend("signup", email);
        string sessionId = $"sgn_{Helper.GenerateHex(32)}";
        string code = Helper.GenerateNumericCode(6);
        DateTimeOffset expiresAt = DateTimeOffset.UtcNow.Add(SignupSession.ChallengeLifetime);
        SetSession(
            new SignupSession
            {
                SessionId = sessionId,
                Email = email,
                Code = code,
                CodeExpiresAt = expiresAt
            },
            SignupSession.ChallengeLifetime);
        _emailSender.SendMfaCode(email, code, expiresAt);
        return new SignupEmailChallenge(sessionId, email, expiresAt);
    }

    /// <summary>
    /// アカウント登録用のメール認証コードを検証する。
    /// </summary>
    public SignupVerifiedSession VerifyEmailChallenge(string sessionId, string code)
    {
        string attemptKey = $"signup_email:{sessionId}";
        _attempts.EnsureAllowed(attemptKey);
        SignupSession? session = GetSession(sessionId);
        if (session is null
            || session.CodeExpiresAt <= DateTimeOffset.UtcNow
            || !string.Equals(session.Code, code, StringComparison.Ordinal))
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        SignupSession verified = new()
        {
            SessionId = session.SessionId,
            Email = session.Email,
            Code = session.Code,
            VerifiedAt = DateTimeOffset.UtcNow,
            CodeExpiresAt = DateTimeOffset.UtcNow.Add(SignupSession.VerifiedLifetime)
        };
        SetSession(verified, SignupSession.VerifiedLifetime);
        _attempts.Reset(attemptKey);
        return new SignupVerifiedSession(sessionId, session.Email, verified.CodeExpiresAt);
    }

    /// <summary>
    /// メール認証済みのアカウント登録セッションを消費する。
    /// </summary>
    public string ConsumeVerifiedEmail(string sessionId)
    {
        SignupSession? session = TakeSession(sessionId);
        if (session is null
            || session.VerifiedAt is null
            || session.CodeExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw Code.UNAUTHORIZED;
        }

        return session.Email;
    }

    private SignupSession? GetSession(string sessionId)
    {
        string? value = _redisStore.GetString(SignupSession.GetRedisKey(sessionId));
        return RedisSessionJson.Deserialize<SignupSession>(value);
    }

    private SignupSession? TakeSession(string sessionId)
    {
        string? value = _redisStore.TakeString(SignupSession.GetRedisKey(sessionId));
        return RedisSessionJson.Deserialize<SignupSession>(value);
    }

    private void SetSession(SignupSession session, TimeSpan expiresIn)
    {
        _redisStore.SetString(
            SignupSession.GetRedisKey(session.SessionId),
            RedisSessionJson.Serialize(session),
            expiresIn);
    }
}

public sealed record SignupEmailChallenge(string SessionId, string Email, DateTimeOffset ExpiresAt);
public sealed record SignupVerifiedSession(string SessionId, string Email, DateTimeOffset ExpiresAt);
