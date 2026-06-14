using System.Collections.Concurrent;
using System.Text.Json;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class SignupSessionService
{
    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan VerifiedLifetime = TimeSpan.FromMinutes(10);
    private static readonly JsonSerializerOptions JsonOptions = new();
    private readonly ConcurrentDictionary<string, SignupSession> _sessions = new();
    private readonly IEmailSender _emailSender;
    private readonly AttemptLimiter _attempts;
    private readonly IRedisStringStore? _redisStore;

    public SignupSessionService(IEmailSender emailSender, AttemptLimiter attempts)
        : this(emailSender, attempts, null)
    {
    }

    internal SignupSessionService(IEmailSender emailSender, AttemptLimiter attempts, IRedisStringStore? redisStore)
    {
        _emailSender = emailSender;
        _attempts = attempts;
        _redisStore = redisStore;
    }

    /// <summary>
    /// アカウント登録用のメール認証コードを発行する。
    /// </summary>
    public SignupEmailChallenge StartEmailChallenge(string email)
    {
        string sessionId = $"sgn_{Helper.GenerateHex(32)}";
        string code = Helper.GenerateNumericCode(6);
        DateTimeOffset expiresAt = DateTimeOffset.UtcNow.Add(ChallengeLifetime);
        SetSession(new SignupSession(sessionId, email, code, expiresAt, null), ChallengeLifetime);
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

        SignupSession verified = session with
        {
            VerifiedAt = DateTimeOffset.UtcNow,
            CodeExpiresAt = DateTimeOffset.UtcNow.Add(VerifiedLifetime)
        };
        SetSession(verified, VerifiedLifetime);
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
        if (_redisStore is null)
        {
            return _sessions.TryGetValue(sessionId, out SignupSession? session) ? session : null;
        }

        string? value = _redisStore.GetString(SessionKey(sessionId));
        return string.IsNullOrWhiteSpace(value) ? null : JsonSerializer.Deserialize<SignupSession>(value, JsonOptions);
    }

    private SignupSession? TakeSession(string sessionId)
    {
        if (_redisStore is null)
        {
            return _sessions.TryRemove(sessionId, out SignupSession? session) ? session : null;
        }

        string? value = _redisStore.TakeString(SessionKey(sessionId));
        return string.IsNullOrWhiteSpace(value) ? null : JsonSerializer.Deserialize<SignupSession>(value, JsonOptions);
    }

    private void SetSession(SignupSession session, TimeSpan expiresIn)
    {
        if (_redisStore is null)
        {
            _sessions[session.SessionId] = session;
            return;
        }

        _redisStore.SetString(SessionKey(session.SessionId), JsonSerializer.Serialize(session, JsonOptions), expiresIn);
    }

    private static string SessionKey(string sessionId)
    {
        return $"auth:signup:session:{sessionId}";
    }
}

public sealed record SignupEmailChallenge(string SessionId, string Email, DateTimeOffset ExpiresAt);
public sealed record SignupVerifiedSession(string SessionId, string Email, DateTimeOffset ExpiresAt);

internal sealed record SignupSession(
    string SessionId,
    string Email,
    string Code,
    DateTimeOffset CodeExpiresAt,
    DateTimeOffset? VerifiedAt);
