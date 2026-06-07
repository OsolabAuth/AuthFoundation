using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class SignupSessionService
{
    private static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan VerifiedLifetime = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<string, SignupSession> _sessions = new();
    private readonly IEmailSender _emailSender;
    private readonly AttemptLimiter _attempts;

    public SignupSessionService(IEmailSender emailSender, AttemptLimiter attempts)
    {
        _emailSender = emailSender;
        _attempts = attempts;
    }

    /// <summary>
    /// アカウント登録用のメール認証コードを発行する。
    /// </summary>
    public SignupEmailChallenge StartEmailChallenge(string email)
    {
        string sessionId = $"sgn_{Helper.GenerateHex(32)}";
        string code = Helper.GenerateNumericCode(6);
        DateTimeOffset expiresAt = DateTimeOffset.UtcNow.Add(ChallengeLifetime);
        _sessions[sessionId] = new SignupSession(sessionId, email, code, expiresAt, null);
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
        if (!_sessions.TryGetValue(sessionId, out SignupSession? session)
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
        _sessions[sessionId] = verified;
        _attempts.Reset(attemptKey);
        return new SignupVerifiedSession(sessionId, session.Email, verified.CodeExpiresAt);
    }

    /// <summary>
    /// メール認証済みのアカウント登録セッションを消費する。
    /// </summary>
    public string ConsumeVerifiedEmail(string sessionId)
    {
        if (!_sessions.TryRemove(sessionId, out SignupSession? session)
            || session.VerifiedAt is null
            || session.CodeExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw Code.UNAUTHORIZED;
        }

        return session.Email;
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
