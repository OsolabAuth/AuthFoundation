using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class InMemoryUserStore
{
    private readonly ConcurrentDictionary<string, UserRecord> _usersByEmail = new(StringComparer.OrdinalIgnoreCase);

    public UserRecord CreateUser(
        string email,
        string password,
        string name,
        DateOnly birthDate,
        string? subject = null,
        string? acceptedTermsId = null)
    {
        var record = new UserRecord(
            subject ?? $"user_{Helper.GenerateHex(16)}",
            email,
            name,
            birthDate,
            acceptedTermsId,
            PasswordUtil.Hash(password),
            DateTimeOffset.UtcNow);

        if (!_usersByEmail.TryAdd(email, record))
        {
            throw new ApiException(
                Code.REQUEST_PARAMETER_ERROR.InternalCode,
                Code.REQUEST_PARAMETER_ERROR.StatusCode,
                "invalid_request",
                "email is already registered");
        }

        return record;
    }

    public UserRecord Authenticate(string email, string password)
    {
        if (!_usersByEmail.TryGetValue(email, out UserRecord? user)
            || !PasswordUtil.Verify(password, user.PasswordHash))
        {
            throw Code.UNAUTHORIZED;
        }

        return user;
    }

    public UserRecord ChangePassword(string email, string currentPassword, string newPassword)
    {
        UserRecord user = Authenticate(email, currentPassword);
        UserRecord updated = user with
        {
            PasswordHash = PasswordUtil.Hash(newPassword)
        };
        _usersByEmail[email] = updated;
        return updated;
    }

    public UserRecord FindByEmail(string email)
    {
        if (!_usersByEmail.TryGetValue(email, out UserRecord? user))
        {
            throw Code.UNAUTHORIZED;
        }

        return user;
    }
}

public sealed record UserRecord(
    string Subject,
    string Email,
    string Name,
    DateOnly BirthDate,
    string? AcceptedTermsId,
    string PasswordHash,
    DateTimeOffset CreatedAt);
