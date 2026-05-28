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
        string? subject = null)
    {
        var record = new UserRecord(
            subject ?? $"user_{Helper.GenerateHex(16)}",
            email,
            name,
            password);

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
            || !string.Equals(user.Password, password, StringComparison.Ordinal))
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
    string Password);
