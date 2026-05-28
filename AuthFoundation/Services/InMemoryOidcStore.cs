using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class InMemoryOidcStore
{
    private static readonly TimeSpan RequestLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);
    private readonly ConcurrentDictionary<string, AuthorizationRequestRecord> _requests = new();
    private readonly ConcurrentDictionary<string, AuthorizationCodeRecord> _codes = new();

    public AuthorizationRequestRecord CreateRequest(
        string clientId,
        string redirectUri,
        string scope,
        string state,
        string nonce,
        string codeChallenge)
    {
        string requestId = Helper.GenerateHex(32);
        var record = new AuthorizationRequestRecord(
            requestId,
            clientId,
            redirectUri,
            scope,
            state,
            nonce,
            codeChallenge,
            DateTimeOffset.UtcNow.Add(RequestLifetime));
        _requests[requestId] = record;
        return record;
    }

    public AuthorizationRequestRecord TakeRequest(string requestId)
    {
        if (!_requests.TryRemove(requestId, out AuthorizationRequestRecord? record)
            || record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw Code.UNAUTHORIZED;
        }

        return record;
    }

    public AuthorizationCodeRecord CreateCode(AuthorizationRequestRecord request, string subject, string email, string name)
    {
        string code = Helper.GenerateHex(64);
        var record = new AuthorizationCodeRecord(
            code,
            request.ClientId,
            request.RedirectUri,
            request.Scope,
            request.Nonce,
            request.CodeChallenge,
            subject,
            email,
            name,
            DateTimeOffset.UtcNow.Add(CodeLifetime));
        _codes[code] = record;
        return record;
    }

    public AuthorizationCodeRecord TakeCode(string code)
    {
        if (!_codes.TryRemove(code, out AuthorizationCodeRecord? record)
            || record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw new ApiException(
                Code.REQUEST_PARAMETER_ERROR.InternalCode,
                Code.REQUEST_PARAMETER_ERROR.StatusCode,
                "invalid_grant",
                "invalid authorization code");
        }

        return record;
    }
}

public sealed record AuthorizationRequestRecord(
    string RequestId,
    string ClientId,
    string RedirectUri,
    string Scope,
    string State,
    string Nonce,
    string CodeChallenge,
    DateTimeOffset ExpiresAt);

public sealed record AuthorizationCodeRecord(
    string Code,
    string ClientId,
    string RedirectUri,
    string Scope,
    string Nonce,
    string CodeChallenge,
    string Subject,
    string Email,
    string Name,
    DateTimeOffset ExpiresAt);
