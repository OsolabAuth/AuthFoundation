using AuthFoundation.Common;
using AuthFoundation.Session;
using StackExchange.Redis;

namespace AuthFoundation.Services;

public class RedisOidcStore : IOidcStore
{
    private readonly IRedisStringStore _store;

    public RedisOidcStore(string connectionString)
        : this(new StackExchangeRedisStringStore(connectionString))
    {
    }

    internal RedisOidcStore(IRedisStringStore store)
    {
        _store = store;
    }

    public AuthorizationRequestRecord CreateRequest(
        string clientId,
        string redirectUri,
        string scope,
        string state,
        string nonce,
        string codeChallenge)
    {
        string requestId = Helper.GenerateHex(32);
        var session = new AuthorizationRequestSession
        {
            RequestId = requestId,
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scope = scope,
            State = state,
            Nonce = nonce,
            CodeChallenge = codeChallenge,
            ExpiresAt = DateTimeOffset.UtcNow.Add(AuthorizationRequestSession.Lifetime)
        };
        _store.SetString(
            AuthorizationRequestSession.GetRedisKey(requestId),
            RedisSessionJson.Serialize(session),
            AuthorizationRequestSession.Lifetime);
        return ToRecord(session);
    }

    public AuthorizationRequestRecord TakeRequest(string requestId)
    {
        AuthorizationRequestSession session = Take<AuthorizationRequestSession>(
            AuthorizationRequestSession.GetRedisKey(requestId),
            Code.UNAUTHORIZED);
        AuthorizationRequestRecord record = ToRecord(session);
        if (record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw Code.UNAUTHORIZED;
        }

        return record;
    }

    public AuthorizationCodeRecord CreateCode(AuthorizationRequestRecord request, string subject, string email, string name)
    {
        string code = Helper.GenerateHex(64);
        var session = new AuthorizationCodeSession
        {
            Code = code,
            ClientId = request.ClientId,
            RedirectUri = request.RedirectUri,
            Scope = request.Scope,
            Nonce = request.Nonce,
            CodeChallenge = request.CodeChallenge,
            Subject = subject,
            Email = email,
            Name = name,
            ExpiresAt = DateTimeOffset.UtcNow.Add(AuthorizationCodeSession.Lifetime)
        };
        _store.SetString(
            AuthorizationCodeSession.GetRedisKey(code),
            RedisSessionJson.Serialize(session),
            AuthorizationCodeSession.Lifetime);
        return ToRecord(session);
    }

    public AuthorizationCodeRecord TakeCode(string code)
    {
        ApiException invalidGrant = InvalidAuthorizationCode();
        AuthorizationCodeSession session = Take<AuthorizationCodeSession>(
            AuthorizationCodeSession.GetRedisKey(code),
            invalidGrant);
        AuthorizationCodeRecord record = ToRecord(session);
        if (record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw invalidGrant;
        }

        return record;
    }

    public AccessTokenRecord CreateAccessToken(AuthorizationCodeRecord code)
    {
        string accessToken = $"dev_{Helper.GenerateHex(48)}";
        var session = new AccessTokenSession
        {
            AccessToken = accessToken,
            ClientId = code.ClientId,
            Scope = code.Scope,
            Subject = code.Subject,
            Email = code.Email,
            Name = code.Name,
            PrincipalType = "user",
            ExpiresAt = DateTimeOffset.UtcNow.Add(AccessTokenSession.Lifetime)
        };
        _store.SetString(
            AccessTokenSession.GetRedisKey(accessToken),
            RedisSessionJson.Serialize(session),
            AccessTokenSession.Lifetime);
        return ToRecord(session);
    }

    public AccessTokenRecord CreateAgentAccessToken(AgentRecord agent, AgentDelegationRecord delegation, string scope)
    {
        string accessToken = $"agt_{Helper.GenerateHex(48)}";
        var session = new AccessTokenSession
        {
            AccessToken = accessToken,
            ClientId = delegation.ClientId,
            Scope = scope,
            Subject = agent.AgentId,
            Name = agent.AgentName,
            PrincipalType = "ai_agent",
            OwnerSubject = agent.OwnerSubject,
            DelegationId = delegation.DelegationId,
            ExpiresAt = DateTimeOffset.UtcNow.Add(AccessTokenSession.Lifetime)
        };
        _store.SetString(
            AccessTokenSession.GetRedisKey(accessToken),
            RedisSessionJson.Serialize(session),
            AccessTokenSession.Lifetime);
        return ToRecord(session);
    }

    public AccessTokenRecord FindAccessToken(string accessToken)
    {
        AccessTokenSession session = Get<AccessTokenSession>(
            AccessTokenSession.GetRedisKey(accessToken),
            Code.UNAUTHORIZED);
        AccessTokenRecord record = ToRecord(session);
        if (record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw Code.UNAUTHORIZED;
        }

        return record;
    }

    public bool RevokeAccessToken(string accessToken)
    {
        return _store.DeleteString(AccessTokenSession.GetRedisKey(accessToken));
    }

    private T Get<T>(string key, ApiException error)
    {
        string? value = _store.GetString(key);
        return Deserialize<T>(value, error);
    }

    private T Take<T>(string key, ApiException error)
    {
        string? value = _store.TakeString(key);
        return Deserialize<T>(value, error);
    }

    private static T Deserialize<T>(string? value, ApiException error)
    {
        T? record = RedisSessionJson.Deserialize<T>(value);
        return record ?? throw error;
    }

    private static AuthorizationRequestRecord ToRecord(AuthorizationRequestSession session)
    {
        return new AuthorizationRequestRecord(
            session.RequestId,
            session.ClientId,
            session.RedirectUri,
            session.Scope,
            session.State,
            session.Nonce,
            session.CodeChallenge,
            session.ExpiresAt);
    }

    private static AuthorizationCodeRecord ToRecord(AuthorizationCodeSession session)
    {
        return new AuthorizationCodeRecord(
            session.Code,
            session.ClientId,
            session.RedirectUri,
            session.Scope,
            session.Nonce,
            session.CodeChallenge,
            session.Subject,
            session.Email,
            session.Name,
            session.ExpiresAt);
    }

    private static AccessTokenRecord ToRecord(AccessTokenSession session)
    {
        return new AccessTokenRecord(
            session.AccessToken,
            session.ClientId,
            session.Scope,
            session.Subject,
            session.Email,
            session.Name,
            session.PrincipalType,
            session.OwnerSubject,
            session.DelegationId,
            session.ExpiresAt);
    }

    private static ApiException InvalidAuthorizationCode()
    {
        return new ApiException(
            Code.REQUEST_PARAMETER_ERROR.InternalCode,
            Code.REQUEST_PARAMETER_ERROR.StatusCode,
            "invalid_grant",
            "invalid authorization code");
    }
}

internal interface IRedisStringStore
{
    void SetString(string key, string value, TimeSpan expiresIn);

    bool SetStringIfNotExists(string key, string value, TimeSpan expiresIn);

    string? GetString(string key);

    string? TakeString(string key);

    bool DeleteString(string key);
}

internal sealed class StackExchangeRedisStringStore : IRedisStringStore
{
    private const string GetAndDeleteScript = """
local value = redis.call('GET', KEYS[1])
if value then
  redis.call('DEL', KEYS[1])
end
return value
""";
    private readonly ConnectionMultiplexer _connection;
    private readonly IDatabase _database;

    public StackExchangeRedisStringStore(string connectionString)
    {
        _connection = ConnectionMultiplexer.Connect(connectionString);
        _database = _connection.GetDatabase();
    }

    public void SetString(string key, string value, TimeSpan expiresIn)
    {
        _database.StringSet(key, value, expiresIn);
    }

    public bool SetStringIfNotExists(string key, string value, TimeSpan expiresIn)
    {
        return _database.StringSet(key, value, expiresIn, When.NotExists);
    }

    public string? GetString(string key)
    {
        RedisValue value = _database.StringGet(key);
        return value.IsNull ? null : value.ToString();
    }

    public string? TakeString(string key)
    {
        RedisResult result = _database.ScriptEvaluate(GetAndDeleteScript, [key]);
        if (result.IsNull)
        {
            return null;
        }

        var value = (RedisValue)result;
        return value.IsNull ? null : value.ToString();
    }

    public bool DeleteString(string key)
    {
        return _database.KeyDelete(key);
    }
}
