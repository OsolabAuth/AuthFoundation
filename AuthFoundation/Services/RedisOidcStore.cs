using System.Text.Json;
using AuthFoundation.Common;
using StackExchange.Redis;

namespace AuthFoundation.Services;

public sealed class RedisOidcStore : IOidcStore
{
    private static readonly TimeSpan RequestLifetime = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(15);
    private static readonly JsonSerializerOptions JsonOptions = new();
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
        var record = new AuthorizationRequestRecord(
            requestId,
            clientId,
            redirectUri,
            scope,
            state,
            nonce,
            codeChallenge,
            DateTimeOffset.UtcNow.Add(RequestLifetime));
        Set(RequestKey(requestId), record, RequestLifetime);
        return record;
    }

    public AuthorizationRequestRecord TakeRequest(string requestId)
    {
        AuthorizationRequestRecord record = Take<AuthorizationRequestRecord>(RequestKey(requestId), Code.UNAUTHORIZED);
        if (record.ExpiresAt <= DateTimeOffset.UtcNow)
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
        Set(CodeKey(code), record, CodeLifetime);
        return record;
    }

    public AuthorizationCodeRecord TakeCode(string code)
    {
        ApiException invalidGrant = InvalidAuthorizationCode();
        AuthorizationCodeRecord record = Take<AuthorizationCodeRecord>(CodeKey(code), invalidGrant);
        if (record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw invalidGrant;
        }

        return record;
    }

    public AccessTokenRecord CreateAccessToken(AuthorizationCodeRecord code)
    {
        string accessToken = $"dev_{Helper.GenerateHex(48)}";
        var record = new AccessTokenRecord(
            accessToken,
            code.ClientId,
            code.Scope,
            code.Subject,
            code.Email,
            code.Name,
            "user",
            string.Empty,
            string.Empty,
            DateTimeOffset.UtcNow.Add(AccessTokenLifetime));
        Set(AccessTokenKey(accessToken), record, AccessTokenLifetime);
        return record;
    }

    public AccessTokenRecord CreateAgentAccessToken(AgentRecord agent, AgentDelegationRecord delegation, string scope)
    {
        string accessToken = $"agt_{Helper.GenerateHex(48)}";
        var record = new AccessTokenRecord(
            accessToken,
            delegation.ClientId,
            scope,
            agent.AgentId,
            string.Empty,
            agent.AgentName,
            "ai_agent",
            agent.OwnerSubject,
            delegation.DelegationId,
            DateTimeOffset.UtcNow.Add(AccessTokenLifetime));
        Set(AccessTokenKey(accessToken), record, AccessTokenLifetime);
        return record;
    }

    public AccessTokenRecord FindAccessToken(string accessToken)
    {
        AccessTokenRecord record = Get<AccessTokenRecord>(AccessTokenKey(accessToken), Code.UNAUTHORIZED);
        if (record.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            throw Code.UNAUTHORIZED;
        }

        return record;
    }

    public bool RevokeAccessToken(string accessToken)
    {
        return _store.DeleteString(AccessTokenKey(accessToken));
    }

    private static string RequestKey(string requestId)
    {
        return $"auth:oidc:request:{requestId}";
    }

    private static string CodeKey(string code)
    {
        return $"auth:oidc:code:{code}";
    }

    private static string AccessTokenKey(string accessToken)
    {
        return $"auth:oidc:access_token:{accessToken}";
    }

    private void Set<T>(string key, T value, TimeSpan expiresIn)
    {
        _store.SetString(key, JsonSerializer.Serialize(value, JsonOptions), expiresIn);
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
        if (string.IsNullOrWhiteSpace(value))
        {
            throw error;
        }

        T? record = JsonSerializer.Deserialize<T>(value, JsonOptions);
        return record ?? throw error;
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
