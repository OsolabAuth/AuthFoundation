using System.Collections.Concurrent;
using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundation.Services;

internal sealed class TestRedisStringStore : IRedisStringStore
{
    private readonly ConcurrentDictionary<string, Entry> _values = new(StringComparer.Ordinal);

    public void SetString(string key, string value, TimeSpan expiresIn)
    {
        _values[key] = new Entry(value, DateTimeOffset.UtcNow.Add(expiresIn));
    }

    public bool SetStringIfNotExists(string key, string value, TimeSpan expiresIn)
    {
        CleanupExpired(key);
        return _values.TryAdd(key, new Entry(value, DateTimeOffset.UtcNow.Add(expiresIn)));
    }

    public string? GetString(string key)
    {
        CleanupExpired(key);
        return _values.TryGetValue(key, out Entry? entry) ? entry.Value : null;
    }

    public string? TakeString(string key)
    {
        CleanupExpired(key);
        return _values.TryRemove(key, out Entry? entry) ? entry.Value : null;
    }

    public bool DeleteString(string key)
    {
        return _values.TryRemove(key, out _);
    }

    private void CleanupExpired(string key)
    {
        if (_values.TryGetValue(key, out Entry? entry) && entry.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _values.TryRemove(key, out _);
        }
    }

    private sealed record Entry(string Value, DateTimeOffset ExpiresAt);
}

public sealed class InMemoryUserStore : IUserStore
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
        UserRecord updated = user with { PasswordHash = PasswordUtil.Hash(newPassword) };
        _usersByEmail[email] = updated;
        return updated;
    }

    public UserRecord ResetPassword(string email, DateOnly birthDate, string newPassword)
    {
        UserRecord user = FindByEmail(email);
        if (user.BirthDate != birthDate)
        {
            throw Code.UNAUTHORIZED;
        }

        UserRecord updated = user with { PasswordHash = PasswordUtil.Hash(newPassword) };
        _usersByEmail[email] = updated;
        return updated;
    }

    public UserRecord Withdraw(string email, string password)
    {
        UserRecord user = Authenticate(email, password);
        _usersByEmail.TryRemove(email, out _);
        return user;
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

public sealed class InMemoryAgentStore : IAgentStore
{
    private static readonly HashSet<string> AllowedDelegatedScopes = new(StringComparer.Ordinal)
    {
        "task_read",
        "task_create",
        "task_comment"
    };

    private readonly ConcurrentDictionary<string, AgentRecord> _agents = new();
    private readonly ConcurrentDictionary<string, AgentDelegationRecord> _delegations = new();
    private readonly AttemptLimiter _attempts;

    public InMemoryAgentStore()
        : this(new AttemptLimiter(new TestRedisStringStore()))
    {
    }

    public InMemoryAgentStore(AttemptLimiter attempts)
    {
        _attempts = attempts;
    }

    public AgentCreateResult CreateAgent(UserRecord owner, string agentName, string clientId, string scope, DateTimeOffset expiresAt)
    {
        ValidateDelegatedScopes(scope);

        string agentId = $"agent_{Helper.GenerateHex(16)}";
        string secret = $"ags_{Helper.GenerateHex(48)}";
        string delegationId = $"del_{Helper.GenerateHex(16)}";
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var agent = new AgentRecord(agentId, owner.Subject, agentName, PasswordUtil.Hash(secret), "active", now, now);
        var delegation = new AgentDelegationRecord(delegationId, agentId, owner.Subject, clientId, scope, expiresAt, now);

        _agents[agentId] = agent;
        _delegations[delegationId] = delegation;
        return new AgentCreateResult(agent, delegation, secret);
    }

    public AgentTokenGrant VerifyTokenRequest(string agentId, string agentSecret, string clientId, string requestedScope)
    {
        string[] requestedScopes = ValidateDelegatedScopes(requestedScope);
        string attemptKey = $"agent_secret:{agentId}";
        _attempts.EnsureAllowed(attemptKey);

        if (!_agents.TryGetValue(agentId, out AgentRecord? agent)
            || !string.Equals(agent.Status, "active", StringComparison.Ordinal)
            || !PasswordUtil.Verify(agentSecret, agent.SecretHash))
        {
            _attempts.RecordFailure(attemptKey);
            throw Code.UNAUTHORIZED;
        }

        _attempts.Reset(attemptKey);
        AgentDelegationRecord? delegation = _delegations.Values.FirstOrDefault(item =>
            string.Equals(item.AgentId, agentId, StringComparison.Ordinal)
            && string.Equals(item.ClientId, clientId, StringComparison.Ordinal)
            && item.ExpiresAt > DateTimeOffset.UtcNow);
        if (delegation is null)
        {
            throw Code.UNAUTHORIZED;
        }

        string[] allowedScopes = Helper.ParseScopes(delegation.Scope);
        if (requestedScopes.Any(scope => !allowedScopes.Contains(scope, StringComparer.Ordinal)))
        {
            throw Code.INVALID_SCOPE;
        }

        return new AgentTokenGrant(agent, delegation, string.Join(' ', requestedScopes));
    }

    public AgentSecretRotationResult RotateSecret(UserRecord owner, string agentId)
    {
        AgentRecord agent = FindOwnedAgent(owner, agentId);
        if (!string.Equals(agent.Status, "active", StringComparison.Ordinal))
        {
            throw Code.UNAUTHORIZED;
        }

        string secret = $"ags_{Helper.GenerateHex(48)}";
        AgentRecord rotated = agent with { SecretHash = PasswordUtil.Hash(secret), UpdatedAt = DateTimeOffset.UtcNow };
        _agents[agentId] = rotated;
        return new AgentSecretRotationResult(rotated, secret);
    }

    public AgentRecord RevokeAgent(UserRecord owner, string agentId)
    {
        AgentRecord agent = FindOwnedAgent(owner, agentId);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AgentRecord revoked = agent with { Status = "revoked", UpdatedAt = now, RevokedAt = now };
        _agents[agentId] = revoked;
        return revoked;
    }

    private AgentRecord FindOwnedAgent(UserRecord owner, string agentId)
    {
        if (!_agents.TryGetValue(agentId, out AgentRecord? agent)
            || !string.Equals(agent.OwnerSubject, owner.Subject, StringComparison.Ordinal))
        {
            throw Code.UNAUTHORIZED;
        }

        return agent;
    }

    private static string[] ValidateDelegatedScopes(string scope)
    {
        string[] scopes = Helper.ParseScopes(scope);
        if (scopes.Length == 0 || scopes.Any(item => !AllowedDelegatedScopes.Contains(item)))
        {
            throw Code.INVALID_SCOPE;
        }

        return scopes;
    }
}

public sealed class InMemoryOidcStore : RedisOidcStore
{
    public InMemoryOidcStore()
        : base(new TestRedisStringStore())
    {
    }
}
