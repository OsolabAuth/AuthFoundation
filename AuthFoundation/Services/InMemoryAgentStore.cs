using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class InMemoryAgentStore
{
    private static readonly HashSet<string> AllowedDelegatedScopes = new(StringComparer.Ordinal)
    {
        "task_read",
        "task_create",
        "task_comment"
    };

    private readonly ConcurrentDictionary<string, AgentRecord> _agents = new();
    private readonly ConcurrentDictionary<string, AgentDelegationRecord> _delegations = new();

    public AgentCreateResult CreateAgent(
        UserRecord owner,
        string agentName,
        string clientId,
        string scope,
        DateTimeOffset expiresAt)
    {
        ValidateDelegatedScopes(scope);

        string agentId = $"agent_{Helper.GenerateHex(16)}";
        string secret = $"ags_{Helper.GenerateHex(48)}";
        string delegationId = $"del_{Helper.GenerateHex(16)}";
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var agent = new AgentRecord(
            agentId,
            owner.Subject,
            agentName,
            PasswordUtil.Hash(secret),
            "active",
            now,
            now);
        var delegation = new AgentDelegationRecord(
            delegationId,
            agentId,
            owner.Subject,
            clientId,
            scope,
            expiresAt,
            now);

        _agents[agentId] = agent;
        _delegations[delegationId] = delegation;
        return new AgentCreateResult(agent, delegation, secret);
    }

    public AgentTokenGrant VerifyTokenRequest(string agentId, string agentSecret, string clientId, string requestedScope)
    {
        string[] requestedScopes = ValidateDelegatedScopes(requestedScope);

        if (!_agents.TryGetValue(agentId, out AgentRecord? agent)
            || !string.Equals(agent.Status, "active", StringComparison.Ordinal)
            || !PasswordUtil.Verify(agentSecret, agent.SecretHash))
        {
            throw Code.UNAUTHORIZED;
        }

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
        AgentRecord rotated = agent with
        {
            SecretHash = PasswordUtil.Hash(secret),
            UpdatedAt = DateTimeOffset.UtcNow
        };
        _agents[agentId] = rotated;
        return new AgentSecretRotationResult(rotated, secret);
    }

    public AgentRecord RevokeAgent(UserRecord owner, string agentId)
    {
        AgentRecord agent = FindOwnedAgent(owner, agentId);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AgentRecord revoked = agent with
        {
            Status = "revoked",
            UpdatedAt = now,
            RevokedAt = now
        };
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

public sealed record AgentRecord(
    string AgentId,
    string OwnerSubject,
    string AgentName,
    string SecretHash,
    string Status,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? RevokedAt = null);

public sealed record AgentDelegationRecord(
    string DelegationId,
    string AgentId,
    string OwnerSubject,
    string ClientId,
    string Scope,
    DateTimeOffset ExpiresAt,
    DateTimeOffset CreatedAt);

public sealed record AgentCreateResult(AgentRecord Agent, AgentDelegationRecord Delegation, string AgentSecret);
public sealed record AgentTokenGrant(AgentRecord Agent, AgentDelegationRecord Delegation, string Scope);
public sealed record AgentSecretRotationResult(AgentRecord Agent, string AgentSecret);
