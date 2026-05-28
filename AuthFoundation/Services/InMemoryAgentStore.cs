using System.Collections.Concurrent;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class InMemoryAgentStore
{
    private readonly ConcurrentDictionary<string, AgentRecord> _agents = new();
    private readonly ConcurrentDictionary<string, AgentDelegationRecord> _delegations = new();

    public AgentCreateResult CreateAgent(
        UserRecord owner,
        string agentName,
        string clientId,
        string scope,
        DateTimeOffset expiresAt)
    {
        string agentId = $"agent_{Helper.GenerateHex(16)}";
        string secret = $"ags_{Helper.GenerateHex(48)}";
        string delegationId = $"del_{Helper.GenerateHex(16)}";
        var agent = new AgentRecord(
            agentId,
            owner.Subject,
            agentName,
            PasswordUtil.Hash(secret),
            "active",
            DateTimeOffset.UtcNow);
        var delegation = new AgentDelegationRecord(
            delegationId,
            agentId,
            owner.Subject,
            clientId,
            scope,
            expiresAt,
            DateTimeOffset.UtcNow);

        _agents[agentId] = agent;
        _delegations[delegationId] = delegation;
        return new AgentCreateResult(agent, delegation, secret);
    }

    public AgentTokenGrant VerifyTokenRequest(string agentId, string agentSecret, string clientId, string requestedScope)
    {
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
        string[] requestedScopes = Helper.ParseScopes(requestedScope);
        if (requestedScopes.Length == 0 || requestedScopes.Any(scope => !allowedScopes.Contains(scope, StringComparer.Ordinal)))
        {
            throw Code.INVALID_SCOPE;
        }

        return new AgentTokenGrant(agent, delegation, string.Join(' ', requestedScopes));
    }
}

public sealed record AgentRecord(
    string AgentId,
    string OwnerSubject,
    string AgentName,
    string SecretHash,
    string Status,
    DateTimeOffset CreatedAt);

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
