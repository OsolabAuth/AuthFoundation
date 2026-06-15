namespace AuthFoundation.Services;

public interface IAgentStore
{
    AgentCreateResult CreateAgent(
        UserRecord owner,
        string agentName,
        string clientId,
        string scope,
        DateTimeOffset expiresAt);

    AgentTokenGrant VerifyTokenRequest(string agentId, string agentSecret, string clientId, string requestedScope);

    AgentSecretRotationResult RotateSecret(UserRecord owner, string agentId);

    AgentRecord RevokeAgent(UserRecord owner, string agentId);
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
