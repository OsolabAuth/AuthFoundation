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
