namespace AuthFoundation.Services;

public interface IOidcStore
{
    AuthorizationRequestRecord CreateRequest(
        string clientId,
        string redirectUri,
        string scope,
        string state,
        string nonce,
        string codeChallenge);

    AuthorizationRequestRecord TakeRequest(string requestId);

    AuthorizationCodeRecord CreateCode(AuthorizationRequestRecord request, string subject, string email, string name);

    AuthorizationCodeRecord TakeCode(string code);

    AuthSessionRecord CreateAuthSession(string subject, string email, string name);

    AuthSessionRecord? FindAuthSession(string sessionId);

    bool RevokeAuthSession(string sessionId);

    AccessTokenRecord CreateAccessToken(AuthorizationCodeRecord code);

    AccessTokenRecord CreateAgentAccessToken(AgentRecord agent, AgentDelegationRecord delegation, string scope);

    AccessTokenRecord FindAccessToken(string accessToken);

    bool RevokeAccessToken(string accessToken);
}
