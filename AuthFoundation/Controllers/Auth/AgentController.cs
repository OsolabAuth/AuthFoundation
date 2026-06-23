using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Serialization;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("agent")]
public sealed class AgentController : ControllerBase
{
    private const string AuthSessionCookieName = "AuthSessionId";

    private readonly IUserStore _users;
    private readonly IAgentStore _agents;
    private readonly StepUpService _stepUp;
    private readonly OidcTokenService _tokens;
    private readonly IOidcStore _oidcStore;

    public AgentController(
        IUserStore users,
        IAgentStore agents,
        StepUpService stepUp,
        OidcTokenService tokens,
        IOidcStore oidcStore)
    {
        _users = users;
        _agents = agents;
        _stepUp = stepUp;
        _tokens = tokens;
        _oidcStore = oidcStore;
    }

    [HttpPost]
    public IActionResult Create([FromBody] CreateAgentRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.AgentName, Code.HttpBodies.NAME.Key, Code.HttpBodies.NAME.Regex);
            ValidateUtil.FormatParam(request.ClientId, Code.HttpBodies.CLIENT_ID.Key, Code.HttpBodies.CLIENT_ID.Regex);
            ValidateUtil.FormatParam(request.Scope, Code.HttpQueries.SCOPE.Key, Code.HttpQueries.SCOPE.Regex);
            ValidateUtil.IndispensableParam(request.StepUpToken, "step_up_token");
            if (!string.Equals(request.ClientId, AppConfig.DevelopmentClientId, StringComparison.Ordinal))
            {
                throw Code.ILLEGAL_CLIENT;
            }

            UserRecord owner = ValidateStepUpOwner(request.OwnerEmail, request.StepUpToken);
            int expiresDays = Math.Clamp(request.ExpiresDays, 1, 90);
            AgentCreateResult result = _agents.CreateAgent(
                owner,
                request.AgentName,
                request.ClientId,
                request.Scope,
                DateTimeOffset.UtcNow.AddDays(expiresDays));

            return Ok(new
            {
                agent_id = result.Agent.AgentId,
                agent_secret = result.AgentSecret,
                delegation_id = result.Delegation.DelegationId,
                scope = result.Delegation.Scope,
                expires_at = result.Delegation.ExpiresAt
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("{agent_id}/secret")]
    public IActionResult RotateSecret([FromRoute(Name = "agent_id")] string agentId, [FromBody] AgentOwnerStepUpRequest request)
    {
        try
        {
            ValidateUtil.IndispensableParam(agentId, "agent_id");
            UserRecord owner = ValidateStepUpOwner(request.OwnerEmail, request.StepUpToken);
            AgentSecretRotationResult result = _agents.RotateSecret(owner, agentId);

            return Ok(new
            {
                agent_id = result.Agent.AgentId,
                agent_secret = result.AgentSecret,
                rotated_at = result.Agent.UpdatedAt
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("{agent_id}/revoke")]
    public IActionResult Revoke([FromRoute(Name = "agent_id")] string agentId, [FromBody] AgentOwnerStepUpRequest request)
    {
        try
        {
            ValidateUtil.IndispensableParam(agentId, "agent_id");
            UserRecord owner = ValidateStepUpOwner(request.OwnerEmail, request.StepUpToken);
            AgentRecord agent = _agents.RevokeAgent(owner, agentId);

            return Ok(new
            {
                agent_id = agent.AgentId,
                status = agent.Status,
                revoked_at = agent.RevokedAt
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpPost("token")]
    public IActionResult Token([FromBody] AgentTokenRequest request)
    {
        try
        {
            ValidateUtil.IndispensableParam(request.AgentId, "agent_id");
            ValidateUtil.IndispensableParam(request.AgentSecret, "agent_secret");
            ValidateUtil.FormatParam(request.ClientId, Code.HttpBodies.CLIENT_ID.Key, Code.HttpBodies.CLIENT_ID.Regex);
            ValidateUtil.FormatParam(request.Scope, Code.HttpQueries.SCOPE.Key, Code.HttpQueries.SCOPE.Regex);
            AgentTokenGrant grant = _agents.VerifyTokenRequest(
                request.AgentId,
                request.AgentSecret,
                request.ClientId,
                request.Scope);
            SetTokenResponseCacheHeaders();
            return Ok(_tokens.CreateAgentTokenResponse(grant.Agent, grant.Delegation, grant.Scope));
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    [HttpGet("me")]
    public IActionResult Me([FromQuery(Name = "client_id")] string clientId, [FromQuery(Name = "scope")] string scope)
    {
        try
        {
            (string agentId, string agentSecret) = ReadBasicAgentCredential();
            ValidateUtil.FormatParam(clientId, Code.HttpBodies.CLIENT_ID.Key, Code.HttpBodies.CLIENT_ID.Regex);
            ValidateUtil.FormatParam(scope, Code.HttpQueries.SCOPE.Key, Code.HttpQueries.SCOPE.Regex);

            AgentTokenGrant grant = _agents.VerifyTokenRequest(agentId, agentSecret, clientId, scope);
            return Ok(new
            {
                principal_type = "ai_agent",
                agent_id = grant.Agent.AgentId,
                agent_name = grant.Agent.AgentName,
                owner_sub = grant.Agent.OwnerSubject,
                delegation_id = grant.Delegation.DelegationId,
                client_id = grant.Delegation.ClientId,
                scope = grant.Scope,
                expires_at = grant.Delegation.ExpiresAt,
                status = grant.Agent.Status
            });
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    private UserRecord ValidateStepUpOwner(string ownerEmail, string stepUpToken)
    {
        ValidateUtil.IndispensableParam(stepUpToken, "step_up_token");
        UserRecord owner = ResolveOwner(ownerEmail);
        StepUpGrant grant = _stepUp.ValidateStepUpToken(stepUpToken);
        if (!string.Equals(grant.Subject, owner.Subject, StringComparison.Ordinal))
        {
            throw Code.UNAUTHORIZED;
        }

        return owner;
    }

    private UserRecord ResolveOwner(string ownerEmail)
    {
        UserRecord? bearerOwner = FindBearerOwner();
        if (bearerOwner is not null)
        {
            return bearerOwner;
        }

        AuthSessionRecord? session = FindAuthSession();
        if (session is not null)
        {
            UserRecord sessionOwner = _users.FindByEmail(session.Email);
            if (!string.Equals(sessionOwner.Subject, session.Subject, StringComparison.Ordinal))
            {
                throw Code.UNAUTHORIZED;
            }

            return sessionOwner;
        }

        ValidateUtil.FormatParam(ownerEmail, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
        return _users.FindByEmail(ownerEmail);
    }

    private UserRecord? FindBearerOwner()
    {
        string header = Request.Headers.Authorization.ToString();
        const string prefix = "Bearer ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string accessToken = header[prefix.Length..].Trim();
        ValidateUtil.IndispensableParam(accessToken, "access_token");

        AccessTokenRecord token = _oidcStore.FindAccessToken(accessToken);
        if (!string.Equals(token.PrincipalType, "user", StringComparison.Ordinal)
            || !HasScope(token.Scope, Code.Scope.OPENID)
            || !HasScope(token.Scope, Code.Scope.PROFILE))
        {
            throw Code.UNAUTHORIZED;
        }

        UserRecord owner = _users.FindByEmail(token.Email);
        if (!string.Equals(owner.Subject, token.Subject, StringComparison.Ordinal))
        {
            throw Code.UNAUTHORIZED;
        }

        return owner;
    }

    private AuthSessionRecord? FindAuthSession()
    {
        string? sessionId = Request.Cookies[AuthSessionCookieName];
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            return null;
        }

        return _oidcStore.FindAuthSession(sessionId);
    }

    private (string AgentId, string AgentSecret) ReadBasicAgentCredential()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var rawHeader)
            || !AuthenticationHeaderValue.TryParse(rawHeader.ToString(), out AuthenticationHeaderValue? header)
            || !string.Equals(header.Scheme, "Basic", StringComparison.OrdinalIgnoreCase)
            || string.IsNullOrWhiteSpace(header.Parameter))
        {
            throw Code.UNAUTHORIZED;
        }

        try
        {
            string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header.Parameter));
            int separator = decoded.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0 || separator == decoded.Length - 1)
            {
                throw Code.UNAUTHORIZED;
            }

            return (decoded[..separator], decoded[(separator + 1)..]);
        }
        catch (FormatException)
        {
            throw Code.UNAUTHORIZED;
        }
    }

    private void SetTokenResponseCacheHeaders()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
    }

    private static bool HasScope(string scope, string requiredScope)
    {
        return scope
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(value => string.Equals(value, requiredScope, StringComparison.Ordinal));
    }
}

public sealed record CreateAgentRequest(
    [property: JsonPropertyName("owner_email")]
    string OwnerEmail,
    [property: JsonPropertyName("agent_name")]
    string AgentName,
    [property: JsonPropertyName("client_id")]
    string ClientId,
    [property: JsonPropertyName("scope")]
    string Scope,
    [property: JsonPropertyName("expires_days")]
    int ExpiresDays,
    [property: JsonPropertyName("step_up_token")]
    string StepUpToken);

public sealed record AgentOwnerStepUpRequest(
    [property: JsonPropertyName("owner_email")]
    string OwnerEmail,
    [property: JsonPropertyName("step_up_token")]
    string StepUpToken);

public sealed record AgentTokenRequest(
    [property: JsonPropertyName("agent_id")]
    string AgentId,
    [property: JsonPropertyName("agent_secret")]
    string AgentSecret,
    [property: JsonPropertyName("client_id")]
    string ClientId,
    [property: JsonPropertyName("scope")]
    string Scope);
