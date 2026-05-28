using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("agent")]
public sealed class AgentController : ControllerBase
{
    private readonly InMemoryUserStore _users;
    private readonly InMemoryAgentStore _agents;
    private readonly StepUpService _stepUp;
    private readonly OidcTokenService _tokens;

    public AgentController(
        InMemoryUserStore users,
        InMemoryAgentStore agents,
        StepUpService stepUp,
        OidcTokenService tokens)
    {
        _users = users;
        _agents = agents;
        _stepUp = stepUp;
        _tokens = tokens;
    }

    [HttpPost]
    public IActionResult Create([FromBody] CreateAgentRequest request)
    {
        try
        {
            ValidateUtil.FormatParam(request.OwnerEmail, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
            ValidateUtil.FormatParam(request.AgentName, Code.HttpBodies.NAME.Key, Code.HttpBodies.NAME.Regex);
            ValidateUtil.FormatParam(request.ClientId, Code.HttpBodies.CLIENT_ID.Key, Code.HttpBodies.CLIENT_ID.Regex);
            ValidateUtil.FormatParam(request.Scope, Code.HttpQueries.SCOPE.Key, Code.HttpQueries.SCOPE.Regex);
            ValidateUtil.IndispensableParam(request.StepUpToken, "step_up_token");
            if (!string.Equals(request.ClientId, AppConfig.DevelopmentClientId, StringComparison.Ordinal))
            {
                throw Code.ILLEGAL_CLIENT;
            }

            UserRecord owner = _users.FindByEmail(request.OwnerEmail);
            StepUpGrant grant = _stepUp.ValidateStepUpToken(request.StepUpToken);
            if (!string.Equals(grant.Subject, owner.Subject, StringComparison.Ordinal))
            {
                throw Code.UNAUTHORIZED;
            }

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
            return Ok(_tokens.CreateAgentTokenResponse(grant.Agent, grant.Delegation, grant.Scope));
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
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

public sealed record AgentTokenRequest(
    [property: JsonPropertyName("agent_id")]
    string AgentId,
    [property: JsonPropertyName("agent_secret")]
    string AgentSecret,
    [property: JsonPropertyName("client_id")]
    string ClientId,
    [property: JsonPropertyName("scope")]
    string Scope);
