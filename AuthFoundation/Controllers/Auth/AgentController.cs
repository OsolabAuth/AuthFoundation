using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json.Serialization;

namespace AuthFoundation.Controllers.Auth;

[ApiController]
[Route("agent")]
public sealed class AgentController : ControllerBase
{
    private readonly IUserStore _users;
    private readonly IAgentStore _agents;
    private readonly StepUpService _stepUp;
    private readonly OidcTokenService _tokens;

    public AgentController(
        IUserStore users,
        IAgentStore agents,
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
            return Ok(_tokens.CreateAgentTokenResponse(grant.Agent, grant.Delegation, grant.Scope));
        }
        catch (ApiException ex)
        {
            return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
        }
    }

    private UserRecord ValidateStepUpOwner(string ownerEmail, string stepUpToken)
    {
        ValidateUtil.FormatParam(ownerEmail, Code.HttpBodies.EMAIL.Key, Code.HttpBodies.EMAIL.Regex);
        ValidateUtil.IndispensableParam(stepUpToken, "step_up_token");
        UserRecord owner = _users.FindByEmail(ownerEmail);
        StepUpGrant grant = _stepUp.ValidateStepUpToken(stepUpToken);
        if (!string.Equals(grant.Subject, owner.Subject, StringComparison.Ordinal))
        {
            throw Code.UNAUTHORIZED;
        }

        return owner;
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
