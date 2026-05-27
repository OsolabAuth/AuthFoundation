using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;

namespace AuthFoundation.Controllers.Agent
{
    [ApiController]
    [Route("agent")]
    public class AgentController : ControllerBase
    {
        private const int AgentIdHexLength = 24;
        private const int AgentSecretHexLength = 64;
        private const int DelegationIdHexLength = 24;
        private static readonly HashSet<string> AllowedDelegationScopes = new(StringComparer.Ordinal)
        {
            "task.read",
            "task.create",
            "task.comment"
        };

        private readonly OsolabAuthContext _dbContext;
        private readonly IRedisClient _redis;

        public AgentController(OsolabAuthContext dbContext, IRedisClient redis)
        {
            _dbContext = dbContext;
            _redis = redis;
        }

        [HttpPost]
        public async Task<IActionResult> PostAgent()
        {
            try
            {
                PostInput input = await PostInput.CreateAsync(Request.HttpContext);
                input.Validate();

                AuthSession session = await RequireAuthSessionAsync();
                osolab_user owner = await RequireActiveOwnerAsync(session.OsolabId);

                DateTime now = DateTime.UtcNow;
                string agentId = await GenerateUniqueAgentIdAsync();
                string agentSecret = GenerateAgentSecret();

                _dbContext.agent_masters.Add(new agent_master
                {
                    agent_id = agentId,
                    owner_osolab_id = owner.osolab_id,
                    agent_name = input.AgentName,
                    secret_hash = AgentSecretHasher.ComputeHash(agentSecret),
                    create_datetime = now,
                    update_datetime = now,
                    status = Code.Status.ACTIVE
                });

                AddAuditLog(agentId, owner.osolab_id, "agent.created", "success", now);
                AddAuditLog(agentId, owner.osolab_id, "agent.secret_issued", "success", now);

                await _dbContext.SaveChangesAsync();
                return Ok(new PostOutput(agentId, agentSecret, input.AgentName));
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx)) { StatusCode = (int)apiEx.StatusCode };
            }
        }

        [HttpPost("{agentId}/delegations")]
        public async Task<IActionResult> PostDelegation(string agentId)
        {
            try
            {
                PostDelegationInput input = await PostDelegationInput.CreateAsync(Request.HttpContext);
                input.Validate();

                AuthSession session = await RequireAuthSessionAsync();
                osolab_user owner = await RequireActiveOwnerAsync(session.OsolabId);
                agent_master agent = await RequireOwnedActiveAgentAsync(agentId, owner.osolab_id);
                await RequireActiveClientAsync(input.ClientId);

                string[] scopes = NormalizeScopes(input.Scope);
                DateTime expiresAt = input.GetExpiresDateTime();
                DateTime now = DateTime.UtcNow;
                if (expiresAt <= now)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "expires_datetime must be in the future");
                }

                string delegationId = await GenerateUniqueDelegationIdAsync();
                string scope = string.Join(' ', scopes);

                _dbContext.agent_delegations.Add(new agent_delegation
                {
                    delegation_id = delegationId,
                    agent_id = agent.agent_id,
                    owner_osolab_id = owner.osolab_id,
                    client_id = input.ClientId,
                    scopes = scope,
                    expires_datetime = expiresAt,
                    verified_datetime = now,
                    create_datetime = now,
                    update_datetime = now,
                    status = Code.Status.ACTIVE
                });

                AddAuditLog(
                    agent.agent_id,
                    owner.osolab_id,
                    "agent.delegation_created",
                    "success",
                    now,
                    delegationId,
                    input.ClientId,
                    scope);

                await _dbContext.SaveChangesAsync();
                return Ok(new PostDelegationOutput(delegationId, agent.agent_id, input.ClientId, scope, expiresAt));
            }
            catch (ApiException ex)
            {
                return new ObjectResult(new ErrorOutput(ex)) { StatusCode = (int)ex.StatusCode };
            }
            catch (Exception ex)
            {
                ApiException apiEx = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new ErrorOutput(apiEx)) { StatusCode = (int)apiEx.StatusCode };
            }
        }

        private async Task<AuthSession> RequireAuthSessionAsync()
        {
            string? sessionId = AuthSession.GetCookieSessionId(Request);
            var session = new AuthSession();
            await session.ReadFromRedisAsync(_redis, sessionId);
            if (!session.HasValue)
            {
                throw new ApiException(Code.UNAUTHORIZED, Code.UNAUTHORIZED.ErrorDescription);
            }

            return session;
        }

        private async Task<osolab_user> RequireActiveOwnerAsync(string osolabId)
        {
            osolab_user? owner = await _dbContext.osolab_users.SingleOrDefaultAsync(x =>
                x.osolab_id == osolabId &&
                x.status == Code.Status.ACTIVE);

            if (owner is null)
            {
                throw new ApiException(Code.UNAUTHORIZED, Code.UNAUTHORIZED.ErrorDescription);
            }

            return owner;
        }

        private async Task<agent_master> RequireOwnedActiveAgentAsync(string agentId, string ownerOsolabId)
        {
            ValidateUtil.IndispensableParam(agentId, "agent_id");
            ValidateUtil.FormatParam(agentId, "agent_id", @"^agent_[a-f0-9]{24}$");

            agent_master? agent = await _dbContext.agent_masters.SingleOrDefaultAsync(x =>
                x.agent_id == agentId &&
                x.owner_osolab_id == ownerOsolabId &&
                x.status == Code.Status.ACTIVE &&
                x.revoked_datetime == null);

            if (agent is null)
            {
                throw new ApiException(Code.UNAUTHORIZED, Code.UNAUTHORIZED.ErrorDescription);
            }

            return agent;
        }

        private async Task RequireActiveClientAsync(string clientId)
        {
            bool exists = await _dbContext.client_masters.AnyAsync(x =>
                x.client_id == clientId &&
                x.status == Code.Status.ACTIVE);

            if (!exists)
            {
                throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorDescription);
            }
        }

        private async Task<string> GenerateUniqueAgentIdAsync()
        {
            for (int i = 0; i < 10; i++)
            {
                string candidate = $"agent_{Helper.GenerateHex(AgentIdHexLength).ToLowerInvariant()}";
                bool exists = await _dbContext.agent_masters.AnyAsync(x => x.agent_id == candidate);
                if (!exists)
                {
                    return candidate;
                }
            }

            throw new ApiException(Code.ID_GENERATION_ERROR, "failed to generate agent_id");
        }

        private async Task<string> GenerateUniqueDelegationIdAsync()
        {
            for (int i = 0; i < 10; i++)
            {
                string candidate = $"delegation_{Helper.GenerateHex(DelegationIdHexLength).ToLowerInvariant()}";
                bool exists = await _dbContext.agent_delegations.AnyAsync(x => x.delegation_id == candidate);
                if (!exists)
                {
                    return candidate;
                }
            }

            throw new ApiException(Code.ID_GENERATION_ERROR, "failed to generate delegation_id");
        }

        private static string GenerateAgentSecret()
        {
            return $"ags_{Helper.GenerateHex(AgentSecretHexLength).ToLowerInvariant()}";
        }

        private static string[] NormalizeScopes(string scope)
        {
            string[] scopes = scope
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

            if (scopes.Length == 0 || scopes.Any(x => !AllowedDelegationScopes.Contains(x)))
            {
                throw new ApiException(Code.INVALID_SCOPE, Code.INVALID_SCOPE.ErrorDescription);
            }

            return scopes;
        }

        private void AddAuditLog(
            string agentId,
            string ownerOsolabId,
            string eventType,
            string result,
            DateTime now,
            string? delegationId = null,
            string? clientId = null,
            string? scope = null)
        {
            _dbContext.agent_audit_logs.Add(new agent_audit_log
            {
                agent_id = agentId,
                owner_osolab_id = ownerOsolabId,
                delegation_id = delegationId,
                event_type = eventType,
                client_id = clientId,
                scope = scope,
                result = result,
                ip_address = Request.HttpContext.Connection.RemoteIpAddress?.ToString(),
                user_agent = Request.Headers.UserAgent.ToString(),
                create_datetime = now
            });
        }

        private sealed class PostInput
        {
            [JsonProperty("agent_name")]
            public string AgentName { get; set; } = string.Empty;

            public static async Task<PostInput> CreateAsync(HttpContext context)
            {
                Helper.ValidateTypeApplicationJson(context.Request.ContentType);
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                string raw = await reader.ReadToEndAsync();
                PostInput? body = JsonConvert.DeserializeObject<PostInput>(raw);
                if (body is null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "invalid json object");
                }

                body.AgentName = body.AgentName.Trim();
                return body;
            }

            public void Validate()
            {
                ValidateUtil.IndispensableParam(AgentName, "agent_name");
                ValidateUtil.FormatParam(AgentName, "agent_name", @"^.{1,128}$");
            }
        }

        private sealed class PostDelegationInput
        {
            [JsonProperty("client_id")]
            public string ClientId { get; set; } = string.Empty;

            [JsonProperty("scope")]
            public string Scope { get; set; } = string.Empty;

            [JsonProperty("expires_datetime")]
            public string ExpiresDatetime { get; set; } = string.Empty;

            public static async Task<PostDelegationInput> CreateAsync(HttpContext context)
            {
                Helper.ValidateTypeApplicationJson(context.Request.ContentType);
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                string raw = await reader.ReadToEndAsync();
                PostDelegationInput? body = JsonConvert.DeserializeObject<PostDelegationInput>(raw);
                if (body is null)
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "invalid json object");
                }

                body.ClientId = body.ClientId.Trim();
                body.Scope = body.Scope.Trim();
                body.ExpiresDatetime = body.ExpiresDatetime.Trim();
                return body;
            }

            public void Validate()
            {
                ValidateUtil.IndispensableParam(ClientId, Code.HttpQueries.CLIENT_ID.Key);
                ValidateUtil.FormatParam(ClientId, Code.HttpQueries.CLIENT_ID.Key, Code.HttpQueries.CLIENT_ID.Regex);
                ValidateUtil.IndispensableParam(Scope, Code.HttpQueries.SCOPE.Key);
                ValidateUtil.FormatParam(Scope, Code.HttpQueries.SCOPE.Key, @"^[A-Za-z0-9_. ]{1,1000}$");
                ValidateUtil.IndispensableParam(ExpiresDatetime, "expires_datetime");
                GetExpiresDateTime();
            }

            public DateTime GetExpiresDateTime()
            {
                if (!DateTimeOffset.TryParse(ExpiresDatetime, out DateTimeOffset expiresAt))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, "expires_datetime is invalid");
                }

                return expiresAt.UtcDateTime;
            }
        }

        private sealed class PostOutput
        {
            [JsonProperty("response_code")]
            public string ResponseCode { get; } = Code.SUCCESS.Code;

            [JsonProperty("message")]
            public string Message { get; } = Code.SUCCESS.ErrorDescription;

            [JsonProperty("agent_id")]
            public string AgentId { get; }

            [JsonProperty("agent_secret")]
            public string AgentSecret { get; }

            [JsonProperty("agent_name")]
            public string AgentName { get; }

            public PostOutput(string agentId, string agentSecret, string agentName)
            {
                AgentId = agentId;
                AgentSecret = agentSecret;
                AgentName = agentName;
            }
        }

        private sealed class PostDelegationOutput
        {
            [JsonProperty("response_code")]
            public string ResponseCode { get; } = Code.SUCCESS.Code;

            [JsonProperty("message")]
            public string Message { get; } = Code.SUCCESS.ErrorDescription;

            [JsonProperty("delegation_id")]
            public string DelegationId { get; }

            [JsonProperty("agent_id")]
            public string AgentId { get; }

            [JsonProperty("client_id")]
            public string ClientId { get; }

            [JsonProperty("scope")]
            public string Scope { get; }

            [JsonProperty("expires_datetime")]
            public DateTime ExpiresDatetime { get; }

            public PostDelegationOutput(
                string delegationId,
                string agentId,
                string clientId,
                string scope,
                DateTime expiresDatetime)
            {
                DelegationId = delegationId;
                AgentId = agentId;
                ClientId = clientId;
                Scope = scope;
                ExpiresDatetime = expiresDatetime;
            }
        }

        private sealed class ErrorOutput
        {
            [JsonProperty("response_code")]
            public string ResponseCode { get; }

            [JsonProperty("error_code")]
            public string ErrorCode { get; }

            [JsonProperty("message")]
            public string Message { get; }

            [JsonProperty("error")]
            public string Error { get; }

            [JsonProperty("error_description")]
            public string ErrorDescription { get; }

            public ErrorOutput(ApiException ex)
            {
                ResponseCode = ex.InternalCode;
                ErrorCode = ex.InternalCode;
                Message = ex.ErrorDescription;
                Error = ex.Error;
                ErrorDescription = ex.ErrorDescription;
            }
        }
    }
}
