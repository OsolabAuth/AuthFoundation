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

        private static string GenerateAgentSecret()
        {
            return $"ags_{Helper.GenerateHex(AgentSecretHexLength).ToLowerInvariant()}";
        }

        private void AddAuditLog(string agentId, string ownerOsolabId, string eventType, string result, DateTime now)
        {
            _dbContext.agent_audit_logs.Add(new agent_audit_log
            {
                agent_id = agentId,
                owner_osolab_id = ownerOsolabId,
                event_type = eventType,
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
