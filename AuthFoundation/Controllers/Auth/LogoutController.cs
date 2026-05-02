using AuthFoundation.Common;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthFoundation.Controllers.Auth
{
    [ApiController]
    [Route("Logout")]
    public class LogoutController : ControllerBase
    {
        private readonly IRedisClient _redis;

        public LogoutController(IRedisClient redis)
        {
            _redis = redis;
        }

        [HttpPost]
        public async Task<IActionResult> PostLogout()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                string? loginSessionId = Request.Cookies["session_id"];
                AuthSession? loginSession = null;
                if (!string.IsNullOrWhiteSpace(loginSessionId))
                {
                    string? raw = await _redis.GetStringAsync(AuthSession.GetRedisKey(loginSessionId));
                    if (!string.IsNullOrWhiteSpace(raw))
                    {
                        loginSession = JsonConvert.DeserializeObject<AuthSession>(raw);
                        await _redis.DeleteAsync(AuthSession.GetRedisKey(loginSessionId));
                    }
                }

                Response.Cookies.Delete("session_id");

                if (!string.IsNullOrWhiteSpace(input.AccessToken))
                {
                    await _redis.DeleteAsync(AccessTokenSession.GetRedisKey(input.AccessToken));
                }

                if (!string.IsNullOrWhiteSpace(input.IdTokenJti) && loginSession != null)
                {
                    await _redis.SetJsonAsync($"id_token_jti:{input.IdTokenJti}", new
                    {
                        jti = input.IdTokenJti,
                        osolab_id = loginSession.OsolabId,
                        revoked_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        reason = "logout"
                    }, TimeSpan.FromHours(1));
                }

                if (input.LogoutAll && loginSession != null)
                {
                    await _redis.SetJsonAsync($"logout_all:{loginSession.OsolabId}", new
                    {
                        revoked_after = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                        reason = "logout_all"
                    }, TimeSpan.FromDays(30));
                }

                return Ok(new { StatusCode = Code.SUCCESS.Code, Message = "logout completed" });
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new { StatusCode = aex.Code, Message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
        }

        public class Input
        {
            public bool LogoutAll { get; set; }
            public string? AccessToken { get; set; }
            public string? IdTokenJti { get; set; }

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeApplicationJson(request.ContentType);
                using var reader = new StreamReader(request.Body);
                string raw = await reader.ReadToEndAsync();
                JObject body = string.IsNullOrWhiteSpace(raw) ? new JObject() : JObject.Parse(raw);
                string auth = request.Headers["Authorization"].ToString();
                string? token = null;
                if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    token = auth.Substring("Bearer ".Length).Trim();
                }
                return new Input
                {
                    LogoutAll = body.Value<bool?>("logout_all") ?? false,
                    AccessToken = token,
                    IdTokenJti = body.Value<string>("id_token_jti")
                };
            }
        }
    }
}
