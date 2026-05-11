using AuthFoundation.Common;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// ログアウト処理を提供します。
    /// </summary>
    [ApiController]
    [Route("Logout")]
    public class LogoutController : ControllerBase
    {
        private readonly IRedisClient _redis;

        /// <summary>
        /// LogoutController を初期化します。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public LogoutController(IRedisClient redis)
        {
            _redis = redis;
        }

        /// <summary>
        /// ログアウトを実行します。
        /// </summary>
        /// <returns>ログアウト結果</returns>
        [HttpPost]
        public async Task<IActionResult> PostLogout()
        {
            try
            {
                Input input = await Input.CreateAsync(Request.HttpContext);
                string? loginSessionId = AuthSession.GetCookieSessionId(Request);
                AuthSession? loginSession = null;
                if (!string.IsNullOrWhiteSpace(loginSessionId))
                {
                    AuthSession session = new AuthSession();
                    string? raw = await session.ReadValueFromRedisAsync(_redis, loginSessionId);
                    if (!string.IsNullOrWhiteSpace(raw) && session.SetValue(raw))
                    {
                        loginSession = session;
                        await _redis.DeleteAsync(AuthSession.GetRedisKey(loginSessionId));
                    }
                }

                Response.Cookies.Delete(Code.AUTH_SESSION_COOKIE_KEY);
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

        /// <summary>
        /// ログアウト入力を表します。
        /// </summary>
        public class Input
        {
            public bool LogoutAll { get; set; }

            public string? AccessToken { get; set; }

            public string? IdTokenJti { get; set; }

            /// <summary>
            /// HTTP リクエストから入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>ログアウト入力</returns>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeApplicationJson(request.ContentType);

                using StreamReader reader = new StreamReader(request.Body);
                string raw = await reader.ReadToEndAsync();
                JObject body = string.IsNullOrWhiteSpace(raw) ? new JObject() : JObject.Parse(raw);
                string auth = request.Headers["Authorization"].ToString();
                string? token = null;
                if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    token = auth["Bearer ".Length..].Trim();
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
