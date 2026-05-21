using AuthFoundation.Common;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// ログアウト処理を提供します。
    /// </summary>
    [ApiController]
    [Route("logout")]
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
                input.Validate();

                string? loginSessionId = AuthSession.GetCookieSessionId(Request);
                bool hadLoginSession = false;
                if (!string.IsNullOrWhiteSpace(loginSessionId))
                {
                    AuthSession session = new AuthSession();
                    string? raw = await session.ReadValueFromRedisAsync(_redis, loginSessionId);
                    if (!string.IsNullOrWhiteSpace(raw) && session.SetValue(raw))
                    {
                        hadLoginSession = true;
                        await session.DeleteSessionAsync(_redis);
                    }
                }

                string authorization = Request.Headers.Authorization.ToString();
                if (!string.IsNullOrWhiteSpace(authorization))
                {
                    ValidateUtil.FormatParam(authorization, Code.HttpHeaders.AUTHORIZATION_BEARER.Key, Code.HttpHeaders.AUTHORIZATION_BEARER.Regex);
                    string accessToken = authorization["Bearer ".Length..].Trim();
                    await _redis.DeleteAsync(AccessTokenSession.GetRedisKey(accessToken), Code.RedisDbNo.ACCESS_TOKEN);
                }

                Response.Cookies.Delete(Code.AUTH_SESSION_COOKIE_KEY);
                Response.Cookies.Delete(Code.AUTH_REQUEST_SESSION_COOKIE_KEY);
                Response.Cookies.Delete("session_id");

                return Ok(new
                {
                    response_code = Code.SUCCESS.Code,
                    result = hadLoginSession ? "logged_out" : "already_logged_out",
                    logout_all = input.LogoutAll
                });
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new { response_code = aex.Code, message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
            catch (Exception ex)
            {
                ApiException aex = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                return new ObjectResult(new { response_code = aex.Code, message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
        }

        private sealed class Input
        {
            public string LogoutAllRaw { get; set; } = string.Empty;

            public bool LogoutAll { get; set; }

            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                Helper.ValidateTypeFormUrlEncoded(request.ContentType);
                IFormCollection form = await request.ReadFormAsync();
                string logoutAll = form[Code.HttpBodies.LOGOUT_ALL.Key].ToString();
                return new Input
                {
                    LogoutAllRaw = logoutAll,
                    LogoutAll = string.Equals(logoutAll, "true", StringComparison.OrdinalIgnoreCase)
                };
            }

            public void Validate()
            {
                ValidateUtil.IndispensableParam(LogoutAllRaw, Code.HttpBodies.LOGOUT_ALL.Key);
                ValidateUtil.FormatParam(LogoutAllRaw, Code.HttpBodies.LOGOUT_ALL.Key, Code.HttpBodies.LOGOUT_ALL.Regex);
            }
        }
    }
}
