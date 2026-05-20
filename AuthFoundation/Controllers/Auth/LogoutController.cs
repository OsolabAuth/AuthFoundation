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
                string? loginSessionId = AuthSession.GetCookieSessionId(Request);
                AuthSession? loginSession = null;
                if (!string.IsNullOrWhiteSpace(loginSessionId))
                {
                    AuthSession session = new AuthSession();
                    string? raw = await session.ReadValueFromRedisAsync(_redis, loginSessionId);
                    if (!string.IsNullOrWhiteSpace(raw) && session.SetValue(raw))
                    {
                        loginSession = session;
                        await session.DeleteSessionAsync(_redis);
                    }
                }

                Response.Cookies.Delete(Code.AUTH_SESSION_COOKIE_KEY);
                Response.Cookies.Delete("session_id");

                return Ok(new { StatusCode = Code.SUCCESS.Code, Message = "logout completed" });
            }
            catch (ApiException aex)
            {
                return new ObjectResult(new { StatusCode = aex.Code, Message = aex.ErrorMessage }) { StatusCode = (int)aex.Status };
            }
        }
    }
}
