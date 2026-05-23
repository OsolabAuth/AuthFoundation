using AuthFoundation.Common;
using AuthFoundation.Session;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace AuthFoundation.Controllers.Auth
{
    /// <summary>
    /// ログアウト処理を提供します。
    /// </summary>
    [ApiController]
    [Route("logout")]
    public class LogoutController : ControllerBase
    {
        private readonly IRedisClient _redis;

        /// <summary>
        /// <see cref="LogoutController"/> の新しいインスタンスを初期化します。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public LogoutController(IRedisClient redis)
        {
            _redis = redis;
        }

        /// <summary>
        /// ログアウト処理を実行し、セッションを破棄します。
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
                    string accessToken = ExtractBearerToken(authorization);
                    if (!string.IsNullOrWhiteSpace(accessToken))
                    {
                        await _redis.DeleteAsync(AccessTokenSession.GetRedisKey(accessToken), Code.RedisDbNo.ACCESS_TOKEN);
                    }
                }

                Response.Cookies.Delete(Code.AUTH_SESSION_COOKIE_KEY);
                Response.Cookies.Delete(Code.AUTH_REQUEST_SESSION_COOKIE_KEY);
                Response.Cookies.Delete("session_id");
                SetNoStoreHeaders(Response);

                return Ok(new
                {
                    response_code = Code.SUCCESS.Code,
                    result = hadLoginSession ? "logged_out" : "already_logged_out",
                    logout_all = input.LogoutAll
                });
            }
            catch (ApiException aex)
            {
                SetNoStoreHeaders(Response);
                return new ObjectResult(new ErrorOutput(aex)) { StatusCode = (int)aex.StatusCode };
            }
            catch (Exception ex)
            {
                ApiException aex = new ApiException(Code.INTERNAL_SERVER_ERROR, ex.Message);
                SetNoStoreHeaders(Response);
                return new ObjectResult(new ErrorOutput(aex)) { StatusCode = (int)aex.StatusCode };
            }
        }

        /// <summary>
        /// Authorization ヘッダーから Bearer トークンを抽出します。
        /// </summary>
        /// <param name="authorization">Authorization ヘッダー値</param>
        /// <returns>抽出したアクセストークン</returns>
        private static string ExtractBearerToken(string authorization)
        {
            if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return string.Empty;
            }

            string token = authorization["Bearer ".Length..].Trim();
            return Regex.IsMatch(token, @"^[A-Za-z0-9._~-]{20,}$")
                ? token
                : string.Empty;
        }

        /// <summary>
        /// レスポンスにキャッシュ無効ヘッダーを設定します。
        /// </summary>
        /// <param name="response">HTTP レスポンス</param>
        private static void SetNoStoreHeaders(HttpResponse response)
        {
            response.Headers["Cache-Control"] = "no-store";
            response.Headers["Pragma"] = "no-cache";
        }

        /// <summary>
        /// /logout 入力を表します。
        /// </summary>
        private sealed class Input
        {
            public string LogoutAllRaw { get; set; } = string.Empty;

            public bool LogoutAll { get; set; }

            /// <summary>
            /// HTTP リクエストからログアウト入力を生成します。
            /// </summary>
            /// <param name="context">HTTP コンテキスト</param>
            /// <returns>ログアウト入力</returns>
            public static async Task<Input> CreateAsync(HttpContext context)
            {
                HttpRequest request = context.Request;
                if (!string.IsNullOrWhiteSpace(request.ContentType)
                    && !Helper.HasContentType(request.ContentType, Code.Content.TYPE_X_WWW_FORM))
                {
                    throw new ApiException(Code.REQUEST_PARAMETER_ERROR, Code.REQUEST_PARAMETER_ERROR.ErrorDescription);
                }

                string logoutAll = string.Empty;
                if (request.HasFormContentType)
                {
                    IFormCollection form = await request.ReadFormAsync();
                    logoutAll = form[Code.HttpBodies.LOGOUT_ALL.Key].ToString();
                }

                return new Input
                {
                    LogoutAllRaw = logoutAll,
                    LogoutAll = string.Equals(logoutAll, "true", StringComparison.OrdinalIgnoreCase)
                };
            }

            /// <summary>
            /// ログアウト入力値を検証します。
            /// </summary>
            public void Validate()
            {
                if (string.IsNullOrWhiteSpace(LogoutAllRaw))
                {
                    LogoutAll = false;
                    return;
                }

                ValidateUtil.FormatParam(LogoutAllRaw, Code.HttpBodies.LOGOUT_ALL.Key, Code.HttpBodies.LOGOUT_ALL.Regex);
            }
        }

        private sealed class ErrorOutput
        {
            public string response_code { get; }
            public string message { get; }
            public string error { get; }
            public string error_code { get; }
            public string error_description { get; }

            /// <summary>
            /// API 例外からエラー出力を生成します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            public ErrorOutput(ApiException ex)
            {
                response_code = ex.InternalCode;
                message = ex.ErrorDescription;
                error = ToOAuthError(ex);
                error_code = ex.InternalCode;
                error_description = ex.ErrorDescription;
            }

            /// <summary>
            /// API 例外を OAuth エラーコードへ変換します。
            /// </summary>
            /// <param name="ex">API 例外</param>
            /// <returns>OAuth エラーコード</returns>
            private static string ToOAuthError(ApiException ex)
            {
                if (string.Equals(ex.InternalCode, Code.REQUEST_PARAMETER_ERROR.Code, StringComparison.Ordinal))
                {
                    return "invalid_request";
                }

                if (string.Equals(ex.InternalCode, Code.INTERNAL_SERVER_ERROR.Code, StringComparison.Ordinal))
                {
                    return "server_error";
                }

                return "invalid_request";
            }
        }
    }
}
