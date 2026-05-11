using AuthFoundation.Common;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// ログインセッションを表します。
    /// </summary>
    public class AuthSession
    {
        /// <summary>
        /// Redis キープレフィックスを表します。
        /// </summary>
        public const string RedisKeyPrefix = "login_session:";

        [JsonProperty("session_id")]
        public string SessionId { get; set; } = string.Empty;

        [JsonProperty("osolab_id")]
        public string OsolabId { get; set; } = string.Empty;

        [JsonProperty("email")]
        public string Email { get; set; } = string.Empty;

        [JsonProperty("client_id")]
        public string ClientId { get; set; } = string.Empty;

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;

        [JsonProperty("expires_at")]
        public string ExpiresAt { get; set; } = string.Empty;

        [JsonProperty("latest_auth_at")]
        public string LatestAuthAt { get; set; } = string.Empty;

        /// <summary>
        /// ログインセッションを初期化します。
        /// </summary>
        public AuthSession()
        {
        }

        /// <summary>
        /// ログインセッションを初期化します。
        /// </summary>
        /// <param name="sessionId">セッションID</param>
        /// <param name="osolabId">Osolab ID</param>
        /// <param name="email">メールアドレス</param>
        /// <param name="clientId">クライアントID</param>
        public AuthSession(string sessionId, string osolabId, string email, string clientId)
        {
            SessionId = sessionId;
            OsolabId = osolabId;
            Email = email;
            ClientId = clientId;
        }

        /// <summary>
        /// Cookie からログインセッションIDを取得します。
        /// </summary>
        /// <param name="request">HTTPリクエスト</param>
        /// <returns>セッションID</returns>
        public static string? GetCookieSessionId(HttpRequest request)
        {
            return request.Cookies[Code.AUTH_SESSION_COOKIE_KEY]
                ?? request.Cookies["session_id"];
        }

        /// <summary>
        /// ログインセッション Cookie を設定します。
        /// </summary>
        /// <param name="response">HTTPレスポンス</param>
        public void AppendCookie(HttpResponse response)
        {
            CookieOptions options = new CookieOptions
            {
                HttpOnly = true,
                Secure = false,
                SameSite = SameSiteMode.Lax,
                MaxAge = TimeSpan.FromSeconds(AppConfig.SessionExpireSec)
            };

            response.Cookies.Append(Code.AUTH_SESSION_COOKIE_KEY, SessionId, options);
            response.Cookies.Append("session_id", SessionId, options);
        }

        /// <summary>
        /// Redis からログインセッション文字列を読み込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="sessionId">セッションID</param>
        /// <returns>セッション文字列</returns>
        public async Task<string?> ReadValueFromRedisAsync(IRedisClient redis, string? sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                return null;
            }

            return await redis.GetStringAsync(GetRedisKey(sessionId));
        }

        /// <summary>
        /// 文字列からログインセッションの値を設定します。
        /// </summary>
        /// <param name="value">セッション文字列</param>
        /// <returns>設定に成功した場合は true</returns>
        public bool SetValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            AuthSession? session = JsonConvert.DeserializeObject<AuthSession>(value);
            if (session == null)
            {
                return false;
            }

            SessionId = session.SessionId;
            OsolabId = session.OsolabId;
            Email = session.Email;
            ClientId = session.ClientId;
            CreatedAt = session.CreatedAt;
            ExpiresAt = session.ExpiresAt;
            LatestAuthAt = session.LatestAuthAt;
            return true;
        }

        /// <summary>
        /// Redis にログインセッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        /// <exception cref="ApiException">500:設定値が不正</exception>
        public async Task WriteToRedisAsync(IRedisClient redis)
        {
            int sessionExpireSeconds = AppConfig.SessionExpireSec;
            if (sessionExpireSeconds <= 0)
            {
                throw new ApiException(Code.INTERNAL_SERVER_ERROR, "Invalid configuration value");
            }

            TimeSpan sessionExpire = TimeSpan.FromSeconds(sessionExpireSeconds);
            DateTime now = DateTimeHelper.GetJstNow();
            CreatedAt = DateTimeHelper.ToJstString(now);
            LatestAuthAt = DateTimeHelper.ToJstString(now);
            ExpiresAt = DateTimeHelper.ToJstString(now.AddSeconds(sessionExpireSeconds));

            await redis.SetStringAsync(GetRedisKey(SessionId), JsonConvert.SerializeObject(this), sessionExpire);
        }

        /// <summary>
        /// Redis にログインセッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task CreateSession(IRedisClient redis)
        {
            await WriteToRedisAsync(redis);
        }

        /// <summary>
        /// Redis キーを取得します。
        /// </summary>
        /// <param name="sessionId">セッションID</param>
        /// <returns>Redis キー</returns>
        public static string GetRedisKey(string sessionId)
        {
            return $"{RedisKeyPrefix}{sessionId}";
        }
    }
}
