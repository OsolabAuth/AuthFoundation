using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// 認可セッションを表します。
    /// </summary>
    public class AuthRequestSession
    {
        /// <summary>
        /// Redis キープレフィックスを表します。
        /// </summary>
        public const string RedisKeyPrefix = "auth_request_session:";

        [JsonProperty("auth_request_session_id")]
        public string SessionId { get; set; } = string.Empty;

        [JsonProperty("response_type")]
        public string ResponseType { get; set; } = string.Empty;

        [JsonProperty("client_id")]
        public string ClientId { get; set; } = string.Empty;

        [JsonProperty("redirect_uri")]
        public string RedirectUri { get; set; } = string.Empty;

        [JsonProperty("state")]
        public string State { get; set; } = string.Empty;

        [JsonProperty("scope")]
        public string Scope { get; set; } = string.Empty;

        [JsonProperty("code_challenge_method")]
        public string CodeChallengeMethod { get; set; } = string.Empty;

        [JsonProperty("code_challenge")]
        public string CodeChallenge { get; set; } = string.Empty;

        [JsonProperty("nonce")]
        public string Nonce { get; set; } = string.Empty;

        [JsonProperty("osolab_id")]
        public string OsolabId { get; set; } = string.Empty;

        [JsonProperty("expires_at")]
        public string ExpiresAt { get; set; } = string.Empty;

        /// <summary>
        /// 認可セッションを初期化します。
        /// </summary>
        public AuthRequestSession()
        {
        }

        /// <summary>
        /// Redis から認可セッション文字列を読み込みます。
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

            return await redis.GetStringAsync(GetRedisKey(sessionId), Common.Code.RedisDbNo.AUTH_REQUEST_SESSION);
        }

        /// <summary>
        /// 文字列から認可セッションの値を設定します。
        /// </summary>
        /// <param name="value">セッション文字列</param>
        /// <returns>設定に成功した場合は true</returns>
        public bool SetValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            AuthRequestSession? session = JsonConvert.DeserializeObject<AuthRequestSession>(value);
            if (session == null)
            {
                return false;
            }

            SessionId = session.SessionId;
            ResponseType = session.ResponseType;
            ClientId = session.ClientId;
            RedirectUri = session.RedirectUri;
            State = session.State;
            Scope = session.Scope;
            CodeChallengeMethod = session.CodeChallengeMethod;
            CodeChallenge = session.CodeChallenge;
            Nonce = session.Nonce;
            OsolabId = session.OsolabId;
            ExpiresAt = session.ExpiresAt;
            return true;
        }

        /// <summary>
        /// Redis に認可セッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task WriteToRedisAsync(IRedisClient redis)
        {
            TimeSpan ttl = TimeSpan.FromSeconds(Code.AuthCode.EXPIRE_SEC);
            ExpiresAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(Code.AuthCode.EXPIRE_SEC));
            await redis.SetStringAsync(GetRedisKey(SessionId), JsonConvert.SerializeObject(this), ttl, Common.Code.RedisDbNo.AUTH_REQUEST_SESSION);
        }

        /// <summary>
        /// Redis に認可セッションを書き込みます。
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

