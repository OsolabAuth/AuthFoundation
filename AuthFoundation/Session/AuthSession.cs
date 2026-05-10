using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// AuthSession class.
    /// </summary>
    public class AuthSession
    {
        public const string RedisKeyPrefix = "login_session:";

        [JsonProperty("session_id")]
        /// <summary>
        /// Gets or sets SessionId.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        [JsonProperty("osolab_id")]
        /// <summary>
        /// Gets or sets OsolabId.
        /// </summary>
        public string OsolabId { get; set; } = string.Empty;

        [JsonProperty("email")]
        /// <summary>
        /// Gets or sets Email.
        /// </summary>
        public string Email { get; set; } = string.Empty;

        [JsonProperty("client_id")]
        /// <summary>
        /// Gets or sets ClientId.
        /// </summary>
        public string ClientId { get; set; } = string.Empty;

        [JsonProperty("created_at")]
        /// <summary>
        /// Gets or sets CreatedAt.
        /// </summary>
        public string CreatedAt { get; set; } = string.Empty;

        [JsonProperty("expires_at")]
        /// <summary>
        /// Gets or sets ExpiresAt.
        /// </summary>
        public string ExpiresAt { get; set; } = string.Empty;

        [JsonProperty("latest_auth_at")]
        /// <summary>
        /// Gets or sets LatestAuthAt.
        /// </summary>
        public string LatestAuthAt { get; set; } = string.Empty;

        /// <summary>
        /// Initializes a new instance of AuthSession.
        /// </summary>
        public AuthSession() { }

        /// <summary>
        /// Initializes a new instance of AuthSession.
        /// </summary>
        public AuthSession(string sessionId, string osolabId, string email, string clientId)
        {
            SessionId = sessionId;
            OsolabId = osolabId;
            Email = email;
            ClientId = clientId;
        }

        /// <summary>
        /// Executes CreateSession.
        /// </summary>
        public async Task CreateSession(IRedisClient redis)
        {
            int sessionExpireSeconds = AppConfig.SessionExpireSec;
            if (sessionExpireSeconds <= 0)
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "Invalid configuration value");
            }

            TimeSpan sessionExpire = TimeSpan.FromSeconds(sessionExpireSeconds);
            DateTime now = DateTimeHelper.GetJstNow();
            CreatedAt = DateTimeHelper.ToJstString(now);
            LatestAuthAt = DateTimeHelper.ToJstString(now);
            ExpiresAt = DateTimeHelper.ToJstString(now.AddSeconds(sessionExpireSeconds));

            string sessionObjectString = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(SessionId), sessionObjectString, sessionExpire);
        }

        /// <summary>
        /// Executes GetRedisKey.
        /// </summary>
        public static string GetRedisKey(string sessionId) => $"{RedisKeyPrefix}{sessionId}";
    }

    /// <summary>
    /// AuthorizationSession class.
    /// </summary>
    public class AuthorizationSession
    {
        public const string RedisKeyPrefix = "authz_session:";

        [JsonProperty("session_id")]
        /// <summary>
        /// Gets or sets SessionId.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;

        [JsonProperty("response_type")]
        /// <summary>
        /// Gets or sets ResponseType.
        /// </summary>
        public string ResponseType { get; set; } = string.Empty;

        [JsonProperty("client_id")]
        /// <summary>
        /// Gets or sets ClientId.
        /// </summary>
        public string ClientId { get; set; } = string.Empty;

        [JsonProperty("redirect_uri")]
        /// <summary>
        /// Gets or sets RedirectUri.
        /// </summary>
        public string RedirectUri { get; set; } = string.Empty;

        [JsonProperty("state")]
        /// <summary>
        /// Gets or sets State.
        /// </summary>
        public string State { get; set; } = string.Empty;

        [JsonProperty("scope")]
        /// <summary>
        /// Gets or sets Scope.
        /// </summary>
        public string Scope { get; set; } = string.Empty;

        [JsonProperty("code_challenge_method")]
        /// <summary>
        /// Gets or sets CodeChallengeMethod.
        /// </summary>
        public string CodeChallengeMethod { get; set; } = string.Empty;

        [JsonProperty("code_challenge")]
        /// <summary>
        /// Gets or sets CodeChallenge.
        /// </summary>
        public string CodeChallenge { get; set; } = string.Empty;

        [JsonProperty("nonce")]
        /// <summary>
        /// Gets or sets Nonce.
        /// </summary>
        public string Nonce { get; set; } = string.Empty;

        [JsonProperty("osolab_id")]
        /// <summary>
        /// Gets or sets OsolabId.
        /// </summary>
        public string OsolabId { get; set; } = string.Empty;

        [JsonProperty("expires_at")]
        /// <summary>
        /// Gets or sets ExpiresAt.
        /// </summary>
        public string ExpiresAt { get; set; } = string.Empty;

        /// <summary>
        /// Executes CreateSession.
        /// </summary>
        public async Task CreateSession(IRedisClient redis)
        {
            TimeSpan ttl = TimeSpan.FromSeconds(Code.AuthCode.EXPIRE_SEC);
            ExpiresAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(Code.AuthCode.EXPIRE_SEC));
            string value = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(SessionId), value, ttl);
        }

        /// <summary>
        /// Executes GetRedisKey.
        /// </summary>
        public static string GetRedisKey(string sessionId) => $"{RedisKeyPrefix}{sessionId}";
    }
}
