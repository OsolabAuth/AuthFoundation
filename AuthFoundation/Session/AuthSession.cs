using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    public class AuthSession
    {
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

        public AuthSession() { }

        public AuthSession(string sessionId, string osolabId, string email, string clientId)
        {
            SessionId = sessionId;
            OsolabId = osolabId;
            Email = email;
            ClientId = clientId;
        }

        public async Task CreateSession(IRedisClient redis)
        {
            int sessionExpireSeconds = AppConfig.SessionExpireSec;
            if (sessionExpireSeconds <= 0)
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }

            TimeSpan sessionExpire = TimeSpan.FromSeconds(sessionExpireSeconds);
            DateTime now = DateTimeHelper.GetJstNow();
            CreatedAt = DateTimeHelper.ToJstString(now);
            LatestAuthAt = DateTimeHelper.ToJstString(now);
            ExpiresAt = DateTimeHelper.ToJstString(now.AddSeconds(sessionExpireSeconds));

            string sessionObjectString = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(SessionId), sessionObjectString, sessionExpire);
        }

        public static string GetRedisKey(string sessionId) => $"{RedisKeyPrefix}{sessionId}";
    }

    public class AuthorizationSession
    {
        public const string RedisKeyPrefix = "authz_session:";

        [JsonProperty("session_id")]
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

        public async Task CreateSession(IRedisClient redis)
        {
            TimeSpan ttl = TimeSpan.FromSeconds(Code.AuthCode.EXPIRE_SEC);
            ExpiresAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(Code.AuthCode.EXPIRE_SEC));
            string value = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(SessionId), value, ttl);
        }

        public static string GetRedisKey(string sessionId) => $"{RedisKeyPrefix}{sessionId}";
    }
}
