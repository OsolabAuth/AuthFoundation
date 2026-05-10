using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// RefreshTokenSession class.
    /// </summary>
    public class RefreshTokenSession
    {
        [JsonProperty("refresh_token")]
        /// <summary>
        /// Gets or sets RefreshToken.
        /// </summary>
        public string RefreshToken { get; set; } = string.Empty;

        [JsonProperty("osolab_id")]
        /// <summary>
        /// Gets or sets OsolabId.
        /// </summary>
        public string OsolabId { get; set; } = string.Empty;

        [JsonProperty("client_id")]
        /// <summary>
        /// Gets or sets ClientId.
        /// </summary>
        public string ClientId { get; set; } = string.Empty;

        [JsonProperty("scope")]
        /// <summary>
        /// Gets or sets Scope.
        /// </summary>
        public string Scope { get; set; } = string.Empty;

        [JsonProperty("expire_at")]
        /// <summary>
        /// Gets or sets ExpireAt.
        /// </summary>
        public string ExpireAt { get; set; } = string.Empty;

        /// <summary>
        /// Executes CreateSession.
        /// </summary>
        public async Task CreateSession(IRedisClient redis)
        {
            int expireSec = AppConfig.RefreshTokenExpireSec;
            if (expireSec <= 0)
            {
                throw new ApiException(Code.INTERNAL_SERVER_ERROR, "Invalid configuration value");
            }

            TimeSpan ttl = TimeSpan.FromSeconds(expireSec);
            ExpireAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(expireSec));
            string value = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(RefreshToken), value, ttl);
        }

        /// <summary>
        /// Executes GetRedisKey.
        /// </summary>
        public static string GetRedisKey(string refreshToken)
        {
            return $"{Code.RefreshToken.REDIS_KEY_PREFIX}{refreshToken}";
        }
    }
}
