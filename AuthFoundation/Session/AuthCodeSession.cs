using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// AuthCodeSession class.
    /// </summary>
    public class AuthCodeSession
    {
        [JsonProperty("code")]
        /// <summary>
        /// Gets or sets Code.
        /// </summary>
        public string Code { get; set; } = string.Empty;

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

        [JsonProperty("redirect_uri")]
        /// <summary>
        /// Gets or sets RedirectUri.
        /// </summary>
        public string RedirectUri { get; set; } = string.Empty;

        [JsonProperty("scope")]
        /// <summary>
        /// Gets or sets Scope.
        /// </summary>
        public string Scope { get; set; } = string.Empty;

        [JsonProperty("code_challenge")]
        /// <summary>
        /// Gets or sets CodeChallenge.
        /// </summary>
        public string CodeChallenge { get; set; } = string.Empty;

        [JsonProperty("code_challenge_method")]
        /// <summary>
        /// Gets or sets CodeChallengeMethod.
        /// </summary>
        public string CodeChallengeMethod { get; set; } = string.Empty;

        [JsonProperty("nonce")]
        /// <summary>
        /// Gets or sets Nonce.
        /// </summary>
        public string Nonce { get; set; } = string.Empty;

        [JsonProperty("state")]
        /// <summary>
        /// Gets or sets State.
        /// </summary>
        public string State { get; set; } = string.Empty;

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
            TimeSpan ttl = TimeSpan.FromSeconds(Common.Code.AuthCode.EXPIRE_SEC);
            ExpireAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(Common.Code.AuthCode.EXPIRE_SEC));
            string value = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(Code), value, ttl);
        }

        /// <summary>
        /// Executes GetRedisKey.
        /// </summary>
        public static string GetRedisKey(string code)
        {
            return $"{Common.Code.AuthCode.REDIS_KEY_PREFIX}{code}";
        }
    }
}
