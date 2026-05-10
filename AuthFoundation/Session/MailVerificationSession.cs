using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// MailVerificationSession class.
    /// </summary>
    public class MailVerificationSession
    {
        public const string RedisKeyPrefix = "mail_verify:";

        [JsonProperty("verification_token")]
        /// <summary>
        /// Gets or sets VerificationToken.
        /// </summary>
        public string VerificationToken { get; set; } = string.Empty;
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
        [JsonProperty("session_id")]
        /// <summary>
        /// Gets or sets SessionId.
        /// </summary>
        public string SessionId { get; set; } = string.Empty;
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

        /// <summary>
        /// Executes CreateSession.
        /// </summary>
        public async Task CreateSession(IRedisClient redis)
        {
            const int expireSec = 1800;
            DateTime now = DateTimeHelper.GetJstNow();
            CreatedAt = DateTimeHelper.ToJstString(now);
            ExpiresAt = DateTimeHelper.ToJstString(now.AddSeconds(expireSec));
            await redis.SetStringAsync(GetRedisKey(VerificationToken), JsonConvert.SerializeObject(this), TimeSpan.FromSeconds(expireSec));
        }

        /// <summary>
        /// Executes GetRedisKey.
        /// </summary>
        public static string GetRedisKey(string token) => $"{RedisKeyPrefix}{token}";
    }
}
