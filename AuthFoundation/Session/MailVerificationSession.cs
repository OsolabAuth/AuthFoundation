using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    public class MailVerificationSession
    {
        public const string RedisKeyPrefix = "mail_verify:";

        [JsonProperty("verification_token")]
        public string VerificationToken { get; set; } = string.Empty;
        [JsonProperty("osolab_id")]
        public string OsolabId { get; set; } = string.Empty;
        [JsonProperty("email")]
        public string Email { get; set; } = string.Empty;
        [JsonProperty("session_id")]
        public string SessionId { get; set; } = string.Empty;
        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;
        [JsonProperty("expires_at")]
        public string ExpiresAt { get; set; } = string.Empty;

        public async Task CreateSession(IRedisClient redis)
        {
            const int expireSec = 1800;
            DateTime now = DateTimeHelper.GetJstNow();
            CreatedAt = DateTimeHelper.ToJstString(now);
            ExpiresAt = DateTimeHelper.ToJstString(now.AddSeconds(expireSec));
            await redis.SetStringAsync(GetRedisKey(VerificationToken), JsonConvert.SerializeObject(this), TimeSpan.FromSeconds(expireSec));
        }

        public static string GetRedisKey(string token) => $"{RedisKeyPrefix}{token}";
    }
}
