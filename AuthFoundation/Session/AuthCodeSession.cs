using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    public class AuthCodeSession
    {
        [JsonProperty("code")]
        public string Code { get; set; } = string.Empty;

        [JsonProperty("osolab_id")]
        public string OsolabId { get; set; } = string.Empty;

        [JsonProperty("email")]
        public string Email { get; set; } = string.Empty;

        [JsonProperty("client_id")]
        public string ClientId { get; set; } = string.Empty;

        [JsonProperty("redirect_uri")]
        public string RedirectUri { get; set; } = string.Empty;

        [JsonProperty("scope")]
        public string Scope { get; set; } = string.Empty;

        [JsonProperty("code_challenge")]
        public string CodeChallenge { get; set; } = string.Empty;

        [JsonProperty("code_challenge_method")]
        public string CodeChallengeMethod { get; set; } = string.Empty;

        [JsonProperty("nonce")]
        public string Nonce { get; set; } = string.Empty;

        [JsonProperty("state")]
        public string State { get; set; } = string.Empty;

        [JsonProperty("expire_at")]
        public string ExpireAt { get; set; } = string.Empty;

        public async Task CreateSession(IRedisClient redis)
        {
            TimeSpan ttl = TimeSpan.FromSeconds(Common.Code.AuthCode.EXPIRE_SEC);
            ExpireAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(Common.Code.AuthCode.EXPIRE_SEC));
            string value = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(Code), value, ttl);
        }

        public static string GetRedisKey(string code)
        {
            return $"{Common.Code.AuthCode.REDIS_KEY_PREFIX}{code}";
        }
    }
}
