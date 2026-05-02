using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    public class AccessTokenSession
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; } = string.Empty;

        [JsonProperty("osolab_id")]
        public string OsolabId { get; set; } = string.Empty;

        [JsonProperty("client_id")]
        public string ClientId { get; set; } = string.Empty;

        [JsonProperty("scope")]
        public string Scope { get; set; } = string.Empty;

        [JsonProperty("expire_at")]
        public string ExpireAt { get; set; } = string.Empty;

        public async Task CreateSession(IRedisClient redis)
        {
            int expireSec = AppConfig.AccessTokenExpireSec;
            if (expireSec <= 0)
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }

            TimeSpan ttl = TimeSpan.FromSeconds(expireSec);
            ExpireAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(expireSec));
            string value = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(AccessToken), value, ttl);
        }

        public static string GetRedisKey(string accessToken)
        {
            return $"{Code.AccessToken.REDIS_KEY_PREFIX}{accessToken}";
        }
    }
}
