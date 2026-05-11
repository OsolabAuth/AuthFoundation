using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// アクセストークンセッションを表します。
    /// </summary>
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

        /// <summary>
        /// アクセストークンセッションを初期化します。
        /// </summary>
        public AccessTokenSession()
        {
        }

        /// <summary>
        /// Redis からアクセストークンセッション文字列を読み込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="accessToken">アクセストークン</param>
        /// <returns>セッション文字列</returns>
        public async Task<string?> ReadValueFromRedisAsync(IRedisClient redis, string? accessToken)
        {
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return null;
            }

            return await redis.GetStringAsync(GetRedisKey(accessToken));
        }

        /// <summary>
        /// 文字列からアクセストークンセッションの値を設定します。
        /// </summary>
        /// <param name="value">セッション文字列</param>
        /// <returns>設定に成功した場合は true</returns>
        public bool SetValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            AccessTokenSession? session = JsonConvert.DeserializeObject<AccessTokenSession>(value);
            if (session == null)
            {
                return false;
            }

            AccessToken = session.AccessToken;
            OsolabId = session.OsolabId;
            ClientId = session.ClientId;
            Scope = session.Scope;
            ExpireAt = session.ExpireAt;
            return true;
        }

        /// <summary>
        /// Redis にアクセストークンセッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task WriteToRedisAsync(IRedisClient redis)
        {
            int expireSec = AppConfig.AccessTokenExpireSec;
            if (expireSec <= 0)
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "Invalid configuration value");
            }

            TimeSpan ttl = TimeSpan.FromSeconds(expireSec);
            ExpireAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(expireSec));
            string value = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(AccessToken), value, ttl);
        }

        /// <summary>
        /// Redis にアクセストークンセッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task CreateSession(IRedisClient redis)
        {
            await WriteToRedisAsync(redis);
        }

        /// <summary>
        /// Redis キーを取得します。
        /// </summary>
        /// <param name="accessToken">アクセストークン</param>
        /// <returns>Redis キー</returns>
        public static string GetRedisKey(string accessToken)
        {
            return $"{Code.AccessToken.REDIS_KEY_PREFIX}{accessToken}";
        }
    }
}
