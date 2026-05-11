using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// リフレッシュトークンセッションを表します。
    /// </summary>
    public class RefreshTokenSession
    {
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; } = string.Empty;

        [JsonProperty("osolab_id")]
        public string OsolabId { get; set; } = string.Empty;

        [JsonProperty("client_id")]
        public string ClientId { get; set; } = string.Empty;

        [JsonProperty("scope")]
        public string Scope { get; set; } = string.Empty;

        [JsonProperty("expire_at")]
        public string ExpireAt { get; set; } = string.Empty;

        /// <summary>
        /// リフレッシュトークンセッションを初期化します。
        /// </summary>
        public RefreshTokenSession()
        {
        }

        /// <summary>
        /// Redis からリフレッシュトークンセッション文字列を読み込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="refreshToken">リフレッシュトークン</param>
        /// <returns>セッション文字列</returns>
        public async Task<string?> ReadValueFromRedisAsync(IRedisClient redis, string? refreshToken)
        {
            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return null;
            }

            return await redis.GetStringAsync(GetRedisKey(refreshToken));
        }

        /// <summary>
        /// 文字列からリフレッシュトークンセッションの値を設定します。
        /// </summary>
        /// <param name="value">セッション文字列</param>
        /// <returns>設定に成功した場合は true</returns>
        public bool SetValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            RefreshTokenSession? session = JsonConvert.DeserializeObject<RefreshTokenSession>(value);
            if (session == null)
            {
                return false;
            }

            RefreshToken = session.RefreshToken;
            OsolabId = session.OsolabId;
            ClientId = session.ClientId;
            Scope = session.Scope;
            ExpireAt = session.ExpireAt;
            return true;
        }

        /// <summary>
        /// Redis にリフレッシュトークンセッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task WriteToRedisAsync(IRedisClient redis)
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
        /// Redis にリフレッシュトークンセッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task CreateSession(IRedisClient redis)
        {
            await WriteToRedisAsync(redis);
        }

        /// <summary>
        /// Redis キーを取得します。
        /// </summary>
        /// <param name="refreshToken">リフレッシュトークン</param>
        /// <returns>Redis キー</returns>
        public static string GetRedisKey(string refreshToken)
        {
            return $"{Code.RefreshToken.REDIS_KEY_PREFIX}{refreshToken}";
        }
    }
}
