using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// メール確認セッションを表します。
    /// </summary>
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

        /// <summary>
        /// メール確認セッションを初期化します。
        /// </summary>
        public MailVerificationSession()
        {
        }

        /// <summary>
        /// Redis からメール確認セッション文字列を読み込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="token">確認トークン</param>
        /// <returns>セッション文字列</returns>
        public async Task<string?> ReadValueFromRedisAsync(IRedisClient redis, string? token)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                return null;
            }

            return await redis.GetStringAsync(GetRedisKey(token), Common.Code.RedisDbNo.MAIL_VERIFICATION_SESSION);
        }

        /// <summary>
        /// 文字列からメール確認セッションの値を設定します。
        /// </summary>
        /// <param name="value">セッション文字列</param>
        /// <returns>設定に成功した場合は true</returns>
        public bool SetValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            MailVerificationSession? session = JsonConvert.DeserializeObject<MailVerificationSession>(value);
            if (session == null)
            {
                return false;
            }

            VerificationToken = session.VerificationToken;
            OsolabId = session.OsolabId;
            Email = session.Email;
            SessionId = session.SessionId;
            CreatedAt = session.CreatedAt;
            ExpiresAt = session.ExpiresAt;
            return true;
        }

        /// <summary>
        /// Redis にメール確認セッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task WriteToRedisAsync(IRedisClient redis)
        {
            const int expireSec = 1800;
            DateTime now = DateTimeHelper.GetJstNow();
            CreatedAt = DateTimeHelper.ToJstString(now);
            ExpiresAt = DateTimeHelper.ToJstString(now.AddSeconds(expireSec));
            await redis.SetStringAsync(GetRedisKey(VerificationToken), JsonConvert.SerializeObject(this), TimeSpan.FromSeconds(expireSec), Common.Code.RedisDbNo.MAIL_VERIFICATION_SESSION);
        }

        /// <summary>
        /// Redis にメール確認セッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task CreateSession(IRedisClient redis)
        {
            await WriteToRedisAsync(redis);
        }

        /// <summary>
        /// Redis キーを取得します。
        /// </summary>
        /// <param name="token">確認トークン</param>
        /// <returns>Redis キー</returns>
        public static string GetRedisKey(string token) => $"{RedisKeyPrefix}{token}";
    }
}
