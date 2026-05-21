using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// サインアップ時のメール認証セッションを表します。
    /// </summary>
    public class SignupSession
    {
        public const string RedisKeyPrefix = "signup_session:";
        public const int ExpireSeconds = 1800;

        [JsonProperty("signup_session_id")]
        public string SignupSessionId { get; set; } = string.Empty;

        [JsonProperty("auth_request_session_id")]
        public string AuthRequestSessionId { get; set; } = string.Empty;

        [JsonProperty("email")]
        public string Email { get; set; } = string.Empty;

        [JsonProperty("code")]
        public string Code { get; set; } = string.Empty;

        [JsonProperty("verified")]
        public bool Verified { get; set; }

        [JsonProperty("created_at")]
        public string CreatedAt { get; set; } = string.Empty;

        [JsonProperty("expires_at")]
        public string ExpiresAt { get; set; } = string.Empty;

        /// <summary>
        /// Redis からメール確認セッション文字列を読み込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="signupSessionId">サインアップセッションID</param>
        /// <returns>セッション文字列</returns>
        public async Task<string?> ReadValueFromRedisAsync(IRedisClient redis, string? signupSessionId)
        {
            if (string.IsNullOrWhiteSpace(signupSessionId))
            {
                return null;
            }

            return await redis.GetStringAsync(GetRedisKey(signupSessionId), Common.Code.RedisDbNo.SIGNUP_SESSION);
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

            SignupSession? session = JsonConvert.DeserializeObject<SignupSession>(value);
            if (session == null)
            {
                return false;
            }

            SignupSessionId = session.SignupSessionId;
            AuthRequestSessionId = session.AuthRequestSessionId;
            Email = session.Email;
            Code = session.Code;
            Verified = session.Verified;
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
            if (string.IsNullOrWhiteSpace(SignupSessionId))
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "signup_session_id is empty");
            }

            DateTime now = DateTimeHelper.GetJstNow();
            CreatedAt = DateTimeHelper.ToJstString(now);
            ExpiresAt = DateTimeHelper.ToJstString(now.AddSeconds(ExpireSeconds));
            await redis.SetStringAsync(
                GetRedisKey(SignupSessionId),
                JsonConvert.SerializeObject(this),
                TimeSpan.FromSeconds(ExpireSeconds),
                Common.Code.RedisDbNo.SIGNUP_SESSION);
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
        /// <param name="signupSessionId">サインアップセッションID</param>
        /// <returns>Redis キー</returns>
        public static string GetRedisKey(string signupSessionId)
        {
            return $"{RedisKeyPrefix}{signupSessionId}";
        }
    }
}


