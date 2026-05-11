using AuthFoundation.Common;
using Newtonsoft.Json;

namespace AuthFoundation.Session
{
    /// <summary>
    /// 認可コードセッションを表します。
    /// </summary>
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

        /// <summary>
        /// 認可コードセッションを初期化します。
        /// </summary>
        public AuthCodeSession()
        {
        }

        /// <summary>
        /// Redis から認可コードセッション文字列を読み込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        /// <param name="code">認可コード</param>
        /// <returns>セッション文字列</returns>
        public async Task<string?> ReadValueFromRedisAsync(IRedisClient redis, string? code)
        {
            if (string.IsNullOrWhiteSpace(code))
            {
                return null;
            }

            return await redis.GetStringAsync(GetRedisKey(code));
        }

        /// <summary>
        /// 文字列から認可コードセッションの値を設定します。
        /// </summary>
        /// <param name="value">セッション文字列</param>
        /// <returns>設定に成功した場合は true</returns>
        public bool SetValue(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return false;
            }

            AuthCodeSession? session = JsonConvert.DeserializeObject<AuthCodeSession>(value);
            if (session == null)
            {
                return false;
            }

            Code = session.Code;
            OsolabId = session.OsolabId;
            Email = session.Email;
            ClientId = session.ClientId;
            RedirectUri = session.RedirectUri;
            Scope = session.Scope;
            CodeChallenge = session.CodeChallenge;
            CodeChallengeMethod = session.CodeChallengeMethod;
            Nonce = session.Nonce;
            State = session.State;
            ExpireAt = session.ExpireAt;
            return true;
        }

        /// <summary>
        /// Redis に認可コードセッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task WriteToRedisAsync(IRedisClient redis)
        {
            TimeSpan ttl = TimeSpan.FromSeconds(Common.Code.AuthCode.EXPIRE_SEC);
            ExpireAt = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(Common.Code.AuthCode.EXPIRE_SEC));
            string value = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(GetRedisKey(Code), value, ttl);
        }

        /// <summary>
        /// Redis に認可コードセッションを書き込みます。
        /// </summary>
        /// <param name="redis">Redis クライアント</param>
        public async Task CreateSession(IRedisClient redis)
        {
            await WriteToRedisAsync(redis);
        }

        /// <summary>
        /// Redis キーを取得します。
        /// </summary>
        /// <param name="code">認可コード</param>
        /// <returns>Redis キー</returns>
        public static string GetRedisKey(string code)
        {
            return $"{Common.Code.AuthCode.REDIS_KEY_PREFIX}{code}";
        }
    }
}
