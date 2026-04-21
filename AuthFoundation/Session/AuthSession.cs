using AuthFoundation.Common;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using static AuthFoundation.Common.Code;

namespace AuthFoundation.Session
{
    public class AuthSession
    {
        [JsonProperty("session_id")]
        public string SessionId { get; set; } = string.Empty;
        [JsonProperty("osolab_id")]
        public string OsolabId { get; set; } = string.Empty;
        [JsonProperty("session_expire")]
        public string SessionExpire { get; set; } = string.Empty;
        [JsonProperty("email")]
        public string Email { get; set; } = string.Empty;
        [JsonProperty("client_id")]
        public string ClientId { get; set; } = string.Empty;
        public AuthSession(string sessionId, string osolabId, string email, string clientId)
        {
            SessionId = sessionId;
            OsolabId = osolabId;
            Email = email;
            ClientId = clientId;
        }

        public async void CreateSession(IRedisClient redis)
        {
            TimeSpan sessionExpireSec;
            string sessionExpireSecStr = AppConfig.SessionExpireSec.ToString();
            if (!TimeSpan.TryParse(sessionExpireSecStr, out sessionExpireSec))
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }
            string expireDateTimeString = DateTimeHelper.ToJstString(DateTimeHelper.GetJstNow().AddSeconds(int.Parse(sessionExpireSecStr)));
            SessionExpire = expireDateTimeString;
            string sessionObjectString = JsonConvert.SerializeObject(this);
            await redis.SetStringAsync(SessionId, sessionObjectString, sessionExpireSec);

        }
    }

}
