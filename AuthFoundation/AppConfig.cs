using Microsoft.Extensions.Configuration;

namespace AuthFoundation.Common
{
    public static class AppConfig
    {
        public static string PasswordHashKey { get; private set; } = string.Empty;
        public static int SessionExpireSec { get; private set; }
        public static int AccessTokenExpireSec { get; private set; }
        public static int RefreshTokenExpireSec { get; private set; }
        public static int IdTokenExpireSec { get; private set; }
        public static string TimezoneJst { get; private set; } = string.Empty;

        public static void Initialize(IConfiguration config)
        {
            PasswordHashKey = GetRequiredString(config, "PasswordHashKey");
            SessionExpireSec = GetRequiredInt(config, "Session_ExpireSec");
            AccessTokenExpireSec = GetRequiredInt(config, "AccessToken_ExpireSec");
            RefreshTokenExpireSec = GetRequiredInt(config, "RefreshToken_ExpireSec");
            IdTokenExpireSec = GetRequiredInt(config, "IDToken_ExpireSec");
        }

        private static string GetRequiredString(IConfiguration config, string key)
        {
            var value = config[key];
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }

            return value;
        }

        private static int GetRequiredInt(IConfiguration config, string key)
        {
            var value = config[key];
            if (!int.TryParse(value, out var result))
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }

            return result;
        }
    }
}