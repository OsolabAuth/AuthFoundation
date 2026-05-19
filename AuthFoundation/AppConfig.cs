using Microsoft.Extensions.Configuration;

namespace AuthFoundation.Common
{
    /// <summary>
    /// AppConfig class.
    /// </summary>
    public static class AppConfig
    {
        /// <summary>
        /// Gets or sets PasswordHashKey.
        /// </summary>
        public static string PasswordHashKey { get; private set; } = string.Empty;
        /// <summary>
        /// Gets or sets JwkPrivateKeyEncryptionKey.
        /// </summary>
        public static string JwkPrivateKeyEncryptionKey { get; private set; } = string.Empty;
        /// <summary>
        /// Gets or sets SessionExpireSec.
        /// </summary>
        public static int SessionExpireSec { get; private set; }
        /// <summary>
        /// Gets or sets AccessTokenExpireSec.
        /// </summary>
        public static int AccessTokenExpireSec { get; private set; }
        /// <summary>
        /// Gets or sets RefreshTokenExpireSec.
        /// </summary>
        public static int RefreshTokenExpireSec { get; private set; }
        /// <summary>
        /// Gets or sets IdTokenExpireSec.
        /// </summary>
        public static int IdTokenExpireSec { get; private set; }
        /// <summary>
        /// Gets or sets Issuer.
        /// </summary>
        public static string Issuer { get; private set; } = "https://auth.osolab-auth.jp/";
        /// <summary>
        /// Gets or sets ServiceDocumentationUrl.
        /// </summary>
        public static string ServiceDocumentationUrl { get; private set; } = "https://osolab.jp/document/auth";
        /// <summary>
        /// Gets or sets AuthUiBaseUrl.
        /// </summary>
        public static string AuthUiBaseUrl { get; private set; } = "https://portal.osolab-auth.jp";
        /// <summary>
        /// Gets or sets InnerClientId.
        /// </summary>
        public static string InnerClientId { get; private set; } = "00000000000000000000000000000000";
        /// <summary>
        /// Gets or sets RedisDbDefault.
        /// </summary>
        public static int RedisDbDefault { get; private set; } = 0;
        /// <summary>
        /// Gets or sets RedisDbLoginSession.
        /// </summary>
        public static int RedisDbLoginSession { get; private set; } = 1;
        /// <summary>
        /// Gets or sets RedisDbAuthCode.
        /// </summary>
        public static int RedisDbAuthCode { get; private set; } = 2;
        /// <summary>
        /// Gets or sets RedisDbAccessToken.
        /// </summary>
        public static int RedisDbAccessToken { get; private set; } = 3;
        /// <summary>
        /// Gets or sets RedisDbRefreshToken.
        /// </summary>
        public static int RedisDbRefreshToken { get; private set; } = 4;
        /// <summary>
        /// Gets or sets RedisDbAuthorizationSession.
        /// </summary>
        public static int RedisDbAuthorizationSession { get; private set; } = 6;
        /// <summary>
        /// Gets or sets RedisDbMailVerification.
        /// </summary>
        public static int RedisDbMailVerification { get; private set; } = 7;
        /// <summary>
        /// Gets or sets RedisDbIdTokenRevocation.
        /// </summary>
        public static int RedisDbIdTokenRevocation { get; private set; } = 8;
        /// <summary>
        /// Gets or sets RedisDbLogoutAllRevocation.
        /// </summary>
        public static int RedisDbLogoutAllRevocation { get; private set; } = 9;

        /// <summary>
        /// Executes Initialize.
        /// </summary>
        public static void Initialize(IConfiguration config)
        {
            PasswordHashKey = GetRequiredString(config, "PasswordHashKey");
            JwkPrivateKeyEncryptionKey = GetRequiredString(config, "JwkPrivateKeyEncryptionKey");
            SessionExpireSec = GetRequiredInt(config, "Session_ExpireSec");
            AccessTokenExpireSec = GetRequiredInt(config, "AccessToken_ExpireSec");
            RefreshTokenExpireSec = GetRequiredInt(config, "RefreshToken_ExpireSec");
            IdTokenExpireSec = GetRequiredInt(config, "IDToken_ExpireSec");
            RedisDbDefault = GetIntOrDefault(config, "RedisDb_Default", 0);
            RedisDbLoginSession = GetIntOrDefault(config, "RedisDb_LoginSession", 1);
            RedisDbAuthCode = GetIntOrDefault(config, "RedisDb_AuthCode", 2);
            RedisDbAccessToken = GetIntOrDefault(config, "RedisDb_AccessToken", 3);
            RedisDbRefreshToken = GetIntOrDefault(config, "RedisDb_RefreshToken", 4);
            RedisDbAuthorizationSession = GetIntOrDefault(config, "RedisDb_AuthorizationSession", 6);
            RedisDbMailVerification = GetIntOrDefault(config, "RedisDb_MailVerification", 7);
            RedisDbIdTokenRevocation = GetIntOrDefault(config, "RedisDb_IdTokenRevocation", 8);
            RedisDbLogoutAllRevocation = GetIntOrDefault(config, "RedisDb_LogoutAllRevocation", 9);

            string? issuer = config["Issuer"];
            if (!string.IsNullOrWhiteSpace(issuer))
            {
                Issuer = issuer.EndsWith('/') ? issuer : issuer + "/";
            }

            string? serviceDoc = config["ServiceDocumentation"];
            if (!string.IsNullOrWhiteSpace(serviceDoc))
            {
                ServiceDocumentationUrl = serviceDoc;
            }

            string? authUiBaseUrl = config["AuthUiBaseUrl"];
            if (!string.IsNullOrWhiteSpace(authUiBaseUrl))
            {
                AuthUiBaseUrl = NormalizeBaseUrl(authUiBaseUrl);
            }

            string? innerClientId = config["InnerClientId"];
            if (!string.IsNullOrWhiteSpace(innerClientId))
            {
                InnerClientId = innerClientId;
            }
        }

        /// <summary>
        /// Executes GetRequiredString.
        /// </summary>
        private static string GetRequiredString(IConfiguration config, string key)
        {
            var value = config[key];
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }

            return value;
        }

        /// <summary>
        /// Executes GetRequiredInt.
        /// </summary>
        private static int GetRequiredInt(IConfiguration config, string key)
        {
            var value = config[key];
            if (!int.TryParse(value, out var result))
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }

            return result;
        }

        /// <summary>
        /// Executes GetIntOrDefault.
        /// </summary>
        private static int GetIntOrDefault(IConfiguration config, string key, int defaultValue)
        {
            string? value = config[key];
            if (string.IsNullOrWhiteSpace(value))
            {
                return defaultValue;
            }

            if (!int.TryParse(value, out int result))
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }

            return result;
        }

        /// <summary>
        /// Executes NormalizeBaseUrl.
        /// </summary>
        private static string NormalizeBaseUrl(string value)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)
                || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                throw new ApiException(Common.Code.INTERNAL_SERVER_ERROR, "環境設定値エラー");
            }

            return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        }
    }
}
