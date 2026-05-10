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
        /// Gets or sets InnerClientId.
        /// </summary>
        public static string InnerClientId { get; private set; } = "00000000000000000000000000000000";

        /// <summary>
        /// Executes Initialize.
        /// </summary>
        public static void Initialize(IConfiguration config)
        {
            PasswordHashKey = GetRequiredString(config, "PasswordHashKey");
            SessionExpireSec = GetRequiredInt(config, "Session_ExpireSec");
            AccessTokenExpireSec = GetRequiredInt(config, "AccessToken_ExpireSec");
            RefreshTokenExpireSec = GetRequiredInt(config, "RefreshToken_ExpireSec");
            IdTokenExpireSec = GetRequiredInt(config, "IDToken_ExpireSec");

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
    }
}
