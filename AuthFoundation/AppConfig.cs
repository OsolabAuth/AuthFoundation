using Microsoft.Extensions.Configuration;

namespace AuthFoundation.Common;

public static class AppConfig
{
    public static string Issuer { get; private set; } = "https://auth.osolab-auth.jp/";
    public static string AuthUiBaseUrl { get; private set; } = "https://portal.osolab-auth.jp";
    public static string[] CorsAllowedOrigins { get; private set; } = ["https://portal.osolab-auth.jp"];
    public static bool DisableHttpsRedirection { get; private set; }
    public static string DevelopmentClientId { get; private set; } = "00000000000000000000000000000000";
    public static string DevelopmentRedirectUri { get; private set; } = "http://localhost:5700/callback";
    public static string SharedUserInfoClientId { get; private set; } = "00000000000000000000000000000000";
    public static string AuthDbConnectionString { get; private set; } = string.Empty;
    public static string RedisConnectionString { get; private set; } = string.Empty;
    public static string SigningKeyId { get; private set; } = string.Empty;
    public static string SigningKeyPrivateKeyPem { get; private set; } = string.Empty;
    public static string AgentAccessTokenAudience { get; private set; } = "task-management-api";
    public static int AttemptLimitMaxAttempts { get; private set; } = 5;
    public static int AttemptLimitWindowMinutes { get; private set; } = 5;
    public static string MailFromName { get; private set; } = "AuthFoundation";
    public static string MailFromEmail { get; private set; } = string.Empty;
    public static string GmailSmtpHost { get; private set; } = "smtp.gmail.com";
    public static int GmailSmtpPort { get; private set; } = 587;
    public static bool GmailSmtpEnableSsl { get; private set; } = true;
    public static string GmailSmtpUsername { get; private set; } = string.Empty;
    public static string GmailSmtpAppPassword { get; private set; } = string.Empty;

    public static void Initialize(IConfiguration config)
    {
        Issuer = NormalizeIssuer(config["Issuer"] ?? Issuer);
        AuthUiBaseUrl = NormalizeBaseUrl(config["AuthUiBaseUrl"] ?? AuthUiBaseUrl);
        CorsAllowedOrigins = ParseCorsOrigins(config["Cors:AllowedOrigins"], AuthUiBaseUrl);
        DisableHttpsRedirection = config.GetValue("DisableHttpsRedirection", false);
        DevelopmentClientId = config["DevelopmentClient:ClientId"] ?? DevelopmentClientId;
        DevelopmentRedirectUri = config["DevelopmentClient:RedirectUri"] ?? DevelopmentRedirectUri;
        SharedUserInfoClientId = config["UserInfo:SharedClientId"] ?? SharedUserInfoClientId;
        AuthDbConnectionString = config.GetConnectionString("AuthDb") ?? config["AuthDb:ConnectionString"] ?? AuthDbConnectionString;
        RedisConnectionString = config.GetConnectionString("Redis") ?? config["Redis:ConnectionString"] ?? RedisConnectionString;
        SigningKeyId = config["SigningKey:KeyId"] ?? SigningKeyId;
        SigningKeyPrivateKeyPem = config["SigningKey:PrivateKeyPem"] ?? SigningKeyPrivateKeyPem;
        AgentAccessTokenAudience = config["AgentAccessToken:Audience"] ?? AgentAccessTokenAudience;
        AttemptLimitMaxAttempts = config.GetValue("AttemptLimit:MaxAttempts", AttemptLimitMaxAttempts);
        AttemptLimitWindowMinutes = config.GetValue("AttemptLimit:WindowMinutes", AttemptLimitWindowMinutes);
        MailFromName = config["Mail:FromName"] ?? MailFromName;
        MailFromEmail = config["Mail:FromEmail"] ?? MailFromEmail;
        GmailSmtpHost = config["GmailSmtp:Host"] ?? GmailSmtpHost;
        GmailSmtpPort = config.GetValue("GmailSmtp:Port", GmailSmtpPort);
        GmailSmtpEnableSsl = config.GetValue("GmailSmtp:EnableSsl", GmailSmtpEnableSsl);
        GmailSmtpUsername = config["GmailSmtp:Username"] ?? GmailSmtpUsername;
        GmailSmtpAppPassword = config["GmailSmtp:AppPassword"] ?? GmailSmtpAppPassword;
    }

    public static bool IsGmailSmtpConfigured()
    {
        return !string.IsNullOrWhiteSpace(MailFromEmail)
            && !string.IsNullOrWhiteSpace(GmailSmtpHost)
            && !string.IsNullOrWhiteSpace(GmailSmtpUsername)
            && !string.IsNullOrWhiteSpace(GmailSmtpAppPassword);
    }

    public static bool IsAuthDbConfigured()
    {
        return !string.IsNullOrWhiteSpace(AuthDbConnectionString);
    }

    public static bool IsRedisConfigured()
    {
        return !string.IsNullOrWhiteSpace(RedisConnectionString);
    }

    private static string NormalizeIssuer(string value)
    {
        string normalized = NormalizeBaseUrl(value);
        return normalized.EndsWith('/') ? normalized : normalized + "/";
    }

    private static string NormalizeBaseUrl(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new ApiException(
                Code.INTERNAL_SERVER_ERROR.InternalCode,
                Code.INTERNAL_SERVER_ERROR.StatusCode,
                Code.INTERNAL_SERVER_ERROR.Error,
                "invalid base url configuration");
        }

        return uri.GetLeftPart(UriPartial.Authority).TrimEnd('/');
    }

    /// <summary>
    /// CORSで許可する画面側Originを設定文字列から構築する。
    /// </summary>
    private static string[] ParseCorsOrigins(string? value, string fallbackOrigin)
    {
        string source = string.IsNullOrWhiteSpace(value) ? fallbackOrigin : value;
        return source
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(NormalizeBaseUrl)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
