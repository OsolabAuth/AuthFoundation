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
    public static string SigningKeyId { get; private set; } = string.Empty;
    public static string SigningKeyPrivateKeyPem { get; private set; } = string.Empty;
    public static string AgentAccessTokenAudience { get; private set; } = "task-management-api";
    public static int AttemptLimitMaxAttempts { get; private set; } = 5;
    public static int AttemptLimitWindowMinutes { get; private set; } = 5;

    public static void Initialize(IConfiguration config)
    {
        Issuer = NormalizeIssuer(config["Issuer"] ?? Issuer);
        AuthUiBaseUrl = NormalizeBaseUrl(config["AuthUiBaseUrl"] ?? AuthUiBaseUrl);
        CorsAllowedOrigins = ParseCorsOrigins(config["Cors:AllowedOrigins"], AuthUiBaseUrl);
        DisableHttpsRedirection = config.GetValue("DisableHttpsRedirection", false);
        DevelopmentClientId = config["DevelopmentClient:ClientId"] ?? DevelopmentClientId;
        DevelopmentRedirectUri = config["DevelopmentClient:RedirectUri"] ?? DevelopmentRedirectUri;
        SigningKeyId = config["SigningKey:KeyId"] ?? SigningKeyId;
        SigningKeyPrivateKeyPem = config["SigningKey:PrivateKeyPem"] ?? SigningKeyPrivateKeyPem;
        AgentAccessTokenAudience = config["AgentAccessToken:Audience"] ?? AgentAccessTokenAudience;
        AttemptLimitMaxAttempts = config.GetValue("AttemptLimit:MaxAttempts", AttemptLimitMaxAttempts);
        AttemptLimitWindowMinutes = config.GetValue("AttemptLimit:WindowMinutes", AttemptLimitWindowMinutes);
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
