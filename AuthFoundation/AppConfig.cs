using Microsoft.Extensions.Configuration;

namespace AuthFoundation.Common;

public static class AppConfig
{
    public static string Issuer { get; private set; } = "https://auth.osolab-auth.jp/";
    public static string AuthUiBaseUrl { get; private set; } = "https://portal.osolab-auth.jp";
    public static bool DisableHttpsRedirection { get; private set; }

    public static void Initialize(IConfiguration config)
    {
        Issuer = NormalizeIssuer(config["Issuer"] ?? Issuer);
        AuthUiBaseUrl = NormalizeBaseUrl(config["AuthUiBaseUrl"] ?? AuthUiBaseUrl);
        DisableHttpsRedirection = config.GetValue("DisableHttpsRedirection", false);
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
}
