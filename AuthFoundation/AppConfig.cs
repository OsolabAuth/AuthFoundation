using Microsoft.Extensions.Configuration;

namespace AuthFoundation.Common;

public static class AppConfig
{
    public static string Issuer { get; private set; } = "https://auth.osolab-auth.jp/";
    public static string AuthUiBaseUrl { get; private set; } = "https://portal.osolab-auth.jp";
    public static bool DisableHttpsRedirection { get; private set; }
    public static string DevelopmentClientId { get; private set; } = "00000000000000000000000000000000";
    public static string DevelopmentRedirectUri { get; private set; } = "http://localhost:5700/callback";

    /// <summary>
    /// アプリケーション設定を読み込み、AuthFoundationの実行時設定を初期化する。
    /// </summary>
    /// <param name="config">読み込み済みのアプリケーション設定。</param>
    public static void Initialize(IConfiguration config)
    {
        Issuer = NormalizeIssuer(config["Issuer"] ?? Issuer);
        AuthUiBaseUrl = NormalizeBaseUrl(config["AuthUiBaseUrl"] ?? AuthUiBaseUrl);
        DisableHttpsRedirection = config.GetValue("DisableHttpsRedirection", false);
        DevelopmentClientId = config["DevelopmentClient:ClientId"] ?? DevelopmentClientId;
        DevelopmentRedirectUri = config["DevelopmentClient:RedirectUri"] ?? DevelopmentRedirectUri;
    }

    /// <summary>
    /// Issuer設定値を末尾スラッシュ付きのURLに正規化する。
    /// </summary>
    /// <param name="value">Issuerとして設定されたURL。</param>
    /// <returns>末尾スラッシュ付きのIssuer URL。</returns>
    private static string NormalizeIssuer(string value)
    {
        string normalized = NormalizeBaseUrl(value);
        return normalized.EndsWith('/') ? normalized : normalized + "/";
    }

    /// <summary>
    /// httpまたはhttpsの絶対URLをorigin形式に正規化する。
    /// </summary>
    /// <param name="value">正規化対象のURL。</param>
    /// <returns>末尾スラッシュなしのorigin URL。</returns>
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
