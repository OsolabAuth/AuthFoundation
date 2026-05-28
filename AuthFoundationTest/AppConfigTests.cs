using AuthFoundation.Common;
using Microsoft.Extensions.Configuration;

namespace AuthFoundationTest;

[TestClass]
public sealed class AppConfigTests
{
    /// <summary>
    /// 各テスト後にAppConfigを既定値へ戻す。
    /// </summary>
    [TestCleanup]
    public void Cleanup()
    {
        AppConfig.Initialize(Configuration(DefaultValues()));
    }

    /// <summary>
    /// Initializeが設定未指定時に既定値を使用することを確認する。
    /// </summary>
    [TestMethod]
    public void Initialize_UsesDefaultsWhenConfigIsEmpty()
    {
        AppConfig.Initialize(Configuration(Array.Empty<KeyValuePair<string, string?>>()));

        Assert.AreEqual("https://auth.osolab-auth.jp/", AppConfig.Issuer);
        Assert.AreEqual("https://portal.osolab-auth.jp", AppConfig.AuthUiBaseUrl);
        Assert.IsFalse(AppConfig.DisableHttpsRedirection);
        Assert.AreEqual("00000000000000000000000000000000", AppConfig.DevelopmentClientId);
        Assert.AreEqual("http://localhost:5700/callback", AppConfig.DevelopmentRedirectUri);
    }

    /// <summary>
    /// InitializeがURLを正規化し、開発用client設定を上書きすることを確認する。
    /// </summary>
    [TestMethod]
    public void Initialize_NormalizesConfiguredUrlsAndOverridesDevelopmentClient()
    {
        AppConfig.Initialize(Configuration(new Dictionary<string, string?>
        {
            ["Issuer"] = "https://issuer.example.com/auth/path",
            ["AuthUiBaseUrl"] = "https://portal.example.com/ui/path",
            ["DisableHttpsRedirection"] = "true",
            ["DevelopmentClient:ClientId"] = "30000000000000000000000000000001",
            ["DevelopmentClient:RedirectUri"] = "http://localhost:3000/callback"
        }));

        Assert.AreEqual("https://issuer.example.com/", AppConfig.Issuer);
        Assert.AreEqual("https://portal.example.com", AppConfig.AuthUiBaseUrl);
        Assert.IsTrue(AppConfig.DisableHttpsRedirection);
        Assert.AreEqual("30000000000000000000000000000001", AppConfig.DevelopmentClientId);
        Assert.AreEqual("http://localhost:3000/callback", AppConfig.DevelopmentRedirectUri);
    }

    /// <summary>
    /// Initializeがhttp URLをorigin形式に正規化できることを確認する。
    /// </summary>
    [TestMethod]
    public void Initialize_AllowsHttpBaseUrl()
    {
        AppConfig.Initialize(Configuration(new Dictionary<string, string?>
        {
            ["Issuer"] = "http://localhost:5700/auth/path",
            ["AuthUiBaseUrl"] = "http://localhost:3000/ui/path"
        }));

        Assert.AreEqual("http://localhost:5700/", AppConfig.Issuer);
        Assert.AreEqual("http://localhost:3000", AppConfig.AuthUiBaseUrl);
    }

    /// <summary>
    /// Initializeがhttp/https以外のURLを拒否することを確認する。
    /// </summary>
    [TestMethod]
    public void Initialize_RejectsInvalidBaseUrl()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            AppConfig.Initialize(Configuration(new Dictionary<string, string?>
            {
                ["Issuer"] = "ftp://issuer.example.com"
            })));

        Assert.AreEqual(Code.INTERNAL_SERVER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// InitializeがURLとして解析できない値を拒否することを確認する。
    /// </summary>
    [TestMethod]
    public void Initialize_RejectsMalformedBaseUrl()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            AppConfig.Initialize(Configuration(new Dictionary<string, string?>
            {
                ["AuthUiBaseUrl"] = "not-a-url"
            })));

        Assert.AreEqual(Code.INTERNAL_SERVER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// インメモリ設定からIConfigurationを生成する。
    /// </summary>
    private static IConfiguration Configuration(IEnumerable<KeyValuePair<string, string?>> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
    }

    /// <summary>
    /// AppConfigを既定値へ戻すための設定値一覧を生成する。
    /// </summary>
    private static Dictionary<string, string?> DefaultValues()
    {
        return new Dictionary<string, string?>
        {
            ["Issuer"] = "https://auth.osolab-auth.jp/",
            ["AuthUiBaseUrl"] = "https://portal.osolab-auth.jp",
            ["DisableHttpsRedirection"] = "false",
            ["DevelopmentClient:ClientId"] = "00000000000000000000000000000000",
            ["DevelopmentClient:RedirectUri"] = "http://localhost:5700/callback"
        };
    }
}
