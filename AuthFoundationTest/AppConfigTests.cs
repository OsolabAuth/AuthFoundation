using AuthFoundation.Common;
using Microsoft.Extensions.Configuration;

namespace AuthFoundationTest;

[TestClass]
public sealed class AppConfigTests
{
    [TestCleanup]
    public void Cleanup()
    {
        AppConfig.Initialize(Configuration(DefaultValues()));
    }

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

    private static IConfiguration Configuration(IEnumerable<KeyValuePair<string, string?>> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
    }

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
