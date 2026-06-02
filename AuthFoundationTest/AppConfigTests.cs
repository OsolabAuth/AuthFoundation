using AuthFoundation.Common;
using Microsoft.Extensions.Configuration;

namespace AuthFoundationTest;

[TestClass]
public sealed class AppConfigTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfig.Initialize(Configuration(DefaultValues()));
    }

    [TestCleanup]
    public void Cleanup()
    {
        AppConfig.Initialize(Configuration(DefaultValues()));
    }

    /// <summary>
    /// 目的: Initialize / Uses Defaults When Config Is Empty の仕様を検証する。
    /// 入力値: Initialize / Uses Defaults When Config Is Empty を確認するためにテスト内で作成したデータ。
    /// 期待値: Initialize / Uses Defaults When Config Is Empty の期待結果になること。
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
        Assert.AreEqual(string.Empty, AppConfig.SigningKeyId);
        Assert.AreEqual(string.Empty, AppConfig.SigningKeyPrivateKeyPem);
        Assert.AreEqual("task-management-api", AppConfig.AgentAccessTokenAudience);
        Assert.AreEqual(5, AppConfig.AttemptLimitMaxAttempts);
        Assert.AreEqual(5, AppConfig.AttemptLimitWindowMinutes);
    }

    /// <summary>
    /// 目的: Initialize / Normalizes Configured Urls And Overrides Development Client の仕様を検証する。
    /// 入力値: Initialize / Normalizes Configured Urls And Overrides Development Client を確認するためにテスト内で作成したデータ。
    /// 期待値: Initialize / Normalizes Configured Urls And Overrides Development Client の期待結果になること。
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
            ["DevelopmentClient:RedirectUri"] = "http://localhost:3000/callback",
            ["SigningKey:KeyId"] = "configured-key",
            ["SigningKey:PrivateKeyPem"] = TestSigningKeys.PrivateKeyPem,
            ["AgentAccessToken:Audience"] = "configured-api",
            ["AttemptLimit:MaxAttempts"] = "3",
            ["AttemptLimit:WindowMinutes"] = "7"
        }));

        Assert.AreEqual("https://issuer.example.com/", AppConfig.Issuer);
        Assert.AreEqual("https://portal.example.com", AppConfig.AuthUiBaseUrl);
        Assert.IsTrue(AppConfig.DisableHttpsRedirection);
        Assert.AreEqual("30000000000000000000000000000001", AppConfig.DevelopmentClientId);
        Assert.AreEqual("http://localhost:3000/callback", AppConfig.DevelopmentRedirectUri);
        Assert.AreEqual("configured-key", AppConfig.SigningKeyId);
        Assert.AreEqual(TestSigningKeys.PrivateKeyPem, AppConfig.SigningKeyPrivateKeyPem);
        Assert.AreEqual("configured-api", AppConfig.AgentAccessTokenAudience);
        Assert.AreEqual(3, AppConfig.AttemptLimitMaxAttempts);
        Assert.AreEqual(7, AppConfig.AttemptLimitWindowMinutes);
    }

    /// <summary>
    /// 目的: Initialize / Allows Http Base Url の仕様を検証する。
    /// 入力値: Initialize / Allows Http Base Url を確認するためにテスト内で作成したデータ。
    /// 期待値: Initialize / Allows Http Base Url の期待結果になること。
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
    /// 目的: Initialize / Rejects Invalid Base Url の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Initialize / Rejects Malformed Base Url の仕様を検証する。
    /// 入力値: Initialize / Rejects Malformed Base Url を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
            ["DevelopmentClient:RedirectUri"] = "http://localhost:5700/callback",
            ["SigningKey:KeyId"] = string.Empty,
            ["SigningKey:PrivateKeyPem"] = string.Empty,
            ["AgentAccessToken:Audience"] = "task-management-api",
            ["AttemptLimit:MaxAttempts"] = "5",
            ["AttemptLimit:WindowMinutes"] = "5"
        };
    }
}
