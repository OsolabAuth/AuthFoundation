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
    /// 逶ｮ逧・ Initialize / Uses Defaults When Config Is Empty 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Initialize / Uses Defaults When Config Is Empty 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Initialize / Uses Defaults When Config Is Empty 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Initialize_UsesDefaultsWhenConfigIsEmpty()
    {
        AppConfig.Initialize(Configuration(Array.Empty<KeyValuePair<string, string?>>()));

        Assert.AreEqual("https://auth.osolab-auth.jp/", AppConfig.Issuer);
        Assert.AreEqual("https://portal.osolab-auth.jp", AppConfig.AuthUiBaseUrl);
        CollectionAssert.AreEqual(new[] { "https://portal.osolab-auth.jp" }, AppConfig.CorsAllowedOrigins);
        Assert.IsFalse(AppConfig.DisableHttpsRedirection);
        Assert.AreEqual("00000000000000000000000000000000", AppConfig.DevelopmentClientId);
        Assert.AreEqual("http://localhost:5700/callback", AppConfig.DevelopmentRedirectUri);
        Assert.AreEqual("00000000000000000000000000000000", AppConfig.SharedUserInfoClientId);
        Assert.AreEqual(string.Empty, AppConfig.AuthDbConnectionString);
        Assert.IsFalse(AppConfig.IsAuthDbConfigured());
        Assert.AreEqual(string.Empty, AppConfig.RedisConnectionString);
        Assert.IsFalse(AppConfig.IsRedisConfigured());
        Assert.AreEqual(string.Empty, AppConfig.SigningKeyId);
        Assert.AreEqual(string.Empty, AppConfig.SigningKeyPrivateKeyPem);
        Assert.AreEqual("task-management-api", AppConfig.AgentAccessTokenAudience);
        Assert.AreEqual(5, AppConfig.AttemptLimitMaxAttempts);
        Assert.AreEqual(5, AppConfig.AttemptLimitWindowMinutes);
        Assert.AreEqual("AuthFoundation", AppConfig.MailFromName);
        Assert.AreEqual(string.Empty, AppConfig.MailFromEmail);
        Assert.AreEqual("smtp.gmail.com", AppConfig.GmailSmtpHost);
        Assert.AreEqual(587, AppConfig.GmailSmtpPort);
        Assert.IsTrue(AppConfig.GmailSmtpEnableSsl);
        Assert.AreEqual(string.Empty, AppConfig.GmailSmtpUsername);
        Assert.AreEqual(string.Empty, AppConfig.GmailSmtpAppPassword);
        Assert.IsFalse(AppConfig.IsGmailSmtpConfigured());
    }

    /// <summary>
    /// 逶ｮ逧・ Initialize / Normalizes Configured Urls And Overrides Development Client 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Initialize / Normalizes Configured Urls And Overrides Development Client 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Initialize / Normalizes Configured Urls And Overrides Development Client 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Initialize_NormalizesConfiguredUrlsAndOverridesDevelopmentClient()
    {
        AppConfig.Initialize(Configuration(new Dictionary<string, string?>
        {
            ["Issuer"] = "https://issuer.example.com/auth/path",
            ["AuthUiBaseUrl"] = "https://portal.example.com/ui/path",
            ["Cors:AllowedOrigins"] = "https://portal.example.com/ui/path, http://localhost:3000/dev, https://portal.example.com/other",
            ["DisableHttpsRedirection"] = "true",
            ["DevelopmentClient:ClientId"] = "30000000000000000000000000000001",
            ["DevelopmentClient:RedirectUri"] = "http://localhost:3000/callback",
            ["UserInfo:SharedClientId"] = "00000000000000000000000000000002",
            ["ConnectionStrings:AuthDb"] = "Server=localhost;Database=Auth;",
            ["ConnectionStrings:Redis"] = "localhost:6379,password=redis-password,abortConnect=false",
            ["SigningKey:KeyId"] = "configured-key",
            ["SigningKey:PrivateKeyPem"] = TestSigningKeys.PrivateKeyPem,
            ["AgentAccessToken:Audience"] = "configured-api",
            ["AttemptLimit:MaxAttempts"] = "3",
            ["AttemptLimit:WindowMinutes"] = "7",
            ["Mail:FromName"] = "Configured Auth",
            ["Mail:FromEmail"] = "auth@example.com",
            ["GmailSmtp:Host"] = "smtp.example.com",
            ["GmailSmtp:Port"] = "2525",
            ["GmailSmtp:EnableSsl"] = "false",
            ["GmailSmtp:Username"] = "smtp-user",
            ["GmailSmtp:AppPassword"] = "smtp-password"
        }));

        Assert.AreEqual("https://issuer.example.com/", AppConfig.Issuer);
        Assert.AreEqual("https://portal.example.com", AppConfig.AuthUiBaseUrl);
        CollectionAssert.AreEqual(
            new[] { "https://portal.example.com", "http://localhost:3000" },
            AppConfig.CorsAllowedOrigins);
        Assert.IsTrue(AppConfig.DisableHttpsRedirection);
        Assert.AreEqual("30000000000000000000000000000001", AppConfig.DevelopmentClientId);
        Assert.AreEqual("http://localhost:3000/callback", AppConfig.DevelopmentRedirectUri);
        Assert.AreEqual("00000000000000000000000000000002", AppConfig.SharedUserInfoClientId);
        Assert.AreEqual("Server=localhost;Database=Auth;", AppConfig.AuthDbConnectionString);
        Assert.IsTrue(AppConfig.IsAuthDbConfigured());
        Assert.AreEqual("localhost:6379,password=redis-password,abortConnect=false", AppConfig.RedisConnectionString);
        Assert.IsTrue(AppConfig.IsRedisConfigured());
        Assert.AreEqual("configured-key", AppConfig.SigningKeyId);
        Assert.AreEqual(TestSigningKeys.PrivateKeyPem, AppConfig.SigningKeyPrivateKeyPem);
        Assert.AreEqual("configured-api", AppConfig.AgentAccessTokenAudience);
        Assert.AreEqual(3, AppConfig.AttemptLimitMaxAttempts);
        Assert.AreEqual(7, AppConfig.AttemptLimitWindowMinutes);
        Assert.AreEqual("Configured Auth", AppConfig.MailFromName);
        Assert.AreEqual("auth@example.com", AppConfig.MailFromEmail);
        Assert.AreEqual("smtp.example.com", AppConfig.GmailSmtpHost);
        Assert.AreEqual(2525, AppConfig.GmailSmtpPort);
        Assert.IsFalse(AppConfig.GmailSmtpEnableSsl);
        Assert.AreEqual("smtp-user", AppConfig.GmailSmtpUsername);
        Assert.AreEqual("smtp-password", AppConfig.GmailSmtpAppPassword);
        Assert.IsTrue(AppConfig.IsGmailSmtpConfigured());
    }

    /// <summary>
    /// 逶ｮ逧・ Initialize / Allows Http Base Url 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Initialize / Allows Http Base Url 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Initialize / Allows Http Base Url 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
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
    /// CORS險ｱ蜿ｯOrigin譛ｪ謖・・ｽ・ｽ譎ゅ↓逕ｻ髱｢URL繧定ｨｱ蜿ｯOrigin縺ｨ縺励※菴ｿ縺・・ｽ・ｽ縺ｨ繧呈､懆ｨｼ縺吶ｋ縲・
    /// </summary>
    [TestMethod]
    public void Initialize_UsesAuthUiBaseUrlAsDefaultCorsOrigin()
    {
        AppConfig.Initialize(Configuration(new Dictionary<string, string?>
        {
            ["AuthUiBaseUrl"] = "https://portal.example.com/login"
        }));

        CollectionAssert.AreEqual(new[] { "https://portal.example.com" }, AppConfig.CorsAllowedOrigins);
    }

    /// <summary>
    /// CORS險ｱ蜿ｯOrigin縺ｫ荳肴ｭ｣縺ｪURL縺悟性縺ｾ繧後ｋ蝣ｴ蜷茨ｿｽE襍ｷ蜍墓凾險ｭ螳壹お繝ｩ繝ｼ縺ｫ縺吶ｋ縺薙→繧呈､懆ｨｼ縺吶ｋ縲・
    /// </summary>
    [TestMethod]
    public void Initialize_RejectsInvalidCorsOrigin()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            AppConfig.Initialize(Configuration(new Dictionary<string, string?>
            {
                ["Cors:AllowedOrigins"] = "https://portal.example.com, javascript:alert(1)"
            })));

        Assert.AreEqual(Code.INTERNAL_SERVER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 逶ｮ逧・ Initialize / Rejects Invalid Base Url 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
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
    /// 逶ｮ逧・ Initialize / Rejects Malformed Base Url 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Initialize / Rejects Malformed Base Url 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
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
            ["UserInfo:SharedClientId"] = "00000000000000000000000000000000",
            ["ConnectionStrings:AuthDb"] = string.Empty,
            ["ConnectionStrings:Redis"] = string.Empty,
            ["SigningKey:KeyId"] = string.Empty,
            ["SigningKey:PrivateKeyPem"] = string.Empty,
            ["AgentAccessToken:Audience"] = "task-management-api",
            ["AttemptLimit:MaxAttempts"] = "5",
            ["AttemptLimit:WindowMinutes"] = "5",
            ["Mail:FromName"] = "AuthFoundation",
            ["Mail:FromEmail"] = string.Empty,
            ["GmailSmtp:Host"] = "smtp.gmail.com",
            ["GmailSmtp:Port"] = "587",
            ["GmailSmtp:EnableSsl"] = "true",
            ["GmailSmtp:Username"] = string.Empty,
            ["GmailSmtp:AppPassword"] = string.Empty
        };
    }
}
