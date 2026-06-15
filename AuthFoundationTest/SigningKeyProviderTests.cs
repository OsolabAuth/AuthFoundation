using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Common;
using AuthFoundation.Services;
using Microsoft.Extensions.Configuration;

namespace AuthFoundationTest;

[TestClass]
public sealed class SigningKeyProviderTests
{
    [TestCleanup]
    public void Cleanup()
    {
        AppConfig.Initialize(Configuration(new Dictionary<string, string?>
        {
            ["Issuer"] = "https://auth.osolab-auth.jp/",
            ["AuthUiBaseUrl"] = "https://portal.osolab-auth.jp",
            ["SigningKey:KeyId"] = string.Empty,
            ["SigningKey:PrivateKeyPem"] = string.Empty,
            ["AgentAccessToken:Audience"] = "task-management-api",
            ["AttemptLimit:MaxAttempts"] = "5",
            ["AttemptLimit:WindowMinutes"] = "5"
        }));
    }

    /// <summary>
    /// 逶ｮ逧・ From Pem / Returns Key And Signs Data 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: From Pem / Returns Key And Signs Data 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: From Pem / Returns Key And Signs Data 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void FromPem_ReturnsKeyAndSignsData()
    {
        using SigningKeyProvider provider = SigningKeyProvider.FromPem(TestSigningKeys.KeyId, TestSigningKeys.PrivateKeyPem);
        byte[] data = Encoding.UTF8.GetBytes("signed payload");

        byte[] signature = provider.SignData(data);

        Assert.AreEqual(TestSigningKeys.KeyId, provider.KeyId);
        using RSA rsa = RSA.Create(provider.ExportPublicParameters());
        Assert.IsTrue(rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    /// <summary>
    /// 逶ｮ逧・ From Pem / Accepts Escaped Newlines 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: From Pem / Accepts Escaped Newlines 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: From Pem / Accepts Escaped Newlines 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void FromPem_AcceptsEscapedNewlines()
    {
        string escapedPem = TestSigningKeys.PrivateKeyPem
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
        using SigningKeyProvider provider = SigningKeyProvider.FromPem(TestSigningKeys.KeyId, escapedPem);
        byte[] data = Encoding.UTF8.GetBytes("escaped pem payload");

        byte[] signature = provider.SignData(data);

        using RSA rsa = RSA.Create(provider.ExportPublicParameters());
        Assert.IsTrue(rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    /// <summary>
    /// 逶ｮ逧・ From Config / Uses Configured Signing Key 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: From Config / Uses Configured Signing Key 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: From Config / Uses Configured Signing Key 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void FromConfig_UsesConfiguredSigningKey()
    {
        AppConfig.Initialize(Configuration(new Dictionary<string, string?>
        {
            ["Issuer"] = "https://auth.osolab-auth.jp/",
            ["AuthUiBaseUrl"] = "https://portal.osolab-auth.jp",
            ["SigningKey:KeyId"] = "configured-test-key",
            ["SigningKey:PrivateKeyPem"] = TestSigningKeys.PrivateKeyPem
        }));

        using SigningKeyProvider provider = SigningKeyProvider.FromConfig();

        Assert.AreEqual("configured-test-key", provider.KeyId);
    }

    /// <summary>
    /// 逶ｮ逧・ From Pem / Rejects Missing Key Id 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void FromPem_RejectsMissingKeyId()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => SigningKeyProvider.FromPem(string.Empty, TestSigningKeys.PrivateKeyPem));

        Assert.AreEqual(Code.INTERNAL_SERVER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 逶ｮ逧・ From Pem / Rejects Missing Private Key Pem 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void FromPem_RejectsMissingPrivateKeyPem()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => SigningKeyProvider.FromPem(TestSigningKeys.KeyId, string.Empty));

        Assert.AreEqual(Code.INTERNAL_SERVER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 逶ｮ逧・ From Pem / Rejects Malformed Private Key Pem 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: From Pem / Rejects Malformed Private Key Pem 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void FromPem_RejectsMalformedPrivateKeyPem()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => SigningKeyProvider.FromPem(TestSigningKeys.KeyId, "not-a-private-key"));

        Assert.AreEqual(Code.INTERNAL_SERVER_ERROR.InternalCode, error.InternalCode);
    }

    private static IConfiguration Configuration(IEnumerable<KeyValuePair<string, string?>> values)
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();
    }
}
