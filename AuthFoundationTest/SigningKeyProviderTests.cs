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
    /// 目的: From Pem / Returns Key And Signs Data の仕様を検証する。
    /// 入力値: From Pem / Returns Key And Signs Data を確認するためにテスト内で作成したデータ。
    /// 期待値: From Pem / Returns Key And Signs Data の期待結果になること。
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
    /// 目的: From Pem / Accepts Escaped Newlines の仕様を検証する。
    /// 入力値: From Pem / Accepts Escaped Newlines を確認するためにテスト内で作成したデータ。
    /// 期待値: From Pem / Accepts Escaped Newlines の期待結果になること。
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
    /// 目的: From Config / Uses Configured Signing Key の仕様を検証する。
    /// 入力値: From Config / Uses Configured Signing Key を確認するためにテスト内で作成したデータ。
    /// 期待値: From Config / Uses Configured Signing Key の期待結果になること。
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
    /// 目的: From Pem / Rejects Missing Key Id の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void FromPem_RejectsMissingKeyId()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => SigningKeyProvider.FromPem(string.Empty, TestSigningKeys.PrivateKeyPem));

        Assert.AreEqual(Code.INTERNAL_SERVER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: From Pem / Rejects Missing Private Key Pem の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void FromPem_RejectsMissingPrivateKeyPem()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => SigningKeyProvider.FromPem(TestSigningKeys.KeyId, string.Empty));

        Assert.AreEqual(Code.INTERNAL_SERVER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: From Pem / Rejects Malformed Private Key Pem の仕様を検証する。
    /// 入力値: From Pem / Rejects Malformed Private Key Pem を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
