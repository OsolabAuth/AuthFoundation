using AuthFoundation.Common;
using AuthFoundationTest.TestSupport;

namespace AuthFoundationTest;

[TestClass]
public sealed class HelperTests
{
    /// <summary>
    /// 検証項目: scope文字列の空白除去と重複削除が行われること。
    /// </summary>
    [TestMethod]
    public void ParseScopes_TrimsEmptyValuesAndRemovesDuplicates()
    {
        List<string> scopes = Helper.ParseScopes("openid  email openid profile ");

        CollectionAssert.AreEqual(
            new[] { "openid", "email", "profile" },
            scopes);
    }

    /// <summary>
    /// 検証項目: 認可クライアント検証がclient有効性、redirect_uri形式、fragment禁止、登録済みURI確認を1つのHelperで行うこと。
    /// </summary>
    [TestMethod]
    public async Task CertAuthorizeClient_ValidatesClientFormatFragmentAndRegistration()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://client.example.com/callback";
        await ApiTestData.CreateClientAsync(context, clientId, "secret", redirectUri);

        Helper.CertAuthorizeClient(context, clientId, redirectUri);

        ApiException invalidClient = Assert.ThrowsExactly<ApiException>(() =>
            Helper.CertAuthorizeClient(context, ApiTestData.NewClientId(), redirectUri));
        Assert.AreEqual(Code.ILLEGAL_CLIENT.Code, invalidClient.Code);

        ApiException invalidFormat = Assert.ThrowsExactly<ApiException>(() =>
            Helper.CertAuthorizeClient(context, clientId, "http://evil.example.com/callback"));
        Assert.AreEqual(Code.ILLEGAL_REDIRECT_URI.Code, invalidFormat.Code);

        ApiException withFragment = Assert.ThrowsExactly<ApiException>(() =>
            Helper.CertAuthorizeClient(context, clientId, "https://client.example.com/callback#token"));
        Assert.AreEqual(Code.ILLEGAL_REDIRECT_URI.Code, withFragment.Code);

        ApiException unregistered = Assert.ThrowsExactly<ApiException>(() =>
            Helper.CertAuthorizeClient(context, clientId, "https://client.example.com/other"));
        Assert.AreEqual(Code.ILLEGAL_REDIRECT_URI.Code, unregistered.Code);
    }

    /// <summary>
    /// 検証項目: redirect_uriへQueryパラメータをURLエンコードして追加できること。
    /// </summary>
    [TestMethod]
    public void BuildRedirectUri_AppendsEscapedParameters()
    {
        string redirectUri = Helper.BuildRedirectUri(
            "https://client.example.com/callback",
            new Dictionary<string, string>
            {
                ["code"] = "abc 123",
                ["state"] = "x/y"
            });

        Assert.AreEqual("https://client.example.com/callback?code=abc%20123&state=x%2Fy", redirectUri);
    }
}
