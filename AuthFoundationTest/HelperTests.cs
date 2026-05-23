using AuthFoundation.Common;
using AuthFoundationTest.TestSupport;

namespace AuthFoundationTest;

[TestClass]
public sealed class HelperTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Parse Scopes を 標準入力 条件で実行
    /// 期待値
    /// 　Trims Empty Values And Removes Duplicates を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void ParseScopes_TrimsEmptyValuesAndRemovesDuplicates()
    {
        List<string> scopes = Helper.ParseScopes("openid  email openid profile ");

        CollectionAssert.AreEqual(
            new[] { "openid", "email", "profile" },
            scopes);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Cert Authorize Client を 標準入力 条件で実行
    /// 期待値
    /// 　Validates Client Format Fragment And Registration を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Cert Authorize Client を 標準入力 条件で実行
    /// 期待値
    /// 　Allows Only Osolab Hyphen Local Pattern For Http を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task CertAuthorizeClient_AllowsOnlyOsolabHyphenLocalPatternForHttp()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string allowedLocalRedirectUri = "http://osolab-portal-local:5173/callback";
        await ApiTestData.CreateClientAsync(context, clientId, "secret", allowedLocalRedirectUri);

        Helper.CertAuthorizeClient(context, clientId, allowedLocalRedirectUri);

        ApiException disallowedLocalHostStyle = Assert.ThrowsExactly<ApiException>(() =>
            Helper.CertAuthorizeClient(context, clientId, "http://osolab-portal.local:5173/callback"));
        Assert.AreEqual(Code.ILLEGAL_REDIRECT_URI.Code, disallowedLocalHostStyle.Code);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Build Redirect Uri を 標準入力 条件で実行
    /// 期待値
    /// 　Appends Escaped Parameters を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
