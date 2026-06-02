using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class RevokeTests
{
    /// <summary>
    /// 目的: Revoke Access Token / Removes Token の仕様を検証する。
    /// 入力値: Revoke Access Token / Removes Token を確認するためにテスト内で作成したデータ。
    /// 期待値: 対象を失効し、失効後の利用を拒否すること。
    /// </summary>
    [TestMethod]
    public void RevokeAccessToken_RemovesToken()
    {
        var store = new InMemoryOidcStore();
        var tokenService = TestSigningKeys.CreateTokenService(store);
        var code = new AuthorizationCodeRecord(
            "code",
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "nonce",
            "challenge",
            "user_1",
            "user@example.com",
            "User",
            DateTimeOffset.UtcNow.AddMinutes(5));

        TokenResponse response = tokenService.CreateTokenResponse(code);
        Assert.IsTrue(store.RevokeAccessToken(response.access_token));
        Assert.ThrowsExactly<ApiException>(() => store.FindAccessToken(response.access_token));
    }
}
