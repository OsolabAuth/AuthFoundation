using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class RevokeTests
{
    /// <summary>
    /// 逶ｮ逧・ Revoke Access Token / Removes Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Revoke Access Token / Removes Token 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 蟇ｾ雎｡繧貞､ｱ蜉ｹ縺励∝､ｱ蜉ｹ蠕鯉ｿｽE蛻ｩ逕ｨ繧呈拠蜷ｦ縺吶ｋ縺薙→縲・
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

        TokenOutput response = tokenService.CreateTokenResponse(code);
        Assert.IsTrue(store.RevokeAccessToken(response.access_token));
        Assert.ThrowsExactly<ApiException>(() => store.FindAccessToken(response.access_token));
    }
}
