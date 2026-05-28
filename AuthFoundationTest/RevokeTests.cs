using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class RevokeTests
{
    [TestMethod]
    public void RevokeAccessToken_RemovesToken()
    {
        var store = new InMemoryOidcStore();
        var tokenService = new OidcTokenService(store);
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
