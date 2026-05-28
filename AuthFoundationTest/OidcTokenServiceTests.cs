using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class OidcTokenServiceTests
{
    [TestMethod]
    public void CreateTokenResponseStoresAccessTokenForUserInfo()
    {
        var store = new InMemoryOidcStore();
        var service = new OidcTokenService(store);
        var code = new AuthorizationCodeRecord(
            "code",
            "30000000000000000000000000000001",
            "http://localhost:3000/callback",
            "openid profile email",
            "nonce",
            "challenge",
            "user_1",
            "test@example.com",
            "Test User",
            DateTimeOffset.UtcNow.AddMinutes(5));

        TokenResponse response = service.CreateTokenResponse(code);
        AccessTokenRecord token = store.FindAccessToken(response.access_token);

        Assert.AreEqual("user_1", token.Subject);
        Assert.AreEqual("test@example.com", token.Email);
    }
}
