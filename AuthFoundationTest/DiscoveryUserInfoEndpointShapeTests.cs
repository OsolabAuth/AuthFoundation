using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class DiscoveryUserInfoEndpointShapeTests
{
    [TestMethod]
    public void Discovery_ReturnsConfiguredOidcMetadataContract()
    {
        var controller = new DiscoveryController(new OidcTokenService(new InMemoryOidcStore()));

        IActionResult action = controller.Discovery();

        var ok = AssertOk(action);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        string issuer = AppConfig.Issuer.TrimEnd('/');
        Assert.AreEqual(issuer, ReadProperty<string>(ok.Value, "issuer"));
        Assert.AreEqual($"{issuer}/authorize", ReadProperty<string>(ok.Value, "authorization_endpoint"));
        Assert.AreEqual($"{issuer}/token", ReadProperty<string>(ok.Value, "token_endpoint"));
        Assert.AreEqual($"{issuer}/userinfo", ReadProperty<string>(ok.Value, "userinfo_endpoint"));
        Assert.AreEqual($"{issuer}/jwks", ReadProperty<string>(ok.Value, "jwks_uri"));
        CollectionAssert.AreEqual(new[] { "code" }, ReadProperty<string[]>(ok.Value, "response_types_supported"));
        CollectionAssert.AreEqual(new[] { "authorization_code" }, ReadProperty<string[]>(ok.Value, "grant_types_supported"));
        CollectionAssert.AreEqual(new[] { "public" }, ReadProperty<string[]>(ok.Value, "subject_types_supported"));
        CollectionAssert.AreEqual(new[] { "RS256" }, ReadProperty<string[]>(ok.Value, "id_token_signing_alg_values_supported"));
        CollectionAssert.AreEqual(new[] { "openid", "email", "profile" }, ReadProperty<string[]>(ok.Value, "scopes_supported"));
        CollectionAssert.AreEqual(new[] { "none" }, ReadProperty<string[]>(ok.Value, "token_endpoint_auth_methods_supported"));
        CollectionAssert.AreEqual(new[] { "S256" }, ReadProperty<string[]>(ok.Value, "code_challenge_methods_supported"));
        CollectionAssert.AreEqual(new[] { "sub", "email", "name" }, ReadProperty<string[]>(ok.Value, "claims_supported"));
    }

    [TestMethod]
    public void Jwks_ReturnsActiveRsaSigningKeyContract()
    {
        var controller = new DiscoveryController(new OidcTokenService(new InMemoryOidcStore()));

        IActionResult action = controller.Jwks();

        var ok = AssertOk(action);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        object[] keys = ReadProperty<object[]>(ok.Value, "keys");
        Assert.AreEqual(1, keys.Length);
        Assert.AreEqual("RSA", ReadProperty<string>(keys[0], "kty"));
        Assert.AreEqual("sig", ReadProperty<string>(keys[0], "use"));
        Assert.AreEqual("RS256", ReadProperty<string>(keys[0], "alg"));
        Assert.IsFalse(string.IsNullOrWhiteSpace(ReadProperty<string>(keys[0], "kid")));
        Assert.IsFalse(string.IsNullOrWhiteSpace(ReadProperty<string>(keys[0], "n")));
        Assert.IsFalse(string.IsNullOrWhiteSpace(ReadProperty<string>(keys[0], "e")));
    }

    [TestMethod]
    public void UserInfo_ReturnsClaimsForKnownBearerToken()
    {
        var store = new InMemoryOidcStore();
        AccessTokenRecord token = store.CreateAccessToken(new AuthorizationCodeRecord(
            "code",
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid profile email",
            "nonce",
            "challenge",
            "subject_1",
            "subject@example.com",
            "Subject One",
            DateTimeOffset.UtcNow.AddMinutes(5)));
        var controller = CreateUserInfoController(store, $"Bearer {token.AccessToken}");

        IActionResult action = controller.Get();

        var ok = AssertOk(action);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("subject_1", ReadProperty<string>(ok.Value, "sub"));
        Assert.AreEqual("subject@example.com", ReadProperty<string>(ok.Value, "email"));
        Assert.AreEqual("Subject One", ReadProperty<string>(ok.Value, "name"));
    }

    [TestMethod]
    public void UserInfo_ReturnsUnauthorizedForMissingBearerToken()
    {
        var controller = CreateUserInfoController(new InMemoryOidcStore(), string.Empty);

        IActionResult action = controller.Get();

        var error = action as ObjectResult;
        Assert.IsNotNull(error);
        Assert.AreEqual(401, error.StatusCode);
        Assert.AreEqual("Bearer", controller.Response.Headers.WWWAuthenticate.ToString());
        var output = error.Value as ErrorOutput;
        Assert.IsNotNull(output);
        Assert.AreEqual("00008", output.ResponseCode);
        Assert.AreEqual("00008", output.ErrorCode);
        Assert.AreEqual("unauthorized", output.Message);
        Assert.AreEqual("invalid_token", output.Error);
        Assert.AreEqual("unauthorized", output.ErrorDescription);
    }

    private static UserInfoController CreateUserInfoController(InMemoryOidcStore store, string authorization)
    {
        var controller = new UserInfoController(store)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext()
            }
        };
        controller.Request.Headers.Authorization = authorization;
        return controller;
    }

    private static OkObjectResult AssertOk(IActionResult action)
    {
        var ok = action as OkObjectResult;
        Assert.IsNotNull(ok);
        Assert.IsNotNull(ok.Value);
        return ok;
    }

    private static T ReadProperty<T>(object? target, string name)
    {
        Assert.IsNotNull(target);
        var property = target.GetType().GetProperty(name);
        Assert.IsNotNull(property);

        object? value = property.GetValue(target);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }
}
