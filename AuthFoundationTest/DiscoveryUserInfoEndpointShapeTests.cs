using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class DiscoveryUserInfoEndpointShapeTests
{
    /// <summary>
    /// 逶ｮ逧・ Discovery / Returns Configured Oidc Metadata Contract 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Discovery / Returns Configured Oidc Metadata Contract 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Discovery / Returns Configured Oidc Metadata Contract 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Discovery_ReturnsConfiguredOidcMetadataContract()
    {
        var controller = new DiscoveryController(TestSigningKeys.CreateTokenService(new InMemoryOidcStore()));

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

    /// <summary>
    /// 逶ｮ逧・ Jwks / Returns Active Rsa Signing Key Contract 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Jwks / Returns Active Rsa Signing Key Contract 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Jwks / Returns Active Rsa Signing Key Contract 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Jwks_ReturnsActiveRsaSigningKeyContract()
    {
        var controller = new DiscoveryController(TestSigningKeys.CreateTokenService(new InMemoryOidcStore()));

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

    /// <summary>
    /// 逶ｮ逧・ User Info / Returns Claims For Known Bearer Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝茨ｿｽE繧ｯ繝ｳ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ菫晏ｭ倡憾諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
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
        IReadOnlyDictionary<string, string> claims = ReadClaims(ok.Value);
        Assert.AreEqual("subject_1", claims["sub"]);
        Assert.AreEqual("subject@example.com", claims["email"]);
        Assert.AreEqual("Subject One", claims["name"]);
    }

    /// <summary>
    /// UserInfo縺経penid縺ｮ縺ｿ縺ｮaccess token縺ｫ蟇ｾ縺励※email/profile claim繧定ｿ斐＆縺ｪ縺・・ｽ・ｽ縺ｨ繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void UserInfo_ReturnsOnlySubjectForOpenIdOnlyScope()
    {
        var store = new InMemoryOidcStore();
        AccessTokenRecord token = store.CreateAccessToken(new AuthorizationCodeRecord(
            "code",
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "openid",
            "nonce",
            "challenge",
            "subject_1",
            "subject@example.com",
            "Subject One",
            DateTimeOffset.UtcNow.AddMinutes(5)));
        var controller = CreateUserInfoController(store, $"Bearer {token.AccessToken}");

        IActionResult action = controller.Get();

        var ok = AssertOk(action);
        IReadOnlyDictionary<string, string> claims = ReadClaims(ok.Value);
        Assert.AreEqual("subject_1", claims["sub"]);
        Assert.IsFalse(claims.ContainsKey("email"));
        Assert.IsFalse(claims.ContainsKey("name"));
    }

    /// <summary>
    /// UserInfo縺経penid scope繧呈戟縺溘↑縺еser access token繧呈拠蜷ｦ縺吶ｋ縺薙→繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void UserInfo_ReturnsUnauthorizedForUserTokenWithoutOpenIdScope()
    {
        var store = new InMemoryOidcStore();
        AccessTokenRecord token = store.CreateAccessToken(new AuthorizationCodeRecord(
            "code",
            AppConfig.DevelopmentClientId,
            AppConfig.DevelopmentRedirectUri,
            "profile email",
            "nonce",
            "challenge",
            "subject_1",
            "subject@example.com",
            "Subject One",
            DateTimeOffset.UtcNow.AddMinutes(5)));
        var controller = CreateUserInfoController(store, $"Bearer {token.AccessToken}");

        IActionResult action = controller.Get();

        var error = action as ObjectResult;
        Assert.IsNotNull(error);
        Assert.AreEqual(401, error.StatusCode);
        Assert.AreEqual("Bearer", controller.Response.Headers.WWWAuthenticate.ToString());
    }

    /// <summary>
    /// UserInfo縺径gent access token繧丹IDC user token縺ｨ縺励※謇ｱ繧上↑縺・・ｽ・ｽ縺ｨ繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void UserInfo_ReturnsUnauthorizedForAgentAccessToken()
    {
        var store = new InMemoryOidcStore();
        var agent = new AgentRecord(
            "agent_1",
            "owner_1",
            "Issue Agent",
            "secret",
            "active",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow);
        var delegation = new AgentDelegationRecord(
            "delegation_1",
            agent.AgentId,
            agent.OwnerSubject,
            AppConfig.DevelopmentClientId,
            "task.read",
            DateTimeOffset.UtcNow.AddMinutes(10),
            DateTimeOffset.UtcNow);
        AccessTokenRecord token = store.CreateAgentAccessToken(agent, delegation, "task.read");
        var controller = CreateUserInfoController(store, $"Bearer {token.AccessToken}");

        IActionResult action = controller.Get();

        var error = action as ObjectResult;
        Assert.IsNotNull(error);
        Assert.AreEqual(401, error.StatusCode);
        Assert.AreEqual("Bearer", controller.Response.Headers.WWWAuthenticate.ToString());
    }

    /// <summary>
    /// 逶ｮ逧・ User Info / Returns Unauthorized For Missing Bearer Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蠢・・ｽ・ｽ鬆・・ｽ・ｽ縺ｾ縺滂ｿｽE隱崎ｨｼ繝倥ャ繝繝ｼ繧呈ｬ關ｽ縺輔○縺滂ｿｽE蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 401 Unauthorized 縺ｨ invalid_token 邉ｻ縺ｮ繧ｨ繝ｩ繝ｼ繧定ｿ斐☆縺薙→縲・
    /// </summary>
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

    private static IReadOnlyDictionary<string, string> ReadClaims(object? target)
    {
        Assert.IsNotNull(target);
        Assert.IsInstanceOfType<Dictionary<string, string>>(target);
        return (Dictionary<string, string>)target;
    }
}
