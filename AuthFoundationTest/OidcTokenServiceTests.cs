using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class OidcTokenServiceTests
{
    /// <summary>
    /// 逶ｮ逧・ Create Token Response Stores Access Token For User Info 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Create Token Response Stores Access Token For User Info 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 蟇ｾ雎｡繝・・ｽE繧ｿ繧剃ｿ晏ｭ倥＠縲∝ｾ檎ｶ夲ｿｽE逅・・ｽ・ｽ蜿ゑｿｽE縺ｧ縺阪ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void CreateTokenResponseStoresAccessTokenForUserInfo()
    {
        var store = new InMemoryOidcStore();
        var service = TestSigningKeys.CreateTokenService(store);
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

        TokenOutput response = service.CreateTokenResponse(code);
        AccessTokenRecord token = store.FindAccessToken(response.access_token);

        Assert.AreEqual("user_1", token.Subject);
        Assert.AreEqual("test@example.com", token.Email);
        Assert.AreEqual("user", token.PrincipalType);
        Assert.AreEqual(string.Empty, token.OwnerSubject);
        Assert.AreEqual(string.Empty, token.DelegationId);
    }

    /// <summary>
    /// 逶ｮ逧・ Create Agent Token Response Stores Opaque Agent Access Token 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Create Agent Token Response Stores Opaque Agent Access Token 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 蟇ｾ雎｡繝・・ｽE繧ｿ繧剃ｿ晏ｭ倥＠縲∝ｾ檎ｶ夲ｿｽE逅・・ｽ・ｽ蜿ゑｿｽE縺ｧ縺阪ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void CreateAgentTokenResponseStoresOpaqueAgentAccessToken()
    {
        var store = new InMemoryOidcStore();
        var service = TestSigningKeys.CreateTokenService(store);
        var agent = new AgentRecord(
            "agent_1",
            "user_1",
            "Issue Triage Agent",
            "secret_hash",
            "active",
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow,
            null);
        var delegation = new AgentDelegationRecord(
            "del_1",
            "agent_1",
            "user_1",
            AppConfig.DevelopmentClientId,
            "task_read task_comment",
            DateTimeOffset.UtcNow.AddDays(7),
            DateTimeOffset.UtcNow);

        AgentTokenOutput response = service.CreateAgentTokenResponse(agent, delegation, "task_read");
        AccessTokenRecord token = store.FindAccessToken(response.access_token);

        Assert.IsTrue(response.access_token.StartsWith("agt_", StringComparison.Ordinal));
        Assert.AreEqual(1, response.access_token.Split('.').Length);
        Assert.AreEqual("agent_1", token.Subject);
        Assert.AreEqual("ai_agent", token.PrincipalType);
        Assert.AreEqual("user_1", token.OwnerSubject);
        Assert.AreEqual("del_1", token.DelegationId);
        Assert.AreEqual("task_read", token.Scope);
        Assert.AreEqual(3, response.id_token.Split('.').Length);
    }
}
