using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AgentDelegatedAuthTests
{
    /// <summary>
    /// 逶ｮ逧・ Verify Token Request / Allows Delegated Scope 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Verify Token Request / Allows Delegated Scope 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝茨ｿｽE繧ｯ繝ｳ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ菫晏ｭ倡憾諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void VerifyTokenRequest_AllowsDelegatedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-owner@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read task_comment",
            DateTimeOffset.UtcNow.AddDays(7));

        AgentTokenGrant grant = agents.VerifyTokenRequest(
            created.Agent.AgentId,
            created.AgentSecret,
            AppConfig.DevelopmentClientId,
            "task_read");

        Assert.AreEqual(owner.Subject, grant.Agent.OwnerSubject);
        Assert.AreEqual("Issue Triage Agent", grant.Agent.AgentName);
        Assert.AreEqual("active", grant.Agent.Status);
        Assert.IsTrue(grant.Agent.CreatedAt <= DateTimeOffset.UtcNow);
        Assert.AreEqual(owner.Subject, grant.Delegation.OwnerSubject);
        Assert.AreEqual(AppConfig.DevelopmentClientId, grant.Delegation.ClientId);
        Assert.AreEqual("task_read task_comment", grant.Delegation.Scope);
        Assert.IsTrue(grant.Delegation.ExpiresAt > DateTimeOffset.UtcNow);
        Assert.IsTrue(grant.Delegation.CreatedAt <= DateTimeOffset.UtcNow);
        Assert.AreEqual("task_read", grant.Scope);
    }

    /// <summary>
    /// 逶ｮ逧・ Create Agent / Rejects Unsupported Delegated Scope 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Create Agent / Rejects Unsupported Delegated Scope 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void CreateAgent_RejectsUnsupportedDelegatedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-create-scope@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();

        ApiException ex = Assert.ThrowsExactly<ApiException>(
            () => agents.CreateAgent(
                owner,
                "Issue Triage Agent",
                AppConfig.DevelopmentClientId,
                "task_read task_delete",
                DateTimeOffset.UtcNow.AddDays(7)));

        Assert.AreEqual("00009", ex.InternalCode);
        Assert.AreEqual("invalid_scope", ex.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Token Request / Rejects Unsupported Requested Scope 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Verify Token Request / Rejects Unsupported Requested Scope 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyTokenRequest_RejectsUnsupportedRequestedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-token-scope@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddDays(7));

        ApiException ex = Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AppConfig.DevelopmentClientId,
                "task_delete"));

        Assert.AreEqual("00009", ex.InternalCode);
        Assert.AreEqual("invalid_scope", ex.Error);
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Token Request / Rejects Expired Delegation 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 譛滄剞蛻・・ｽ・ｽ縺ｫ螟画峩縺励◆繝・・ｽ・ｽ繝医ョ繝ｼ繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyTokenRequest_RejectsExpiredDelegation()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-expired@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddSeconds(-1));

        Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AppConfig.DevelopmentClientId,
                "task_read"));
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Token Request / Rejects Unknown Agent 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyTokenRequest_RejectsUnknownAgent()
    {
        var agents = new InMemoryAgentStore();

        Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                "agent_missing",
                "ags_missing",
                AppConfig.DevelopmentClientId,
                "task_read"));
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Token Request / Rejects Unknown Client 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyTokenRequest_RejectsUnknownClient()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-client-direct@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddDays(7));

        Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                "99999999999999999999999999999999",
                "task_read"));
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Token Request / Rejects Empty Requested Scope 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Verify Token Request / Rejects Empty Requested Scope 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void VerifyTokenRequest_RejectsEmptyRequestedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-empty-scope@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddDays(7));

        Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AppConfig.DevelopmentClientId,
                string.Empty));
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Token Request / Blocks After Repeated Wrong Secrets 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 繝茨ｿｽE繧ｯ繝ｳ繝ｬ繧ｹ繝昴Φ繧ｹ縺ｨ菫晏ｭ倡憾諷九′莉墓ｧ倥←縺翫ｊ縺ｫ縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void VerifyTokenRequest_BlocksAfterRepeatedWrongSecrets()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-secret-limit@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore(TestServices.CreateAttemptLimiter(1, TimeSpan.FromMinutes(5)));
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddDays(7));
        Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                "ags_wrong",
                AppConfig.DevelopmentClientId,
                "task_read"));

        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AppConfig.DevelopmentClientId,
                "task_read"));

        Assert.AreEqual(Code.UNAUTHORIZED.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 逶ｮ逧・ Rotate Secret / Replaces Secret And Rejects Previous Secret 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Rotate Secret / Replaces Secret And Rejects Previous Secret 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void RotateSecret_ReplacesSecretAndRejectsPreviousSecret()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-rotate@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddDays(7));

        AgentSecretRotationResult rotated = agents.RotateSecret(owner, created.Agent.AgentId);

        Assert.AreNotEqual(created.AgentSecret, rotated.AgentSecret);
        Assert.IsTrue(rotated.AgentSecret.StartsWith("ags_", StringComparison.Ordinal));
        Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AppConfig.DevelopmentClientId,
                "task_read"));
        AgentTokenGrant grant = agents.VerifyTokenRequest(
            created.Agent.AgentId,
            rotated.AgentSecret,
            AppConfig.DevelopmentClientId,
            "task_read");
        Assert.AreEqual(created.Agent.AgentId, grant.Agent.AgentId);
    }

    /// <summary>
    /// 逶ｮ逧・ Revoke Agent / Marks Agent Revoked And Rejects Token Request 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Revoke Agent / Marks Agent Revoked And Rejects Token Request 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void RevokeAgent_MarksAgentRevokedAndRejectsTokenRequest()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-revoke@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddDays(7));

        AgentRecord revoked = agents.RevokeAgent(owner, created.Agent.AgentId);

        Assert.AreEqual("revoked", revoked.Status);
        Assert.IsNotNull(revoked.RevokedAt);
        Assert.ThrowsExactly<ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AppConfig.DevelopmentClientId,
                "task_read"));
    }

    /// <summary>
    /// 逶ｮ逧・ Rotate Secret / Rejects Different Owner 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Rotate Secret / Rejects Different Owner 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void RotateSecret_RejectsDifferentOwner()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-owner-rotate@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        UserRecord other = users.CreateUser("agent-other-rotate@example.com", "Passw0rd!", "Other Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddDays(7));

        Assert.ThrowsExactly<ApiException>(() => agents.RotateSecret(other, created.Agent.AgentId));
    }

    /// <summary>
    /// 逶ｮ逧・ Rotate Secret / Rejects Revoked Agent 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Rotate Secret / Rejects Revoked Agent 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void RotateSecret_RejectsRevokedAgent()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-revoked-rotate@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            DateTimeOffset.UtcNow.AddDays(7));
        agents.RevokeAgent(owner, created.Agent.AgentId);

        Assert.ThrowsExactly<ApiException>(() => agents.RotateSecret(owner, created.Agent.AgentId));
    }
}
