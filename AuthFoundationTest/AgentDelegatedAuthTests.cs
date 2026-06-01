using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AgentDelegatedAuthTests
{
    [TestMethod]
    public void VerifyTokenRequest_AllowsDelegatedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-owner@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read task.comment",
            DateTimeOffset.UtcNow.AddDays(7));

        AgentTokenGrant grant = agents.VerifyTokenRequest(
            created.Agent.AgentId,
            created.AgentSecret,
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read");

        Assert.AreEqual(owner.Subject, grant.Agent.OwnerSubject);
        Assert.AreEqual("Issue Triage Agent", grant.Agent.AgentName);
        Assert.AreEqual("active", grant.Agent.Status);
        Assert.IsTrue(grant.Agent.CreatedAt <= DateTimeOffset.UtcNow);
        Assert.AreEqual(owner.Subject, grant.Delegation.OwnerSubject);
        Assert.AreEqual(AuthFoundation.Common.AppConfig.DevelopmentClientId, grant.Delegation.ClientId);
        Assert.AreEqual("task.read task.comment", grant.Delegation.Scope);
        Assert.IsTrue(grant.Delegation.ExpiresAt > DateTimeOffset.UtcNow);
        Assert.IsTrue(grant.Delegation.CreatedAt <= DateTimeOffset.UtcNow);
        Assert.AreEqual("task.read", grant.Scope);
    }

    [TestMethod]
    public void VerifyTokenRequest_RejectsExpiredDelegation()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-expired@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read",
            DateTimeOffset.UtcNow.AddSeconds(-1));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AuthFoundation.Common.AppConfig.DevelopmentClientId,
                "task.read"));
    }

    [TestMethod]
    public void VerifyTokenRequest_RejectsUnknownAgent()
    {
        var agents = new InMemoryAgentStore();

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => agents.VerifyTokenRequest(
                "agent_missing",
                "ags_missing",
                AuthFoundation.Common.AppConfig.DevelopmentClientId,
                "task.read"));
    }

    [TestMethod]
    public void VerifyTokenRequest_RejectsUnknownClient()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-client-direct@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read",
            DateTimeOffset.UtcNow.AddDays(7));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                "99999999999999999999999999999999",
                "task.read"));
    }

    [TestMethod]
    public void VerifyTokenRequest_RejectsEmptyRequestedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-empty-scope@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(
            owner,
            "Issue Triage Agent",
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read",
            DateTimeOffset.UtcNow.AddDays(7));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AuthFoundation.Common.AppConfig.DevelopmentClientId,
                string.Empty));
    }

    /// <summary>
    /// 目的: agent_secret再発行時に旧secretが無効化され、新secretでtoken発行できることを検証する。
    /// 入力値: owner=agent-rotate@example.com, scope=task.read, old agent_secret。
    /// 期待値: 旧agent_secretは401相当のApiException、新agent_secretはAgentTokenGrantを返す。
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
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read",
            DateTimeOffset.UtcNow.AddDays(7));

        AgentSecretRotationResult rotated = agents.RotateSecret(owner, created.Agent.AgentId);

        Assert.AreNotEqual(created.AgentSecret, rotated.AgentSecret);
        Assert.IsTrue(rotated.AgentSecret.StartsWith("ags_", StringComparison.Ordinal));
        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AuthFoundation.Common.AppConfig.DevelopmentClientId,
                "task.read"));
        AgentTokenGrant grant = agents.VerifyTokenRequest(
            created.Agent.AgentId,
            rotated.AgentSecret,
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read");
        Assert.AreEqual(created.Agent.AgentId, grant.Agent.AgentId);
    }

    /// <summary>
    /// 目的: agent失効後にtoken発行が拒否されることを検証する。
    /// 入力値: owner=agent-revoke@example.com, scope=task.read, active agent。
    /// 期待値: status=revoked, revoked_atあり、token発行は401相当のApiException。
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
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read",
            DateTimeOffset.UtcNow.AddDays(7));

        AgentRecord revoked = agents.RevokeAgent(owner, created.Agent.AgentId);

        Assert.AreEqual("revoked", revoked.Status);
        Assert.IsNotNull(revoked.RevokedAt);
        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => agents.VerifyTokenRequest(
                created.Agent.AgentId,
                created.AgentSecret,
                AuthFoundation.Common.AppConfig.DevelopmentClientId,
                "task.read"));
    }

    /// <summary>
    /// 目的: 他ユーザー所有agentのsecret再発行が拒否されることを検証する。
    /// 入力値: owner=agent-owner-rotate@example.com, other=agent-other-rotate@example.com。
    /// 期待値: RotateSecretは401相当のApiException。
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
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read",
            DateTimeOffset.UtcNow.AddDays(7));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(() => agents.RotateSecret(other, created.Agent.AgentId));
    }

    /// <summary>
    /// 目的: revoked agentのsecret再発行が拒否されることを検証する。
    /// 入力値: owner=agent-revoked-rotate@example.com, revoked agent。
    /// 期待値: RotateSecretは401相当のApiException。
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
            AuthFoundation.Common.AppConfig.DevelopmentClientId,
            "task.read",
            DateTimeOffset.UtcNow.AddDays(7));
        agents.RevokeAgent(owner, created.Agent.AgentId);

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(() => agents.RotateSecret(owner, created.Agent.AgentId));
    }
}
