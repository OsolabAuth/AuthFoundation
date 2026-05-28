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
}
