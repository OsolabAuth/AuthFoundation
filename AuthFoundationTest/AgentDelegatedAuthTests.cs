using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AgentDelegatedAuthTests
{
    /// <summary>
    /// 目的: Verify Token Request / Allows Delegated Scope の仕様を検証する。
    /// 入力値: Verify Token Request / Allows Delegated Scope を確認するためにテスト内で作成したデータ。
    /// 期待値: トークンレスポンスと保存状態が仕様どおりになること。
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
    /// 目的: Create Agent / Rejects Unsupported Delegated Scope の仕様を検証する。
    /// 入力値: Create Agent / Rejects Unsupported Delegated Scope を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Verify Token Request / Rejects Unsupported Requested Scope の仕様を検証する。
    /// 入力値: Verify Token Request / Rejects Unsupported Requested Scope を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Verify Token Request / Rejects Expired Delegation の仕様を検証する。
    /// 入力値: 期限切れに変更したテストデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Verify Token Request / Rejects Unknown Agent の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Verify Token Request / Rejects Unknown Client の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Verify Token Request / Rejects Empty Requested Scope の仕様を検証する。
    /// 入力値: Verify Token Request / Rejects Empty Requested Scope を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Verify Token Request / Blocks After Repeated Wrong Secrets の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: トークンレスポンスと保存状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void VerifyTokenRequest_BlocksAfterRepeatedWrongSecrets()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-secret-limit@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore(new AttemptLimiter(1, TimeSpan.FromMinutes(5)));
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
    /// 目的: Rotate Secret / Replaces Secret And Rejects Previous Secret の仕様を検証する。
    /// 入力値: Rotate Secret / Replaces Secret And Rejects Previous Secret を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Revoke Agent / Marks Agent Revoked And Rejects Token Request の仕様を検証する。
    /// 入力値: Revoke Agent / Marks Agent Revoked And Rejects Token Request を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Rotate Secret / Rejects Different Owner の仕様を検証する。
    /// 入力値: Rotate Secret / Rejects Different Owner を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
    /// 目的: Rotate Secret / Rejects Revoked Agent の仕様を検証する。
    /// 入力値: Rotate Secret / Rejects Revoked Agent を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
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
