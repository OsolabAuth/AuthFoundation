using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using System.Text;

namespace AuthFoundationTest;

[TestClass]
public sealed class AgentEndpointShapeTests
{
    /// <summary>
    /// 目的: Create / Returns Agent Secret And Delegation の仕様を検証する。
    /// 入力値: Create / Returns Agent Secret And Delegation を確認するためにテスト内で作成したデータ。
    /// 期待値: Create / Returns Agent Secret And Delegation の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Create_ReturnsAgentSecretAndDelegation()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("agent-create@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1), "agent_owner");
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "agent-create@example.com");
        var controller = CreateController(users, new InMemoryAgentStore(), stepUp);
        var request = new CreateAgentRequest(
            "agent-create@example.com",
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read task_comment",
            7,
            grant.StepUpToken);

        var ok = EndpointTestHelper.AssertOk(controller.Create(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "agent_id").StartsWith("agent_", StringComparison.Ordinal));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "agent_secret").StartsWith("ags_", StringComparison.Ordinal));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<string>(ok.Value, "delegation_id").StartsWith("del_", StringComparison.Ordinal));
        Assert.AreEqual("task_read task_comment", EndpointTestHelper.ReadProperty<string>(ok.Value, "scope"));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<DateTimeOffset>(ok.Value, "expires_at") > DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 目的: Create / Returns Invalid Client For Unknown Client の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: invalid_client のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Create_ReturnsInvalidClientForUnknownClient()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("agent-client@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "agent-client@example.com");
        var controller = CreateController(users, new InMemoryAgentStore(), stepUp);
        var request = new CreateAgentRequest(
            "agent-client@example.com",
            "Issue Triage Agent",
            "99999999999999999999999999999999",
            "task_read",
            7,
            grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Create(request), 400);

        Assert.AreEqual("00002", error.ResponseCode);
        Assert.AreEqual("invalid_client", error.Error);
    }

    /// <summary>
    /// 目的: Create / Returns Invalid Scope For Unsupported Scope の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: invalid_scope のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Create_ReturnsInvalidScopeForUnsupportedScope()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("agent-create-invalid-scope@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "agent-create-invalid-scope@example.com");
        var controller = CreateController(users, new InMemoryAgentStore(), stepUp);
        var request = new CreateAgentRequest(
            "agent-create-invalid-scope@example.com",
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read task_delete",
            7,
            grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Create(request), 400);

        Assert.AreEqual("00009", error.ResponseCode);
        Assert.AreEqual("invalid_scope", error.Error);
    }

    /// <summary>
    /// 目的: Create / Returns Unauthorized For Step Up Subject Mismatch の仕様を検証する。
    /// 入力値: Create / Returns Unauthorized For Step Up Subject Mismatch を確認するためにテスト内で作成したデータ。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Create_ReturnsUnauthorizedForStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("agent-owner@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1), "agent_owner");
        users.CreateUser("agent-other@example.com", "Passw0rd!", "Other Owner", new DateOnly(2000, 1, 1), "agent_other");
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "agent-other@example.com");
        var controller = CreateController(users, new InMemoryAgentStore(), stepUp);
        var request = new CreateAgentRequest(
            "agent-owner@example.com",
            "Issue Triage Agent",
            AppConfig.DevelopmentClientId,
            "task_read",
            7,
            grant.StepUpToken);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Create(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Token / Returns Agent Bearer Token の仕様を検証する。
    /// 入力値: Token / Returns Agent Bearer Token を確認するためにテスト内で作成したデータ。
    /// 期待値: トークンレスポンスと保存状態が仕様どおりになること。
    /// </summary>
    [TestMethod]
    public void Token_ReturnsAgentBearerToken()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-token@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read task_comment", DateTimeOffset.UtcNow.AddDays(7));
        var oidcStore = new InMemoryOidcStore();
        var controller = CreateController(users, agents, new StepUpService(users), oidcStore);
        var request = new AgentTokenRequest(created.Agent.AgentId, created.AgentSecret, AppConfig.DevelopmentClientId, "task_read");

        var ok = EndpointTestHelper.AssertOk(controller.Token(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        var response = ok.Value as AgentTokenResponse;
        Assert.IsNotNull(response);
        Assert.IsTrue(response.access_token.StartsWith("agt_", StringComparison.Ordinal));
        Assert.AreEqual(1, response.access_token.Split('.').Length);
        AccessTokenRecord accessToken = oidcStore.FindAccessToken(response.access_token);
        Assert.AreEqual("ai_agent", accessToken.PrincipalType);
        Assert.AreEqual(created.Agent.AgentId, accessToken.Subject);
        Assert.AreEqual(owner.Subject, accessToken.OwnerSubject);
        Assert.AreEqual(created.Delegation.DelegationId, accessToken.DelegationId);
        Assert.AreEqual("task_read", accessToken.Scope);
        Assert.AreEqual("Bearer", response.token_type);
        Assert.AreEqual(900, response.expires_in);
        Assert.AreEqual("task_read", response.scope);
        Assert.AreEqual(3, response.id_token.Split('.').Length);
    }

    /// <summary>
    /// 目的: Token / Returns Unauthorized For Wrong Secret の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Token_ReturnsUnauthorizedForWrongSecret()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-secret@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read", DateTimeOffset.UtcNow.AddDays(7));
        var controller = CreateController(users, agents, new StepUpService(users));
        var request = new AgentTokenRequest(created.Agent.AgentId, "ags_wrong", AppConfig.DevelopmentClientId, "task_read");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Token(request), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Token / Returns Invalid Scope For Undelegated Scope の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: invalid_scope のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Token_ReturnsInvalidScopeForUndelegatedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-scope@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read", DateTimeOffset.UtcNow.AddDays(7));
        var controller = CreateController(users, agents, new StepUpService(users));
        var request = new AgentTokenRequest(created.Agent.AgentId, created.AgentSecret, AppConfig.DevelopmentClientId, "task_comment");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Token(request), 400);

        Assert.AreEqual("00009", error.ResponseCode);
        Assert.AreEqual("invalid_scope", error.Error);
    }

    /// <summary>
    /// 目的: Token / Returns Invalid Scope For Unsupported Scope の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: invalid_scope のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Token_ReturnsInvalidScopeForUnsupportedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-token-invalid-scope@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read", DateTimeOffset.UtcNow.AddDays(7));
        var controller = CreateController(users, agents, new StepUpService(users));
        var request = new AgentTokenRequest(created.Agent.AgentId, created.AgentSecret, AppConfig.DevelopmentClientId, "task_delete");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Token(request), 400);

        Assert.AreEqual("00009", error.ResponseCode);
        Assert.AreEqual("invalid_scope", error.Error);
    }

    /// <summary>
    /// 目的: Me / Returns Agent Metadata の仕様を検証する。
    /// 入力値: Me / Returns Agent Metadata を確認するためにテスト内で作成したデータ。
    /// 期待値: Me / Returns Agent Metadata の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Me_ReturnsAgentMetadata()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-me@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1), "agent_me_owner");
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read task_comment", DateTimeOffset.UtcNow.AddDays(7));
        var controller = CreateController(users, agents, new StepUpService(users));
        SetBasicAgentCredential(controller, created.Agent.AgentId, created.AgentSecret);

        var ok = EndpointTestHelper.AssertOk(controller.Me(AppConfig.DevelopmentClientId, "task_read"));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("ai_agent", EndpointTestHelper.ReadProperty<string>(ok.Value, "principal_type"));
        Assert.AreEqual(created.Agent.AgentId, EndpointTestHelper.ReadProperty<string>(ok.Value, "agent_id"));
        Assert.AreEqual("Issue Triage Agent", EndpointTestHelper.ReadProperty<string>(ok.Value, "agent_name"));
        Assert.AreEqual(owner.Subject, EndpointTestHelper.ReadProperty<string>(ok.Value, "owner_sub"));
        Assert.AreEqual(created.Delegation.DelegationId, EndpointTestHelper.ReadProperty<string>(ok.Value, "delegation_id"));
        Assert.AreEqual(AppConfig.DevelopmentClientId, EndpointTestHelper.ReadProperty<string>(ok.Value, "client_id"));
        Assert.AreEqual("task_read", EndpointTestHelper.ReadProperty<string>(ok.Value, "scope"));
        Assert.AreEqual("active", EndpointTestHelper.ReadProperty<string>(ok.Value, "status"));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<DateTimeOffset>(ok.Value, "expires_at") > DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 目的: Me / Returns Unauthorized For Missing Basic Auth の仕様を検証する。
    /// 入力値: 必須項目または認証ヘッダーを欠落させた入力値。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Me_ReturnsUnauthorizedForMissingBasicAuth()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new InMemoryAgentStore(), new StepUpService(users));

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Me(AppConfig.DevelopmentClientId, "task_read"), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Me / Returns Unauthorized For Wrong Secret の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Me_ReturnsUnauthorizedForWrongSecret()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-me-secret@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read", DateTimeOffset.UtcNow.AddDays(7));
        var controller = CreateController(users, agents, new StepUpService(users));
        SetBasicAgentCredential(controller, created.Agent.AgentId, "ags_wrong");

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Me(AppConfig.DevelopmentClientId, "task_read"), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Me / Returns Unauthorized For Malformed Basic Credential の仕様を検証する。
    /// 入力値: Me / Returns Unauthorized For Malformed Basic Credential を確認するためにテスト内で作成したデータ。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Me_ReturnsUnauthorizedForMalformedBasicCredential()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new InMemoryAgentStore(), new StepUpService(users));
        string malformed = Convert.ToBase64String(Encoding.UTF8.GetBytes("agent_only"));
        controller.Request.Headers.Authorization = $"Basic {malformed}";

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Me(AppConfig.DevelopmentClientId, "task_read"), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Me / Returns Unauthorized For Invalid Basic Base64 の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Me_ReturnsUnauthorizedForInvalidBasicBase64()
    {
        var users = new InMemoryUserStore();
        var controller = CreateController(users, new InMemoryAgentStore(), new StepUpService(users));
        controller.Request.Headers.Authorization = "Basic a";

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Me(AppConfig.DevelopmentClientId, "task_read"), 401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Me / Returns Invalid Scope For Undelegated Scope の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: invalid_scope のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Me_ReturnsInvalidScopeForUndelegatedScope()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-me-scope@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read", DateTimeOffset.UtcNow.AddDays(7));
        var controller = CreateController(users, agents, new StepUpService(users));
        SetBasicAgentCredential(controller, created.Agent.AgentId, created.AgentSecret);

        ErrorOutput error = EndpointTestHelper.AssertError(controller.Me(AppConfig.DevelopmentClientId, "task_comment"), 400);

        Assert.AreEqual("00009", error.ResponseCode);
        Assert.AreEqual("invalid_scope", error.Error);
    }

    /// <summary>
    /// 目的: Rotate Secret / Returns New Secret And Invalidates Previous Secret の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: Rotate Secret / Returns New Secret And Invalidates Previous Secret の期待結果になること。
    /// </summary>
    [TestMethod]
    public void RotateSecret_ReturnsNewSecretAndInvalidatesPreviousSecret()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-rotate-api@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read", DateTimeOffset.UtcNow.AddDays(7));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "agent-rotate-api@example.com");
        var controller = CreateController(users, agents, stepUp);

        var ok = EndpointTestHelper.AssertOk(controller.RotateSecret(
            created.Agent.AgentId,
            new AgentOwnerStepUpRequest("agent-rotate-api@example.com", grant.StepUpToken)));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual(created.Agent.AgentId, EndpointTestHelper.ReadProperty<string>(ok.Value, "agent_id"));
        string newSecret = EndpointTestHelper.ReadProperty<string>(ok.Value, "agent_secret");
        Assert.IsTrue(newSecret.StartsWith("ags_", StringComparison.Ordinal));
        Assert.AreNotEqual(created.AgentSecret, newSecret);
        Assert.IsTrue(EndpointTestHelper.ReadProperty<DateTimeOffset>(ok.Value, "rotated_at") <= DateTimeOffset.UtcNow);

        ErrorOutput oldSecretError = EndpointTestHelper.AssertError(
            controller.Token(new AgentTokenRequest(created.Agent.AgentId, created.AgentSecret, AppConfig.DevelopmentClientId, "task_read")),
            401);
        Assert.AreEqual("00008", oldSecretError.ResponseCode);

        var tokenOk = EndpointTestHelper.AssertOk(
            controller.Token(new AgentTokenRequest(created.Agent.AgentId, newSecret, AppConfig.DevelopmentClientId, "task_read")));
        Assert.AreEqual(200, tokenOk.StatusCode ?? 200);
    }

    /// <summary>
    /// 目的: Revoke / Returns Revoked And Invalidates Agent の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 対象を失効し、失効後の利用を拒否すること。
    /// </summary>
    [TestMethod]
    public void Revoke_ReturnsRevokedAndInvalidatesAgent()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-revoke-api@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read", DateTimeOffset.UtcNow.AddDays(7));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "agent-revoke-api@example.com");
        var controller = CreateController(users, agents, stepUp);

        var ok = EndpointTestHelper.AssertOk(controller.Revoke(
            created.Agent.AgentId,
            new AgentOwnerStepUpRequest("agent-revoke-api@example.com", grant.StepUpToken)));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual(created.Agent.AgentId, EndpointTestHelper.ReadProperty<string>(ok.Value, "agent_id"));
        Assert.AreEqual("revoked", EndpointTestHelper.ReadProperty<string>(ok.Value, "status"));
        Assert.IsTrue(EndpointTestHelper.ReadProperty<DateTimeOffset>(ok.Value, "revoked_at") <= DateTimeOffset.UtcNow);

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.Token(new AgentTokenRequest(created.Agent.AgentId, created.AgentSecret, AppConfig.DevelopmentClientId, "task_read")),
            401);
        Assert.AreEqual("00008", error.ResponseCode);
    }

    /// <summary>
    /// 目的: Rotate Secret / Returns Unauthorized For Step Up Subject Mismatch の仕様を検証する。
    /// 入力値: Rotate Secret / Returns Unauthorized For Step Up Subject Mismatch を確認するためにテスト内で作成したデータ。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void RotateSecret_ReturnsUnauthorizedForStepUpSubjectMismatch()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-rotate-owner@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        users.CreateUser("agent-rotate-other@example.com", "Passw0rd!", "Other Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read", DateTimeOffset.UtcNow.AddDays(7));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "agent-rotate-other@example.com");
        var controller = CreateController(users, agents, stepUp);

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.RotateSecret(
                created.Agent.AgentId,
                new AgentOwnerStepUpRequest("agent-rotate-owner@example.com", grant.StepUpToken)),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    /// <summary>
    /// 目的: Revoke / Returns Unauthorized For Unknown Agent の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 401 Unauthorized と invalid_token 系のエラーを返すこと。
    /// </summary>
    [TestMethod]
    public void Revoke_ReturnsUnauthorizedForUnknownAgent()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("agent-missing-revoke@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var stepUp = new StepUpService(users);
        StepUpGrant grant = IssueEmailStepUp(stepUp, "agent-missing-revoke@example.com");
        var controller = CreateController(users, new InMemoryAgentStore(), stepUp);

        ErrorOutput error = EndpointTestHelper.AssertError(
            controller.Revoke(
                "agent_missing",
                new AgentOwnerStepUpRequest("agent-missing-revoke@example.com", grant.StepUpToken)),
            401);

        Assert.AreEqual("00008", error.ResponseCode);
        Assert.AreEqual("invalid_token", error.Error);
    }

    private static AgentController CreateController(
        InMemoryUserStore users,
        InMemoryAgentStore agents,
        StepUpService stepUp,
        InMemoryOidcStore? oidcStore = null)
    {
        return EndpointTestHelper.WithHttpContext(
            new AgentController(users, agents, stepUp, TestSigningKeys.CreateTokenService(oidcStore ?? new InMemoryOidcStore())));
    }

    private static void SetBasicAgentCredential(AgentController controller, string agentId, string agentSecret)
    {
        string credentials = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{agentId}:{agentSecret}"));
        controller.Request.Headers.Authorization = $"Basic {credentials}";
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }
}
