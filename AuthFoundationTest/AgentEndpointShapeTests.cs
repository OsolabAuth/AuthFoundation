using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;
using System.Text;

namespace AuthFoundationTest;

[TestClass]
public sealed class AgentEndpointShapeTests
{
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
    /// 目的: /agent作成時にPhase 1許可リスト外のscopeが拒否されることを検証する。
    /// 入力値: owner_email=agent-create-invalid-scope@example.com, scope=task_read task_delete。
    /// 期待値: 400、response_code=00009、error=invalid_scope。
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

    [TestMethod]
    public void Token_ReturnsAgentBearerToken()
    {
        var users = new InMemoryUserStore();
        UserRecord owner = users.CreateUser("agent-token@example.com", "Passw0rd!", "Agent Owner", new DateOnly(2000, 1, 1));
        var agents = new InMemoryAgentStore();
        AgentCreateResult created = agents.CreateAgent(owner, "Issue Triage Agent", AppConfig.DevelopmentClientId, "task_read task_comment", DateTimeOffset.UtcNow.AddDays(7));
        var controller = CreateController(users, agents, new StepUpService(users));
        var request = new AgentTokenRequest(created.Agent.AgentId, created.AgentSecret, AppConfig.DevelopmentClientId, "task_read");

        var ok = EndpointTestHelper.AssertOk(controller.Token(request));

        Assert.AreEqual(200, ok.StatusCode ?? 200);
        var response = ok.Value as AgentTokenResponse;
        Assert.IsNotNull(response);
        Assert.IsTrue(response.access_token.StartsWith("agt_", StringComparison.Ordinal));
        Assert.AreEqual("Bearer", response.token_type);
        Assert.AreEqual(900, response.expires_in);
        Assert.AreEqual("task_read", response.scope);
        Assert.AreEqual(3, response.id_token.Split('.').Length);
    }

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
    /// 目的: /agent/tokenでPhase 1許可リスト外のscope要求が拒否されることを検証する。
    /// 入力値: agent delegation scope=task_read, requested scope=task_delete。
    /// 期待値: 400、response_code=00009、error=invalid_scope。
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
    /// 目的: GET /agent/me でagent資格情報と委譲情報をトークン発行なしで確認できることを検証する。
    /// 入力値: Basic認証=agent_id:agent_secret, client_id=DevelopmentClientId, scope=task_read。
    /// 期待値: 200、principal_type=ai_agent、agent_id/owner_sub/delegation_id/scope/statusが返る。
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
    /// 目的: GET /agent/me がBasic認証なしの自己確認を拒否することを検証する。
    /// 入力値: Authorizationヘッダーなし、client_id=DevelopmentClientId, scope=task_read。
    /// 期待値: 401、response_code=00008、error=invalid_token。
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
    /// 目的: GET /agent/me が誤ったagent_secretを拒否することを検証する。
    /// 入力値: Basic認証=agent_id:ags_wrong, client_id=DevelopmentClientId, scope=task_read。
    /// 期待値: 401、response_code=00008、error=invalid_token。
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
    /// 目的: GET /agent/me がBasic認証のagent_id/agent_secret区切り不正を拒否することを検証する。
    /// 入力値: Basic認証=agent_only、client_id=DevelopmentClientId、scope=task_read。
    /// 期待値: 401、response_code=00008、error=invalid_token。
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
    /// 目的: GET /agent/me がbase64として復号できないBasic認証値を拒否することを検証する。
    /// 入力値: Basic認証=a、client_id=DevelopmentClientId、scope=task_read。
    /// 期待値: 401、response_code=00008、error=invalid_token。
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
    /// 目的: GET /agent/me が委譲されていないscopeを拒否することを検証する。
    /// 入力値: delegation scope=task_read、requested scope=task_comment。
    /// 期待値: 400、response_code=00009、error=invalid_scope。
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
    /// 目的: /agent/{agent_id}/secretでagent_secretを再発行し、旧secretを無効化できることを検証する。
    /// 入力値: owner_email=agent-rotate-api@example.com, step_up_token, active agent。
    /// 期待値: 200、agent_secretはags_始まり、旧secretのtoken発行は401、新secretのtoken発行は200。
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
    /// 目的: /agent/{agent_id}/revokeでagentを失効し、以後のtoken発行を拒否できることを検証する。
    /// 入力値: owner_email=agent-revoke-api@example.com, step_up_token, active agent。
    /// 期待値: 200、status=revoked、revoked_atあり、token発行は401。
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
    /// 目的: step_up_tokenのsubjectがownerと異なる場合にsecret再発行を拒否することを検証する。
    /// 入力値: owner_email=agent-rotate-owner@example.com, step_up_token=別ユーザー。
    /// 期待値: 401、response_code=00008、error=invalid_token。
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
    /// 目的: 存在しないagent_idの失効が拒否されることを検証する。
    /// 入力値: agent_id=agent_missing, owner_email=agent-missing-revoke@example.com, step_up_token。
    /// 期待値: 401、response_code=00008、error=invalid_token。
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

    private static AgentController CreateController(InMemoryUserStore users, InMemoryAgentStore agents, StepUpService stepUp)
    {
        return EndpointTestHelper.WithHttpContext(
            new AgentController(users, agents, stepUp, new OidcTokenService(new InMemoryOidcStore())));
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
