using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Services;

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

    private static AgentController CreateController(InMemoryUserStore users, InMemoryAgentStore agents, StepUpService stepUp)
    {
        return EndpointTestHelper.WithHttpContext(
            new AgentController(users, agents, stepUp, new OidcTokenService(new InMemoryOidcStore())));
    }

    private static StepUpGrant IssueEmailStepUp(StepUpService stepUp, string email)
    {
        MfaEmailChallenge challenge = stepUp.StartEmailChallenge(email);
        return stepUp.VerifyEmailChallenge(email, challenge.Code);
    }
}
