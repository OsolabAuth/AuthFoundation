using AuthFoundation.Common;
using AuthFoundation.Controllers.Agent;
using AuthFoundation.Data;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;

namespace AuthFoundationTest;

[TestClass]
public sealed class AgentApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    [TestMethod]
    public async Task PostAgent_ValidLoginSession_CreatesAgentAndReturnsOneTimeSecret()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"agent-owner-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());

        string sessionId = await ApiTestData.WriteLoginSessionAsync(redis, osolabId, email);

        var controller = new AgentController(context, redis);
        var httpContext = ControllerTestHelper.CreateJsonContext(new
        {
            agent_name = "Issue Triage Agent"
        });
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostAgent();

        if (result is not OkObjectResult)
        {
            Assert.Fail(ControllerTestHelper.ToJObject(result).ToString());
        }
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        StringAssert.StartsWith(body.Value<string>("agent_id"), "agent_");
        StringAssert.StartsWith(body.Value<string>("agent_secret"), "ags_");
        Assert.AreEqual("Issue Triage Agent", body.Value<string>("agent_name"));

        string agentId = body.Value<string>("agent_id")!;
        string agentSecret = body.Value<string>("agent_secret")!;
        var saved = await context.agent_masters.SingleAsync(x => x.agent_id == agentId);
        Assert.AreEqual(osolabId, saved.owner_osolab_id);
        Assert.AreEqual("Issue Triage Agent", saved.agent_name);
        Assert.AreEqual(Code.Status.ACTIVE, saved.status);
        Assert.AreNotEqual(agentSecret, saved.secret_hash);
        Assert.IsTrue(AgentSecretHasher.Verify(agentSecret, saved.secret_hash));

        string[] events = await context.agent_audit_logs
            .Where(x => x.agent_id == agentId)
            .OrderBy(x => x.audit_log_id)
            .Select(x => x.event_type)
            .ToArrayAsync();
        CollectionAssert.AreEqual(new[] { "agent.created", "agent.secret_issued" }, events);
    }

    [TestMethod]
    public async Task PostAgent_MissingLoginSession_ReturnsUnauthorized()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new AgentController(context, new FakeRedisClient());
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = ControllerTestHelper.CreateJsonContext(new
            {
                agent_name = "Issue Triage Agent"
            })
        };

        IActionResult result = await controller.PostAgent();

        JObject body = ControllerTestHelper.AssertError(result, (int)Code.UNAUTHORIZED.Status, Code.UNAUTHORIZED.Code);
        Assert.AreEqual("invalid_token", body.Value<string>("error"));
    }

    [TestMethod]
    public async Task PostDelegation_ValidOwnerAgentAndClient_CreatesDelegation()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"agent-delegation-owner-{Guid.NewGuid():N}@example.com";
        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());
        await ApiTestData.CreateClientAsync(context, clientId);

        string sessionId = await ApiTestData.WriteLoginSessionAsync(redis, osolabId, email);
        string agentId = await CreateAgentAsync(context, redis, sessionId);
        DateTimeOffset expiresAt = DateTimeOffset.UtcNow.AddDays(30);

        var controller = new AgentController(context, redis);
        var httpContext = ControllerTestHelper.CreateJsonContext(new
        {
            client_id = clientId,
            scope = "task.read task.comment",
            expires_datetime = expiresAt.ToString("O")
        });
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostDelegation(agentId);

        JObject body = ControllerTestHelper.AssertOk(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        StringAssert.StartsWith(body.Value<string>("delegation_id"), "delegation_");
        Assert.AreEqual(agentId, body.Value<string>("agent_id"));
        Assert.AreEqual(clientId, body.Value<string>("client_id"));
        Assert.AreEqual("task.read task.comment", body.Value<string>("scope"));

        string delegationId = body.Value<string>("delegation_id")!;
        var saved = await context.agent_delegations.SingleAsync(x => x.delegation_id == delegationId);
        Assert.AreEqual(agentId, saved.agent_id);
        Assert.AreEqual(osolabId, saved.owner_osolab_id);
        Assert.AreEqual(clientId, saved.client_id);
        Assert.AreEqual("task.read task.comment", saved.scopes);
        Assert.AreEqual(Code.Status.ACTIVE, saved.status);
        Assert.IsNotNull(saved.verified_datetime);

        string[] events = await context.agent_audit_logs
            .Where(x => x.delegation_id == delegationId)
            .Select(x => x.event_type)
            .ToArrayAsync();
        CollectionAssert.AreEqual(new[] { "agent.delegation_created" }, events);
    }

    [TestMethod]
    public async Task PostDelegation_DisallowedScope_ReturnsInvalidScope()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var redis = new FakeRedisClient();
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"agent-delegation-scope-{Guid.NewGuid():N}@example.com";
        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());
        await ApiTestData.CreateClientAsync(context, clientId);

        string sessionId = await ApiTestData.WriteLoginSessionAsync(redis, osolabId, email);
        string agentId = await CreateAgentAsync(context, redis, sessionId);

        var controller = new AgentController(context, redis);
        var httpContext = ControllerTestHelper.CreateJsonContext(new
        {
            client_id = clientId,
            scope = "task.delete",
            expires_datetime = DateTimeOffset.UtcNow.AddDays(30).ToString("O")
        });
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostDelegation(agentId);

        JObject body = ControllerTestHelper.AssertError(result, (int)Code.INVALID_SCOPE.Status, Code.INVALID_SCOPE.Code);
        Assert.AreEqual("invalid_scope", body.Value<string>("error"));
    }

    private static async Task<string> CreateAgentAsync(OsolabAuthContext context, FakeRedisClient redis, string sessionId)
    {
        var controller = new AgentController(context, redis);
        var httpContext = ControllerTestHelper.CreateJsonContext(new
        {
            agent_name = "Issue Triage Agent"
        });
        ControllerTestHelper.SetCookie(httpContext, Code.AUTH_SESSION_COOKIE_KEY, sessionId);
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostAgent();
        JObject body = ControllerTestHelper.AssertOk(result);
        return body.Value<string>("agent_id")!;
    }
}
