using AuthFoundation.Common;
using AuthFoundation.Controllers.Agent;
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
}
