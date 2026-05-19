using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Session;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class AuthorizeApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    [TestMethod]
    public async Task GetAuthorize_AnonymousUser_ReturnsLoginRedirectBodyAndStoresAuthorizationSession()
    {
        await using var context = TestDbContextFactory.Create();
        Assert.IsTrue(await context.Database.CanConnectAsync(), "SQL Server is not available. Run the SQL folder initialization before this test.");

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["x-auth-ui-session-mode"] = "body";
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + $"&client_id={Code.InnerClient.OSOLAB_CLIENT_ID}"
            + "&redirect_uri=https%3A%2F%2Fportal.osolab-auth.jp%2Fcallback"
            + "&state=state-api-test"
            + "&scope=openid%20email%20profile"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();
        Assert.IsInstanceOfType<OkObjectResult>(result);

        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        Assert.AreEqual("redirect", body.Value<string>("result"));

        string sessionId = body.Value<string>("session_id") ?? string.Empty;
        Assert.AreEqual(Code.Session.LENGTH, sessionId.Length);
        StringAssert.StartsWith(body.Value<string>("redirect_url"), $"{AppConfig.AuthUiBaseUrl}/login");

        string? stored = await redis.GetStringAsync(AuthorizationSession.GetRedisKey(sessionId));
        Assert.IsFalse(string.IsNullOrWhiteSpace(stored));

        var saved = new AuthorizationSession();
        Assert.IsTrue(saved.SetValue(stored!));
        Assert.AreEqual(Code.InnerClient.OSOLAB_CLIENT_ID, saved.ClientId);
        Assert.AreEqual("openid email profile", saved.Scope);
    }

    [TestMethod]
    public async Task GetAuthorize_InvalidClient_ReturnsRequestError()
    {
        await using var context = TestDbContextFactory.Create();
        Assert.IsTrue(await context.Database.CanConnectAsync(), "SQL Server is not available. Run the SQL folder initialization before this test.");

        var redis = new FakeRedisClient();
        var controller = new AuthorizeController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString(
            "?response_type=code"
            + "&client_id=99999999999999999999999999999999"
            + "&redirect_uri=https%3A%2F%2Fportal.osolab-auth.jp%2Fcallback"
            + "&state=state-api-test"
            + "&scope=openid"
            + "&code_challenge_method=S256"
            + $"&code_challenge={new string('a', 43)}"
            + "&nonce=nonce-api-test");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();
        Assert.IsInstanceOfType<ObjectResult>(result);

        var objectResult = (ObjectResult)result;
        Assert.AreEqual((int)Code.ILLEGAL_CLIENT.Status, objectResult.StatusCode);

        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.ILLEGAL_CLIENT.Code, body.Value<string>("response_code"));
    }
}
