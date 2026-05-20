using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TempClientController = AuthFoundation.Controllers.Temp.ClientController;

namespace AuthFoundationTest;

[TestClass]
public sealed class ViewAndTempApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: GET /terms/view が外部Auth UI設定時にsession_id付き規約URLへリダイレクトすること。
    /// </summary>
    [TestMethod]
    public void GetTermView_RedirectsToConfiguredAuthUi()
    {
        using var context = TestDbContextFactory.Create();
        var redis = new FakeRedisClient();
        var controller = new TermController(
            context,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString("?session_id=abcdef0123456789abcdef0123456789");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = controller.GetTermView();

        Assert.IsInstanceOfType<RedirectResult>(result);
        Assert.AreEqual($"{AppConfig.AuthUiBaseUrl}/terms?session_id=abcdef0123456789abcdef0123456789", ((RedirectResult)result).Url);
    }

    /// <summary>
    /// 検証項目: GET /terms がx-session-idヘッダーから認可セッションを取得して規約一覧を返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetTerms_ValidHeaderSession_ReturnsTerms()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string termId = $"term-{Guid.NewGuid():N}"[..32];
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateRequiredTermAsync(context, clientId, termId);

        var redis = new FakeRedisClient();
        string sessionId = Helper.GenerateHex(Code.Session.LENGTH).ToLowerInvariant();
        await ApiTestData.WriteAuthorizationSessionAsync(
            redis,
            ApiTestData.CreateAuthorizationSession(sessionId, clientId, "https://portal.osolab-auth.jp/callback", "openid"));

        var controller = new TermController(
            context,
            new TestWebHostEnvironment(),
            new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers[Code.HttpHeaders.X_SESSION_ID.Key] = sessionId;
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetTerms();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(clientId, body.Value<string>("client_id"));
        Assert.AreEqual(termId, body["terms"]!.First!.Value<string>("term_id"));
    }

    /// <summary>
    /// 検証項目: 一時GET /temp/client がclient_idからscopeとredirect_uriを返すこと。
    /// </summary>
    [TestMethod]
    public async Task TempGetClient_ValidClientId_ReturnsClientConfiguration()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId, "secret", "https://portal.osolab-auth.jp/callback", Code.Scope.OPENID);

        var redis = new FakeRedisClient();
        var controller = new TempClientController(context, new AuthorizeExecutionService(context, redis));
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString($"?client_id={clientId}");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetAuthorize();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        CollectionAssert.Contains(body["client_scope"]!.Values<string>().ToArray(), Code.Scope.OPENID);
    }
}
