using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using AuthFoundation.Controllers.Client;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;
using ClientTermController = AuthFoundation.Controllers.Client.TermController;

namespace AuthFoundationTest;

[TestClass]
public sealed class ClientManagementApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: POST /Client 正常系でclient_id/client_secretを発行し、DBに有効クライアントとして登録すること。
    /// </summary>
    [TestMethod]
    public async Task PostClient_ValidJson_CreatesClient()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new ClientController(context);
        string clientName = $"client-{Guid.NewGuid():N}";
        var httpContext = ControllerTestHelper.CreateJsonContext(new
        {
            client_name = clientName
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostClient();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));
        string clientId = body.Value<string>("ClientId")!;
        Assert.IsTrue(await context.client_masters.AnyAsync(x => x.client_id == clientId && x.client_name == clientName && x.status == Code.Status.ACTIVE));
    }

    /// <summary>
    /// 検証項目: POST /Client のContent-Type不正時に00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostClient_InvalidContentType_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new ClientController(context);
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        IActionResult result = await controller.PostClient();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }

    /// <summary>
    /// 検証項目: POST /register 互換エンドポイントでもclient_id/client_secretを発行できること。
    /// </summary>
    [TestMethod]
    public async Task RegisterClient_ValidJson_CreatesClient()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new ClientRegistrationController(context);
        string clientName = $"registered-{Guid.NewGuid():N}";
        var httpContext = ControllerTestHelper.CreateJsonContext(new
        {
            client_name = clientName
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.RegisterClient();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));
        Assert.IsTrue(await context.client_masters.AnyAsync(x => x.client_id == body.Value<string>("ClientId") && x.client_name == clientName));
    }

    /// <summary>
    /// 検証項目: GET /Client 正常系で登録済みclientのscopeとredirect_uriを返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetClient_ValidClientId_ReturnsScopesAndRedirectUris()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string redirectUri = "https://portal.osolab-auth.jp/callback";
        await ApiTestData.CreateClientAsync(context, clientId, "secret", redirectUri, Code.Scope.OPENID);

        var controller = new ClientController(context);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString($"?client_id={clientId}");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetClient();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("response_code"));
        CollectionAssert.Contains(body["client_scope"]!.Values<string>().ToArray(), Code.Scope.OPENID);
        CollectionAssert.Contains(body["client_redirect_uri"]!.Values<string>().ToArray(), redirectUri);
    }

    /// <summary>
    /// 検証項目: GET /Client の未登録client_idで00002を返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetClient_UnknownClientId_ReturnsIllegalClient()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new ClientController(context);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString("?client_id=99999999999999999999999999999999");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetClient();

        ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_CLIENT.Status, Code.ILLEGAL_CLIENT.Code);
    }

    /// <summary>
    /// 検証項目: POST /Term 正常系でクライアント規約を登録できること。
    /// </summary>
    [TestMethod]
    public async Task PostTerm_NewTerm_CreatesClientTerm()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId);
        string termId = $"term-{Guid.NewGuid():N}"[..32];

        var controller = new ClientTermController(context);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["term_seq_id"] = "",
            ["term_name"] = termId,
            ["term_version"] = "1",
            ["required"] = "1",
            ["term_url"] = $"https://portal.osolab-auth.jp/terms/{termId}"
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTerm();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));
        Assert.AreEqual(termId, body.Value<string>("TermId"));
        Assert.IsTrue(await context.client_terms.AnyAsync(x => x.client_id == clientId && x.term_id == termId));
    }

    /// <summary>
    /// 検証項目: POST /Term のrequired不正値で00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PostTerm_InvalidRequired_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        await ApiTestData.CreateClientAsync(context, clientId);
        var controller = new ClientTermController(context);
        var httpContext = ControllerTestHelper.CreateFormContext(new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["term_name"] = "term-invalid-required",
            ["required"] = "2",
            ["term_url"] = "https://portal.osolab-auth.jp/terms/invalid"
        });
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PostTerm();

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }
}
