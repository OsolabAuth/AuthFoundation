using AuthFoundation.Common;
using AuthFoundation.Controllers.Inner;
using AuthFoundation.Models;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json.Linq;

namespace AuthFoundationTest;

[TestClass]
public sealed class InnerUserApiTests
{
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 検証項目: GET /inner/users 正常系で内部クライアントBasic認証を検証し、email/status filterに一致するユーザーを返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetUsers_ValidInnerClient_ReturnsFilteredUsers()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string email = $"inner-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateUserAsync(context, ApiTestData.NewOsolabId(), email, ApiTestData.NewPassword());

        var controller = new InnerUserController(context);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(Code.InnerClient.OSOLAB_CLIENT_ID, "0000000000000000");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetUsers(email, Code.Status.ACTIVE);

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.IsTrue(body["users"]!.Any(x => x.Value<string>("email") == email));
    }

    /// <summary>
    /// 検証項目: GET /inner/users のBasic認証secret不一致時に00002を返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetUsers_InvalidInnerClientSecret_ReturnsIllegalClient()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        var controller = new InnerUserController(context);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(Code.InnerClient.OSOLAB_CLIENT_ID, "wrong");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetUsers();

        ControllerTestHelper.AssertError(result, (int)Code.ILLEGAL_CLIENT.Status, Code.ILLEGAL_CLIENT.Code);
    }

    /// <summary>
    /// 検証項目: GET /inner/users/{osolabId}/claims 正常系で対象client_idのclaimsを返すこと。
    /// </summary>
    [TestMethod]
    public async Task GetClaims_ValidRequest_ReturnsClaims()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"claims-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());
        context.user_infos.Add(new user_info
        {
            osolab_id = osolabId,
            client_id = clientId,
            data_key = "name",
            data_value = "Claims User",
            create_datetime = DateTime.UtcNow,
            update_datetime = DateTime.UtcNow,
            status = Code.Status.ACTIVE
        });
        await context.SaveChangesAsync();

        var controller = new InnerUserController(context);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(Code.InnerClient.OSOLAB_CLIENT_ID, "0000000000000000");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.GetClaims(osolabId, clientId);

        Assert.IsInstanceOfType<OkObjectResult>(result);
        JObject body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(osolabId, body.Value<string>("osolab_id"));
        Assert.AreEqual("Claims User", body["claims"]!.Value<string>("name"));
    }

    /// <summary>
    /// 検証項目: PUT /inner/users/{osolabId}/claims 正常系でemail/status/claimsを更新すること。
    /// </summary>
    [TestMethod]
    public async Task PutClaims_ValidRequest_UpdatesUserAndClaims()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string osolabId = ApiTestData.NewOsolabId();
        string email = $"putclaims-{Guid.NewGuid():N}@example.com";
        string updatedEmail = $"updated-{Guid.NewGuid():N}@example.com";
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateUserAsync(context, osolabId, email, ApiTestData.NewPassword());

        var controller = new InnerUserController(context);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(Code.InnerClient.OSOLAB_CLIENT_ID, "0000000000000000");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PutClaims(osolabId, new InnerUserController.UpsertClaimsInput
        {
            ClientId = clientId,
            Email = updatedEmail,
            Status = Code.Status.ACTIVE,
            Claims = new Dictionary<string, string>
            {
                ["name"] = "Updated User"
            }
        });

        Assert.IsInstanceOfType<OkObjectResult>(result);
        Assert.AreEqual(updatedEmail, (await context.osolab_users.SingleAsync(x => x.osolab_id == osolabId)).email);
        Assert.AreEqual("Updated User", (await context.user_infos.SingleAsync(x =>
            x.osolab_id == osolabId
            && x.client_id == clientId
            && x.data_key == "name")).data_value);
    }

    /// <summary>
    /// 検証項目: PUT /inner/users/{osolabId}/claims で未定義data_key指定時に00001を返すこと。
    /// </summary>
    [TestMethod]
    public async Task PutClaims_UnsupportedDataKey_ReturnsRequestParameterError()
    {
        await using var context = TestDbContextFactory.Create();
        await ApiTestData.AssertDatabaseAvailableAsync(context);

        string clientId = ApiTestData.NewClientId();
        string osolabId = ApiTestData.NewOsolabId();
        await ApiTestData.CreateClientAsync(context, clientId);
        await ApiTestData.CreateUserAsync(context, osolabId, $"unsupported-{Guid.NewGuid():N}@example.com", ApiTestData.NewPassword());

        var controller = new InnerUserController(context);
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers.Authorization = ControllerTestHelper.BasicAuthorization(Code.InnerClient.OSOLAB_CLIENT_ID, "0000000000000000");
        controller.ControllerContext = new ControllerContext { HttpContext = httpContext };

        IActionResult result = await controller.PutClaims(osolabId, new InnerUserController.UpsertClaimsInput
        {
            ClientId = clientId,
            Claims = new Dictionary<string, string>
            {
                ["unsupported_key"] = "value"
            }
        });

        ControllerTestHelper.AssertError(result, (int)Code.REQUEST_PARAMETER_ERROR.Status, Code.REQUEST_PARAMETER_ERROR.Code);
    }
}
