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
    /// <summary>
    /// 前提条件
    /// 　DB：テスト実行前の初期データを投入可能
    /// 　リクエスト：なし（テスト初期化処理）
    /// 期待値
    /// 　共通設定とテスト実行環境が初期化される
    /// </summary>
    /// <returns></returns>
    [TestInitialize]
    public void Initialize()
    {
        AppConfigTestHelper.Initialize();
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Users を Valid Inner Client 条件で実行
    /// 期待値
    /// 　Returns Filtered Users を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Users を Invalid Inner Client Secret 条件で実行
    /// 期待値
    /// 　Returns Illegal Client を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Claims を Valid Request 条件で実行
    /// 期待値
    /// 　Returns Claims を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Put Claims を Valid Request 条件で実行
    /// 期待値
    /// 　Updates User And Claims を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Put Claims を Unsupported Data Key 条件で実行
    /// 期待値
    /// 　Returns Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
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
