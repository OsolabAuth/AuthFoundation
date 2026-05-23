using AuthFoundation.Common;
using AuthFoundation.Controllers;
using AuthFoundationTest.TestSupport;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class VersionApiTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Get Version を 標準入力 条件で実行
    /// 期待値
    /// 　Returns Version を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public async Task GetVersion_ReturnsVersion()
    {
        var controller = new VersionController();
        controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };

        IActionResult result = await controller.GetVersion();

        Assert.IsInstanceOfType<OkObjectResult>(result);
        var body = ControllerTestHelper.ToJObject(result);
        Assert.AreEqual(Code.SUCCESS.Code, body.Value<string>("StatusCode"));
        Assert.IsFalse(string.IsNullOrWhiteSpace(body.Value<string>("Version")));
    }
}
