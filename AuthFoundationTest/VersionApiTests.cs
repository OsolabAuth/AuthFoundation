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
    /// 検証項目: GET /Version が00000と現在のバージョン文字列を返すこと。
    /// </summary>
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
