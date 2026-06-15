using AuthFoundation.Controllers;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class VersionEndpointShapeTests
{
    /// <summary>
    /// 逶ｮ逧・ Get / Returns Service Version Status 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Get / Returns Service Version Status 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Get / Returns Service Version Status 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Get_ReturnsServiceVersionStatus()
    {
        var controller = new VersionController();

        var ok = controller.Get() as OkObjectResult;

        Assert.IsNotNull(ok);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("AuthFoundation", ReadProperty<string>(ok.Value, "service"));
        Assert.AreEqual("rebuild-common", ReadProperty<string>(ok.Value, "version"));
        Assert.AreEqual("ok", ReadProperty<string>(ok.Value, "status"));
    }

    private static T ReadProperty<T>(object? target, string name)
    {
        Assert.IsNotNull(target);
        var property = target.GetType().GetProperty(name);
        Assert.IsNotNull(property);

        object? value = property.GetValue(target);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }
}
