using AuthFoundation.Controllers;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class VersionEndpointShapeTests
{
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
