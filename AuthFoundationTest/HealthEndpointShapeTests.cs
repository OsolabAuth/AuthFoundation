using AuthFoundation.Common;
using AuthFoundation.Controllers.Auth;
using Microsoft.AspNetCore.Mvc;

namespace AuthFoundationTest;

[TestClass]
public sealed class HealthEndpointShapeTests
{
    [TestMethod]
    public void Live_ReturnsOkHealthContract()
    {
        var controller = new HealthController();

        IActionResult action = controller.Live();

        var ok = AssertOk(action);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("ok", ReadProperty<string>(ok.Value, "status"));
        Assert.AreEqual("live", ReadProperty<string>(ok.Value, "check"));
        Assert.IsTrue(ReadProperty<DateTimeOffset>(ok.Value, "checked_at") <= DateTimeOffset.UtcNow);
    }

    [TestMethod]
    public void Ready_ReturnsOkHealthContract()
    {
        var controller = new HealthController();

        IActionResult action = controller.Ready();

        var ok = AssertOk(action);
        Assert.AreEqual(200, ok.StatusCode ?? 200);
        Assert.AreEqual("ok", ReadProperty<string>(ok.Value, "status"));
        Assert.AreEqual("ready", ReadProperty<string>(ok.Value, "check"));
        Assert.AreEqual(AppConfig.Issuer.TrimEnd('/'), ReadProperty<string>(ok.Value, "issuer"));
        Assert.AreEqual(AppConfig.AuthUiBaseUrl, ReadProperty<string>(ok.Value, "auth_ui_base_url"));
        Assert.IsTrue(ReadProperty<DateTimeOffset>(ok.Value, "checked_at") <= DateTimeOffset.UtcNow);
    }

    [TestMethod]
    public void AppConfig_DefaultIssuer_IsConfiguredForReadyCheck()
    {
        Assert.IsTrue(AppConfig.Issuer.StartsWith("https://", StringComparison.Ordinal));
        Assert.IsFalse(string.IsNullOrWhiteSpace(AppConfig.AuthUiBaseUrl));
    }

    private static OkObjectResult AssertOk(IActionResult action)
    {
        var ok = action as OkObjectResult;
        Assert.IsNotNull(ok);
        Assert.IsNotNull(ok.Value);
        return ok;
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
