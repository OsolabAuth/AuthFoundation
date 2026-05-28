using AuthFoundation.Common;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System.Text;

namespace AuthFoundationTest;

internal static class EndpointTestHelper
{
    public static TController WithHttpContext<TController>(TController controller)
        where TController : ControllerBase
    {
        controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };
        return controller;
    }

    public static void SetForm(HttpContext context, Dictionary<string, StringValues> values)
    {
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(string.Empty));
        context.Features.Set<IFormFeature>(new FormFeature(new FormCollection(values)));
    }

    public static OkObjectResult AssertOk(IActionResult action)
    {
        var ok = action as OkObjectResult;
        Assert.IsNotNull(ok);
        Assert.IsNotNull(ok.Value);
        return ok;
    }

    public static ErrorOutput AssertError(IActionResult action, int statusCode)
    {
        var result = action as ObjectResult;
        Assert.IsNotNull(result);
        Assert.AreEqual(statusCode, result.StatusCode);
        var output = result.Value as ErrorOutput;
        Assert.IsNotNull(output);
        return output;
    }

    public static T ReadProperty<T>(object? target, string name)
    {
        Assert.IsNotNull(target);
        var property = target.GetType().GetProperty(name);
        Assert.IsNotNull(property);

        object? value = property.GetValue(target);
        Assert.IsInstanceOfType<T>(value);
        return (T)value;
    }
}
