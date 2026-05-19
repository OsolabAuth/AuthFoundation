using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace AuthFoundationTest.TestSupport;

internal static class ControllerTestHelper
{
    public static DefaultHttpContext CreateFormContext(IDictionary<string, string> values)
    {
        var context = new DefaultHttpContext();
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Form = new FormCollection(values.ToDictionary(
            pair => pair.Key,
            pair => new StringValues(pair.Value)));

        return context;
    }

    public static JObject ToJObject(IActionResult result)
    {
        object? value = result switch
        {
            ObjectResult objectResult => objectResult.Value,
            JsonResult jsonResult => jsonResult.Value,
            _ => null
        };

        Assert.IsNotNull(value);
        return JObject.Parse(JsonConvert.SerializeObject(value));
    }
}
