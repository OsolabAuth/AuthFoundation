using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text;

namespace AuthFoundationTest.TestSupport;

internal static class ControllerTestHelper
{
    public static DefaultHttpContext CreateFormContext(IDictionary<string, string> values)
    {
        return CreateFormContext(values.ToDictionary(
            pair => pair.Key,
            pair => new[] { pair.Value }.AsEnumerable()));
    }

    public static DefaultHttpContext CreateFormContext(IDictionary<string, IEnumerable<string>> values)
    {
        var context = new DefaultHttpContext();
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.Form = new FormCollection(values.ToDictionary(
            pair => pair.Key,
            pair => new StringValues(pair.Value.ToArray())));

        return context;
    }

    public static DefaultHttpContext CreateJsonContext(object body)
    {
        return CreateJsonContext(JsonConvert.SerializeObject(body));
    }

    public static DefaultHttpContext CreateJsonContext(string rawJson)
    {
        var context = new DefaultHttpContext();
        context.Request.ContentType = "application/json";
        context.Request.Body = new MemoryStream(Encoding.UTF8.GetBytes(rawJson));
        return context;
    }

    public static void SetCookie(DefaultHttpContext context, string name, string value)
    {
        string current = context.Request.Headers.Cookie.ToString();
        string appended = $"{name}={value}";
        context.Request.Headers.Cookie = string.IsNullOrWhiteSpace(current)
            ? appended
            : $"{current}; {appended}";
    }

    public static string ExtractCookieValue(IHeaderDictionary headers, string key)
    {
        string setCookie = string.Join("\n", headers.SetCookie.ToArray());
        foreach (string cookie in setCookie.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!cookie.StartsWith($"{key}=", StringComparison.Ordinal))
            {
                continue;
            }

            string valuePart = cookie.Split(';', 2)[0];
            return valuePart[(key.Length + 1)..];
        }

        Assert.Fail($"Cookie '{key}' was not set.");
        return string.Empty;
    }

    public static string BasicAuthorization(string userName, string password)
    {
        string raw = $"{userName}:{password}";
        return $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes(raw))}";
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

    public static JObject AssertError(IActionResult result, int statusCode, string responseCode)
    {
        Assert.IsInstanceOfType<ObjectResult>(result);
        var objectResult = (ObjectResult)result;
        Assert.AreEqual(statusCode, objectResult.StatusCode);

        JObject body = ToJObject(result);
        Assert.AreEqual(responseCode, body.Value<string>("error_code") ?? body.Value<string>("response_code") ?? body.Value<string>("StatusCode"));
        return body;
    }
}
