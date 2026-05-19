using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class HelperTests
{
    [TestMethod]
    public void ParseScopes_TrimsEmptyValuesAndRemovesDuplicates()
    {
        List<string> scopes = Helper.ParseScopes("openid  email openid profile ");

        CollectionAssert.AreEqual(
            new[] { "openid", "email", "profile" },
            scopes);
    }

    [TestMethod]
    [DataRow("https://client.example.com/callback", true)]
    [DataRow("http://localhost:3000/callback", true)]
    [DataRow("http://osolab-app-local:3000/callback", true)]
    [DataRow("http://example.com/callback", false)]
    [DataRow("ftp://localhost/callback", false)]
    public void IsRedirectUriFormatValid_AppliesProductionAndLocalhostRules(string redirectUri, bool expected)
    {
        Assert.AreEqual(expected, Helper.IsRedirectUriFormatValid(redirectUri));
    }

    [TestMethod]
    public void BuildRedirectUri_AppendsEscapedParameters()
    {
        string redirectUri = Helper.BuildRedirectUri(
            "https://client.example.com/callback",
            new Dictionary<string, string>
            {
                ["code"] = "abc 123",
                ["state"] = "x/y"
            });

        Assert.AreEqual("https://client.example.com/callback?code=abc%20123&state=x%2Fy", redirectUri);
    }
}
