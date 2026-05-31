using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class HelperTests
{
    [TestMethod]
    public void GenerateHex_ReturnsRequestedLength()
    {
        string value = Helper.GenerateHex(16);

        Assert.AreEqual(16, value.Length);
        StringAssert.Matches(value, new System.Text.RegularExpressions.Regex("^[a-f0-9]+$"));
    }

    [TestMethod]
    public void ParseScopes_RemovesDuplicatesAndBlanks()
    {
        string[] scopes = Helper.ParseScopes("openid  email openid");

        CollectionAssert.AreEqual(new[] { "openid", "email" }, scopes);
    }
}
