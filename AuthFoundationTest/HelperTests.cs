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
    public void GenerateHex_RejectsNonPositiveLength()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() => Helper.GenerateHex(0));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    [TestMethod]
    public void ParseScopes_RemovesDuplicatesAndBlanks()
    {
        string[] scopes = Helper.ParseScopes("openid  email openid");

        CollectionAssert.AreEqual(new[] { "openid", "email" }, scopes);
    }

    [TestMethod]
    public void IsJsonContentType_ReturnsExpectedResult()
    {
        Assert.IsTrue(Helper.IsJsonContentType("application/json; charset=utf-8"));
        Assert.IsFalse(Helper.IsJsonContentType("text/plain"));
        Assert.IsFalse(Helper.IsJsonContentType(null));
    }
}
