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

    /// <summary>
    /// Purpose: verify numeric verification codes keep the requested fixed width.
    /// Input: digits=6.
    /// Expected: generated value has 6 numeric characters.
    /// </summary>
    [TestMethod]
    public void GenerateNumericCode_ReturnsRequestedDigitLength()
    {
        string value = Helper.GenerateNumericCode(6);

        Assert.AreEqual(6, value.Length);
        StringAssert.Matches(value, new System.Text.RegularExpressions.Regex("^[0-9]{6}$"));
    }

    /// <summary>
    /// Purpose: verify invalid numeric verification code lengths are rejected.
    /// Input: digits=0.
    /// Expected: request parameter ApiException.
    /// </summary>
    [TestMethod]
    public void GenerateNumericCode_RejectsNonPositiveLength()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() => Helper.GenerateNumericCode(0));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// Purpose: verify numeric verification code lengths that would overflow the range are rejected.
    /// Input: digits=10.
    /// Expected: request parameter ApiException.
    /// </summary>
    [TestMethod]
    public void GenerateNumericCode_RejectsTooLargeLength()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() => Helper.GenerateNumericCode(10));

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
