using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class HelperTests
{
    /// <summary>
    /// GenerateHexが指定桁数の小文字16進文字列を返すことを確認する。
    /// </summary>
    [TestMethod]
    public void GenerateHex_ReturnsRequestedLength()
    {
        string value = Helper.GenerateHex(16);

        Assert.AreEqual(16, value.Length);
        StringAssert.Matches(value, new System.Text.RegularExpressions.Regex("^[a-f0-9]+$"));
    }

    /// <summary>
    /// ParseScopesが空白と重複を除外したscope配列を返すことを確認する。
    /// </summary>
    [TestMethod]
    public void ParseScopes_RemovesDuplicatesAndBlanks()
    {
        string[] scopes = Helper.ParseScopes("openid  email openid");

        CollectionAssert.AreEqual(new[] { "openid", "email" }, scopes);
    }
}
