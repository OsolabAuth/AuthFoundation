using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class HelperTests
{
    /// <summary>
    /// 目的: Generate Hex / Returns Requested Length の仕様を検証する。
    /// 入力値: Generate Hex / Returns Requested Length を確認するためにテスト内で作成したデータ。
    /// 期待値: Generate Hex / Returns Requested Length の期待結果になること。
    /// </summary>
    [TestMethod]
    public void GenerateHex_ReturnsRequestedLength()
    {
        string value = Helper.GenerateHex(16);

        Assert.AreEqual(16, value.Length);
        StringAssert.Matches(value, new System.Text.RegularExpressions.Regex("^[a-f0-9]+$"));
    }

    /// <summary>
    /// 目的: Generate Hex / Rejects Non Positive Length の仕様を検証する。
    /// 入力値: Generate Hex / Rejects Non Positive Length を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void GenerateHex_RejectsNonPositiveLength()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() => Helper.GenerateHex(0));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Generate Numeric Code / Returns Requested Digit Length の仕様を検証する。
    /// 入力値: Generate Numeric Code / Returns Requested Digit Length を確認するためにテスト内で作成したデータ。
    /// 期待値: Generate Numeric Code / Returns Requested Digit Length の期待結果になること。
    /// </summary>
    [TestMethod]
    public void GenerateNumericCode_ReturnsRequestedDigitLength()
    {
        string value = Helper.GenerateNumericCode(6);

        Assert.AreEqual(6, value.Length);
        StringAssert.Matches(value, new System.Text.RegularExpressions.Regex("^[0-9]{6}$"));
    }

    /// <summary>
    /// 目的: Generate Numeric Code / Rejects Non Positive Length の仕様を検証する。
    /// 入力値: Generate Numeric Code / Rejects Non Positive Length を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void GenerateNumericCode_RejectsNonPositiveLength()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() => Helper.GenerateNumericCode(0));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Generate Numeric Code / Rejects Too Large Length の仕様を検証する。
    /// 入力値: Generate Numeric Code / Rejects Too Large Length を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void GenerateNumericCode_RejectsTooLargeLength()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() => Helper.GenerateNumericCode(10));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.InternalCode, error.InternalCode);
    }

    /// <summary>
    /// 目的: Parse Scopes / Removes Duplicates And Blanks の仕様を検証する。
    /// 入力値: Parse Scopes / Removes Duplicates And Blanks を確認するためにテスト内で作成したデータ。
    /// 期待値: Parse Scopes / Removes Duplicates And Blanks の期待結果になること。
    /// </summary>
    [TestMethod]
    public void ParseScopes_RemovesDuplicatesAndBlanks()
    {
        string[] scopes = Helper.ParseScopes("openid  email openid");

        CollectionAssert.AreEqual(new[] { "openid", "email" }, scopes);
    }

    /// <summary>
    /// 目的: Is Json Content Type / Returns Expected Result の仕様を検証する。
    /// 入力値: Is Json Content Type / Returns Expected Result を確認するためにテスト内で作成したデータ。
    /// 期待値: Is Json Content Type / Returns Expected Result の期待結果になること。
    /// </summary>
    [TestMethod]
    public void IsJsonContentType_ReturnsExpectedResult()
    {
        Assert.IsTrue(Helper.IsJsonContentType("application/json; charset=utf-8"));
        Assert.IsFalse(Helper.IsJsonContentType("text/plain"));
        Assert.IsFalse(Helper.IsJsonContentType(null));
    }
}
