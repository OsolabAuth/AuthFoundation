using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class ValidateUtilTests
{
    /// <summary>
    /// 目的: Format Param / Accepts Matching Value の仕様を検証する。
    /// 入力値: Format Param / Accepts Matching Value を確認するためにテスト内で作成したデータ。
    /// 期待値: Format Param / Accepts Matching Value の期待結果になること。
    /// </summary>
    [TestMethod]
    public void FormatParam_AcceptsMatchingValue()
    {
        ValidateUtil.FormatParam("test@example.com", "email", Code.HttpBodies.EMAIL.Regex);
    }

    /// <summary>
    /// 目的: Format Param / Rejects Invalid Value の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void FormatParam_RejectsInvalidValue()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            ValidateUtil.FormatParam("invalid", "email", Code.HttpBodies.EMAIL.Regex));

        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Indispensable Param / Rejects Blank Value の仕様を検証する。
    /// 入力値: Indispensable Param / Rejects Blank Value を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void IndispensableParam_RejectsBlankValue()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            ValidateUtil.IndispensableParam(" ", "email"));

        Assert.AreEqual("email is required", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Error Output / Copies Api Exception Fields の仕様を検証する。
    /// 入力値: Error Output / Copies Api Exception Fields を確認するためにテスト内で作成したデータ。
    /// 期待値: Error Output / Copies Api Exception Fields の期待結果になること。
    /// </summary>
    [TestMethod]
    public void ErrorOutput_CopiesApiExceptionFields()
    {
        var exception = new ApiException("99999", System.Net.HttpStatusCode.Conflict, "conflict", "conflict detail");

        var output = new ErrorOutput(exception);

        Assert.AreEqual("99999", exception.InternalCode);
        Assert.AreEqual(System.Net.HttpStatusCode.Conflict, exception.StatusCode);
        Assert.AreEqual("conflict", exception.Error);
        Assert.AreEqual("conflict detail", exception.ErrorDescription);
        Assert.AreEqual("conflict detail", exception.Message);
        Assert.AreEqual("99999", output.ResponseCode);
        Assert.AreEqual("99999", output.ErrorCode);
        Assert.AreEqual("conflict detail", output.Message);
        Assert.AreEqual("conflict", output.Error);
        Assert.AreEqual("conflict detail", output.ErrorDescription);
    }
}
