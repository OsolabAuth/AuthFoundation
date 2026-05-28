using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class ValidateUtilTests
{
    /// <summary>
    /// FormatParamが正規表現に一致する値を受け付けることを確認する。
    /// </summary>
    [TestMethod]
    public void FormatParam_AcceptsMatchingValue()
    {
        ValidateUtil.FormatParam("test@example.com", "email", Code.HttpBodies.EMAIL.Regex);
    }

    /// <summary>
    /// FormatParamが正規表現に一致しない値を拒否することを確認する。
    /// </summary>
    [TestMethod]
    public void FormatParam_RejectsInvalidValue()
    {
        try
        {
            ValidateUtil.FormatParam("invalid", "email", Code.HttpBodies.EMAIL.Regex);
            Assert.Fail("Expected ApiException.");
        }
        catch (ApiException)
        {
        }
    }
}
