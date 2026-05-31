using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class ValidateUtilTests
{
    [TestMethod]
    public void FormatParam_AcceptsMatchingValue()
    {
        ValidateUtil.FormatParam("test@example.com", "email", Code.HttpBodies.EMAIL.Regex);
    }

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
