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
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            ValidateUtil.FormatParam("invalid", "email", Code.HttpBodies.EMAIL.Regex));

        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    [TestMethod]
    public void IndispensableParam_RejectsBlankValue()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            ValidateUtil.IndispensableParam(" ", "email"));

        Assert.AreEqual("email is required", error.ErrorDescription);
    }

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
