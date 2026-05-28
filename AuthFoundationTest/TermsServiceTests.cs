using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class TermsServiceTests
{
    [TestMethod]
    public void Current_ReturnsTermsDocument()
    {
        var service = new TermsService();
        TermsDocument terms = service.Current();

        Assert.AreEqual(TermsService.CurrentTermsId, terms.TermsId);
        Assert.IsFalse(string.IsNullOrWhiteSpace(terms.Body));
    }
}
