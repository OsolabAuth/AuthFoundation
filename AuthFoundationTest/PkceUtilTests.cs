using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class PkceUtilTests
{
    [TestMethod]
    public void CreateS256Challenge_ReturnsKnownValue()
    {
        string challenge = PkceUtil.CreateS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        Assert.AreEqual("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
    }
}
