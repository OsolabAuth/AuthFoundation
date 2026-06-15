using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class TermsServiceTests
{
    /// <summary>
    /// 逶ｮ逧・ Current / Returns Terms Document 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Current / Returns Terms Document 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Current / Returns Terms Document 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void Current_ReturnsTermsDocument()
    {
        var service = new TermsService();
        TermsDocument terms = service.Current();

        Assert.AreEqual(TermsService.CurrentTermsId, terms.TermsId);
        Assert.IsFalse(string.IsNullOrWhiteSpace(terms.Body));
    }
}
