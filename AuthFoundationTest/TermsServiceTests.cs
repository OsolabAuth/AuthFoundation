using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class TermsServiceTests
{
    /// <summary>
    /// 目的: Current / Returns Terms Document の仕様を検証する。
    /// 入力値: Current / Returns Terms Document を確認するためにテスト内で作成したデータ。
    /// 期待値: Current / Returns Terms Document の期待結果になること。
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
