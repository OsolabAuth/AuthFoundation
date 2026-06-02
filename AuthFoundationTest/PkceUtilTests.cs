using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class PkceUtilTests
{
    /// <summary>
    /// 目的: Create S256 Challenge / Returns Known Value の仕様を検証する。
    /// 入力値: テスト内で登録した正常な対象データ。
    /// 期待値: Create S256 Challenge / Returns Known Value の期待結果になること。
    /// </summary>
    [TestMethod]
    public void CreateS256Challenge_ReturnsKnownValue()
    {
        string challenge = PkceUtil.CreateS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        Assert.AreEqual("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
    }
}
