using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordUtilTests
{
    /// <summary>
    /// 目的: Verify / Returns True For Matching Password の仕様を検証する。
    /// 入力値: Verify / Returns True For Matching Password を確認するためにテスト内で作成したデータ。
    /// 期待値: Verify / Returns True For Matching Password の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsTrueForMatchingPassword()
    {
        string hash = PasswordUtil.Hash("Passw0rd!");

        Assert.IsTrue(PasswordUtil.Verify("Passw0rd!", hash));
    }

    /// <summary>
    /// 目的: Verify / Returns False For Different Password の仕様を検証する。
    /// 入力値: Verify / Returns False For Different Password を確認するためにテスト内で作成したデータ。
    /// 期待値: Verify / Returns False For Different Password の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsFalseForDifferentPassword()
    {
        string hash = PasswordUtil.Hash("Passw0rd!");

        Assert.IsFalse(PasswordUtil.Verify("WrongPassw0rd!", hash));
    }

    /// <summary>
    /// 目的: Verify / Returns False For Malformed Hash の仕様を検証する。
    /// 入力値: Verify / Returns False For Malformed Hash を確認するためにテスト内で作成したデータ。
    /// 期待値: Verify / Returns False For Malformed Hash の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsFalseForMalformedHash()
    {
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "invalid"));
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "iterations.salt.hash"));
    }
}
