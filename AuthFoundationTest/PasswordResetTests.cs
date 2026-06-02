using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetTests
{
    /// <summary>
    /// 目的: Reset Password / Requires Matching Birth Date の仕様を検証する。
    /// 入力値: Reset Password / Requires Matching Birth Date を確認するためにテスト内で作成したデータ。
    /// 期待値: Reset Password / Requires Matching Birth Date の期待結果になること。
    /// </summary>
    [TestMethod]
    public void ResetPassword_RequiresMatchingBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset@example.com", "Passw0rd!", "Reset User", new DateOnly(2001, 2, 3));

        users.ResetPassword("reset@example.com", new DateOnly(2001, 2, 3), "ResetPassw0rd!");
        UserRecord user = users.Authenticate("reset@example.com", "ResetPassw0rd!");

        Assert.AreEqual("Reset User", user.Name);
    }

    /// <summary>
    /// 目的: Reset Password / Rejects Mismatched Birth Date の仕様を検証する。
    /// 入力値: Reset Password / Rejects Mismatched Birth Date を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void ResetPassword_RejectsMismatchedBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset-mismatch-service@example.com", "Passw0rd!", "Reset User", new DateOnly(2001, 2, 3));

        Assert.ThrowsExactly<AuthFoundation.Common.ApiException>(
            () => users.ResetPassword("reset-mismatch-service@example.com", new DateOnly(2001, 2, 4), "ResetPassw0rd!"));
        UserRecord user = users.Authenticate("reset-mismatch-service@example.com", "Passw0rd!");

        Assert.AreEqual("Reset User", user.Name);
    }
}
