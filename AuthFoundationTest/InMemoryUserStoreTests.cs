using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class InMemoryUserStoreTests
{
    /// <summary>
    /// 目的: Authenticate / Returns Created User の仕様を検証する。
    /// 入力値: Authenticate / Returns Created User を確認するためにテスト内で作成したデータ。
    /// 期待値: Authenticate / Returns Created User の期待結果になること。
    /// </summary>
    [TestMethod]
    public void Authenticate_ReturnsCreatedUser()
    {
        var users = new InMemoryUserStore();
        UserRecord created = users.CreateUser("new@example.com", "Passw0rd!", "New User", new DateOnly(2000, 1, 1));

        UserRecord authenticated = users.Authenticate("new@example.com", "Passw0rd!");

        Assert.AreEqual(created.Subject, authenticated.Subject);
        Assert.AreEqual("New User", authenticated.Name);
        Assert.IsTrue(authenticated.CreatedAt <= DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// 目的: Authenticate / Rejects Wrong Password の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void Authenticate_RejectsWrongPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reject@example.com", "Passw0rd!", "Reject User", new DateOnly(2000, 1, 1));

        Assert.ThrowsExactly<ApiException>(() => users.Authenticate("reject@example.com", "WrongPassw0rd!"));
    }

    /// <summary>
    /// 目的: Authenticate / Rejects Unknown Email の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void Authenticate_RejectsUnknownEmail()
    {
        var users = new InMemoryUserStore();

        Assert.ThrowsExactly<ApiException>(() => users.Authenticate("missing@example.com", "Passw0rd!"));
    }

    /// <summary>
    /// 目的: Create User / Rejects Duplicate Email の仕様を検証する。
    /// 入力値: Create User / Rejects Duplicate Email を確認するためにテスト内で作成したデータ。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void CreateUser_RejectsDuplicateEmail()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("duplicate@example.com", "Passw0rd!", "Duplicate User", new DateOnly(2000, 1, 1));

        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => users.CreateUser("DUPLICATE@example.com", "Passw0rd!", "Duplicate User", new DateOnly(2000, 1, 1)));

        Assert.AreEqual("00001", error.InternalCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email is already registered", error.ErrorDescription);
    }

    /// <summary>
    /// 目的: Find By Email / Rejects Unknown Email の仕様を検証する。
    /// 入力値: 存在しないIDやメールアドレスなど、未知の対象を表す値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void FindByEmail_RejectsUnknownEmail()
    {
        var users = new InMemoryUserStore();

        Assert.ThrowsExactly<ApiException>(() => users.FindByEmail("missing@example.com"));
    }
}
