using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class InMemoryUserStoreTests
{
    /// <summary>
    /// Authenticateが登録済みユーザーを返すことを確認する。
    /// </summary>
    [TestMethod]
    public void Authenticate_ReturnsCreatedUser()
    {
        var users = new InMemoryUserStore();
        UserRecord created = users.CreateUser("new@example.com", "Passw0rd!", "New User");

        UserRecord authenticated = users.Authenticate("new@example.com", "Passw0rd!");

        Assert.AreEqual(created.Subject, authenticated.Subject);
        Assert.AreEqual("New User", authenticated.Name);
    }

    /// <summary>
    /// Authenticateが誤ったパスワードを拒否することを確認する。
    /// </summary>
    [TestMethod]
    public void Authenticate_RejectsWrongPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reject@example.com", "Passw0rd!", "Reject User");

        Assert.ThrowsExactly<ApiException>(() => users.Authenticate("reject@example.com", "WrongPassw0rd!"));
    }

    /// <summary>
    /// Authenticateが未登録メールアドレスを拒否することを確認する。
    /// </summary>
    [TestMethod]
    public void Authenticate_RejectsUnknownEmail()
    {
        var users = new InMemoryUserStore();

        Assert.ThrowsExactly<ApiException>(() => users.Authenticate("missing@example.com", "Passw0rd!"));
    }

    /// <summary>
    /// CreateUserが大文字小文字を区別せず重複メールアドレスを拒否することを確認する。
    /// </summary>
    [TestMethod]
    public void CreateUser_RejectsDuplicateEmail()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("duplicate@example.com", "Passw0rd!", "Duplicate User");

        ApiException error = Assert.ThrowsExactly<ApiException>(
            () => users.CreateUser("DUPLICATE@example.com", "Passw0rd!", "Duplicate User"));

        Assert.AreEqual("00001", error.InternalCode);
        Assert.AreEqual("invalid_request", error.Error);
        Assert.AreEqual("email is already registered", error.ErrorDescription);
    }
}
