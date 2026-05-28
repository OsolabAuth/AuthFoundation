using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class InMemoryUserStoreTests
{
    /// <summary>
    /// Purpose: verify a user registered by the test can authenticate.
    /// Input: email=new@example.com, password=Passw0rd!, name=New User.
    /// Expected: Authenticate returns the same subject and name.
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
    /// Purpose: verify authentication rejects a mismatched password.
    /// Input: registered email=reject@example.com, password=WrongPassw0rd!.
    /// Expected: ApiException unauthorized.
    /// </summary>
    [TestMethod]
    public void Authenticate_RejectsWrongPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reject@example.com", "Passw0rd!", "Reject User");

        Assert.ThrowsExactly<ApiException>(() => users.Authenticate("reject@example.com", "WrongPassw0rd!"));
    }

    /// <summary>
    /// Purpose: verify authentication rejects an unknown email.
    /// Input: missing email=missing@example.com.
    /// Expected: ApiException unauthorized.
    /// </summary>
    [TestMethod]
    public void Authenticate_RejectsUnknownEmail()
    {
        var users = new InMemoryUserStore();

        Assert.ThrowsExactly<ApiException>(() => users.Authenticate("missing@example.com", "Passw0rd!"));
    }

    /// <summary>
    /// Purpose: verify duplicate email registration is rejected case-insensitively.
    /// Input: duplicate email values duplicate@example.com and DUPLICATE@example.com.
    /// Expected: ApiException invalid_request with duplicate email message.
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
