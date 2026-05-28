using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordChangeTests
{
    [TestMethod]
    public void ChangePassword_UpdatesPasswordHash()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("change@example.com", "Passw0rd!", "Change User", new DateOnly(2000, 1, 1));

        users.ChangePassword("change@example.com", "Passw0rd!", "NewPassw0rd!");
        UserRecord user = users.Authenticate("change@example.com", "NewPassw0rd!");

        Assert.AreEqual("Change User", user.Name);
    }
}
