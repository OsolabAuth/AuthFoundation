using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetTests
{
    [TestMethod]
    public void ResetPassword_RequiresMatchingBirthDate()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reset@example.com", "Passw0rd!", "Reset User", new DateOnly(2001, 2, 3));

        users.ResetPassword("reset@example.com", new DateOnly(2001, 2, 3), "ResetPassw0rd!");
        UserRecord user = users.Authenticate("reset@example.com", "ResetPassw0rd!");

        Assert.AreEqual("Reset User", user.Name);
    }
}
