using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetTests
{
    /// <summary>
    /// Purpose: verify direct password reset updates the password when birth date matches.
    /// Input: registered email, matching birth date, and strong new password.
    /// Expected: new password authenticates.
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
    /// Purpose: verify direct password reset rejects mismatched birth date.
    /// Input: registered email, wrong birth date, and strong new password.
    /// Expected: ApiException and old password remains valid.
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
