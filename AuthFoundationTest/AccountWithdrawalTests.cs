using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AccountWithdrawalTests
{
    [TestMethod]
    public void Withdraw_RemovesUser()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("withdraw@example.com", "Passw0rd!", "Withdraw User", new DateOnly(2000, 1, 1));

        UserRecord removed = users.Withdraw("withdraw@example.com", "Passw0rd!");

        Assert.AreEqual("Withdraw User", removed.Name);
        Assert.ThrowsExactly<ApiException>(() => users.FindByEmail("withdraw@example.com"));
    }
}
