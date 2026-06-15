using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class AccountWithdrawalTests
{
    /// <summary>
    /// 逶ｮ逧・ Withdraw / Removes User 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Withdraw / Removes User 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Withdraw / Removes User 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
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
