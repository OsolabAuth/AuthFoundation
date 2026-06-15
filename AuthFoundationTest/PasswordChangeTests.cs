using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordChangeTests
{
    /// <summary>
    /// 逶ｮ逧・ Change Password / Updates Password Hash 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Change Password / Updates Password Hash 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Change Password / Updates Password Hash 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
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
