using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordResetTests
{
    /// <summary>
    /// 逶ｮ逧・ Reset Password / Requires Matching Birth Date 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Reset Password / Requires Matching Birth Date 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Reset Password / Requires Matching Birth Date 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
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
    /// 逶ｮ逧・ Reset Password / Rejects Mismatched Birth Date 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Reset Password / Rejects Mismatched Birth Date 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
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
