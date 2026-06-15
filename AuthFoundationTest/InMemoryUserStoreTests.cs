using AuthFoundation.Common;
using AuthFoundation.Services;

namespace AuthFoundationTest;

[TestClass]
public sealed class InMemoryUserStoreTests
{
    /// <summary>
    /// 逶ｮ逧・ Authenticate / Returns Created User 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Authenticate / Returns Created User 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Authenticate / Returns Created User 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
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
    /// 逶ｮ逧・ Authenticate / Rejects Wrong Password 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Authenticate_RejectsWrongPassword()
    {
        var users = new InMemoryUserStore();
        users.CreateUser("reject@example.com", "Passw0rd!", "Reject User", new DateOnly(2000, 1, 1));

        Assert.ThrowsExactly<ApiException>(() => users.Authenticate("reject@example.com", "WrongPassw0rd!"));
    }

    /// <summary>
    /// 逶ｮ逧・ Authenticate / Rejects Unknown Email 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void Authenticate_RejectsUnknownEmail()
    {
        var users = new InMemoryUserStore();

        Assert.ThrowsExactly<ApiException>(() => users.Authenticate("missing@example.com", "Passw0rd!"));
    }

    /// <summary>
    /// 逶ｮ逧・ Create User / Rejects Duplicate Email 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Create User / Rejects Duplicate Email 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
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
    /// 逶ｮ逧・ Find By Email / Rejects Unknown Email 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 蟄伜惠縺励↑縺ИD繧・・ｽ・ｽ繝ｼ繝ｫ繧｢繝峨Ξ繧ｹ縺ｪ縺ｩ縲∵悴遏･縺ｮ蟇ｾ雎｡繧定｡ｨ縺吝､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void FindByEmail_RejectsUnknownEmail()
    {
        var users = new InMemoryUserStore();

        Assert.ThrowsExactly<ApiException>(() => users.FindByEmail("missing@example.com"));
    }
}
