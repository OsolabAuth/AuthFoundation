using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class TotpUtilTests
{
    /// <summary>
    /// 逶ｮ逧・ Generate Secret / Returns Base32 Secret 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Generate Secret / Returns Base32 Secret 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Generate Secret / Returns Base32 Secret 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void GenerateSecret_ReturnsBase32Secret()
    {
        string secret = TotpUtil.GenerateSecret(1);

        Assert.IsFalse(string.IsNullOrWhiteSpace(secret));
    }

    /// <summary>
    /// 逶ｮ逧・ Verify Code / Returns False For Wrong Code 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 豁｣縺励＞荳ｻ菴薙↓邏舌▼縺九↑縺・・ｽ・ｽ縺｣縺溯ｪ崎ｨｼ諠・・ｽ・ｽ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Verify Code / Returns False For Wrong Code 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void VerifyCode_ReturnsFalseForWrongCode()
    {
        string secret = TotpUtil.GenerateSecret();

        Assert.IsFalse(TotpUtil.VerifyCode(secret, "000000", DateTimeOffset.UtcNow));
    }

    /// <summary>
    /// 逶ｮ逧・ Generate Code / Rejects Invalid Secret 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void GenerateCode_RejectsInvalidSecret()
    {
        Assert.ThrowsExactly<ApiException>(() => TotpUtil.GenerateCode("invalid!", DateTimeOffset.UtcNow));
    }
}
