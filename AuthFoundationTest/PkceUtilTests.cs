using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class PkceUtilTests
{
    /// <summary>
    /// 逶ｮ逧・ Create S256 Challenge / Returns Known Value 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝・・ｽ・ｽ繝茨ｿｽE縺ｧ逋ｻ骭ｲ縺励◆豁｣蟶ｸ縺ｪ蟇ｾ雎｡繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Create S256 Challenge / Returns Known Value 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void CreateS256Challenge_ReturnsKnownValue()
    {
        string challenge = PkceUtil.CreateS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        Assert.AreEqual("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
    }
}
