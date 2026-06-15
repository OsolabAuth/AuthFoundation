using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class ValidateUtilTests
{
    /// <summary>
    /// 逶ｮ逧・ Format Param / Accepts Matching Value 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Format Param / Accepts Matching Value 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Format Param / Accepts Matching Value 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void FormatParam_AcceptsMatchingValue()
    {
        ValidateUtil.FormatParam("test@example.com", "email", Code.HttpBodies.EMAIL.Regex);
    }

    /// <summary>
    /// 逶ｮ逧・ Format Param / Rejects Invalid Value 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: 繝輔か繝ｼ繝槭ャ繝井ｸ肴ｭ｣縺ｾ縺滂ｿｽE讓ｩ髯仙､厄ｿｽE蜈･蜉帛､縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void FormatParam_RejectsInvalidValue()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            ValidateUtil.FormatParam("invalid", "email", Code.HttpBodies.EMAIL.Regex));

        Assert.AreEqual("email is invalid", error.ErrorDescription);
    }

    /// <summary>
    /// 逶ｮ逧・ Indispensable Param / Rejects Blank Value 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Indispensable Param / Rejects Blank Value 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: 荳肴ｭ｣縺ｾ縺滂ｿｽE譛滄剞蛻・・ｽ・ｽ縺ｮ蜈･蜉帙ｒ諡貞凄縺吶ｋ縺薙→縲・
    /// </summary>
    [TestMethod]
    public void IndispensableParam_RejectsBlankValue()
    {
        ApiException error = Assert.ThrowsExactly<ApiException>(() =>
            ValidateUtil.IndispensableParam(" ", "email"));

        Assert.AreEqual("email is required", error.ErrorDescription);
    }

    /// <summary>
    /// 逶ｮ逧・ Error Output / Copies Api Exception Fields 縺ｮ莉墓ｧ倥ｒ讀懆ｨｼ縺吶ｋ縲・
    /// 蜈･蜉帛､: Error Output / Copies Api Exception Fields 繧堤｢ｺ隱阪☆繧九◆繧√↓繝・・ｽ・ｽ繝茨ｿｽE縺ｧ菴懶ｿｽE縺励◆繝・・ｽE繧ｿ縲・
    /// 譛溷ｾ・・ｽ・ｽ: Error Output / Copies Api Exception Fields 縺ｮ譛溷ｾ・・ｽ・ｽ譫懊↓縺ｪ繧九％縺ｨ縲・
    /// </summary>
    [TestMethod]
    public void ErrorOutput_CopiesApiExceptionFields()
    {
        var exception = new ApiException("99999", System.Net.HttpStatusCode.Conflict, "conflict", "conflict detail");

        var output = new ErrorOutput(exception);

        Assert.AreEqual("99999", exception.InternalCode);
        Assert.AreEqual(System.Net.HttpStatusCode.Conflict, exception.StatusCode);
        Assert.AreEqual("conflict", exception.Error);
        Assert.AreEqual("conflict detail", exception.ErrorDescription);
        Assert.AreEqual("conflict detail", exception.Message);
        Assert.AreEqual("99999", output.ResponseCode);
        Assert.AreEqual("99999", output.ErrorCode);
        Assert.AreEqual("conflict detail", output.Message);
        Assert.AreEqual("conflict", output.Error);
        Assert.AreEqual("conflict detail", output.ErrorDescription);
    }
}
