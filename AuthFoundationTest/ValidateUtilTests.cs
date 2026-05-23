using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class ValidateUtilTests
{
    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Email Param を Valid Email 条件で実行
    /// 期待値
    /// 　Does Not Throw を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void EmailParam_ValidEmail_DoesNotThrow()
    {
        ValidateUtil.EmailParam("user.name+tag@example.com", "email");
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Email Param を Invalid Email 条件で実行
    /// 期待値
    /// 　Throws Request Parameter Error を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void EmailParam_InvalidEmail_ThrowsRequestParameterError()
    {
        ApiException ex = Assert.ThrowsExactly<ApiException>(() =>
            ValidateUtil.EmailParam("user@@example.com", "email"));

        Assert.AreEqual(Code.REQUEST_PARAMETER_ERROR.Code, ex.Code);
    }

    /// <summary>
    /// 前提条件
    /// 　DB：テストデータを事前投入済み
    /// 　リクエスト：Email Param を Trimmed Email 条件で実行
    /// 期待値
    /// 　Does Not Throw を満たすレスポンス/動作になる
    /// </summary>
    /// <returns></returns>
    [TestMethod]
    public void EmailParam_TrimmedEmail_DoesNotThrow()
    {
        ValidateUtil.EmailParam("  user@example.com  ", "email");
    }
}
