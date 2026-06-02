using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class TotpUtilTests
{
    /// <summary>
    /// 目的: Generate Secret / Returns Base32 Secret の仕様を検証する。
    /// 入力値: Generate Secret / Returns Base32 Secret を確認するためにテスト内で作成したデータ。
    /// 期待値: Generate Secret / Returns Base32 Secret の期待結果になること。
    /// </summary>
    [TestMethod]
    public void GenerateSecret_ReturnsBase32Secret()
    {
        string secret = TotpUtil.GenerateSecret(1);

        Assert.IsFalse(string.IsNullOrWhiteSpace(secret));
    }

    /// <summary>
    /// 目的: Verify Code / Returns False For Wrong Code の仕様を検証する。
    /// 入力値: 正しい主体に紐づかない誤った認証情報。
    /// 期待値: Verify Code / Returns False For Wrong Code の期待結果になること。
    /// </summary>
    [TestMethod]
    public void VerifyCode_ReturnsFalseForWrongCode()
    {
        string secret = TotpUtil.GenerateSecret();

        Assert.IsFalse(TotpUtil.VerifyCode(secret, "000000", DateTimeOffset.UtcNow));
    }

    /// <summary>
    /// 目的: Generate Code / Rejects Invalid Secret の仕様を検証する。
    /// 入力値: フォーマット不正または権限外の入力値。
    /// 期待値: 不正または期限切れの入力を拒否すること。
    /// </summary>
    [TestMethod]
    public void GenerateCode_RejectsInvalidSecret()
    {
        Assert.ThrowsExactly<ApiException>(() => TotpUtil.GenerateCode("invalid!", DateTimeOffset.UtcNow));
    }
}
