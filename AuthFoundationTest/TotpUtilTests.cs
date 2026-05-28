using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class TotpUtilTests
{
    [TestMethod]
    public void GenerateSecret_ReturnsBase32Secret()
    {
        string secret = TotpUtil.GenerateSecret(1);

        Assert.IsFalse(string.IsNullOrWhiteSpace(secret));
    }

    [TestMethod]
    public void VerifyCode_ReturnsFalseForWrongCode()
    {
        string secret = TotpUtil.GenerateSecret();

        Assert.IsFalse(TotpUtil.VerifyCode(secret, "000000", DateTimeOffset.UtcNow));
    }

    [TestMethod]
    public void GenerateCode_RejectsInvalidSecret()
    {
        Assert.ThrowsExactly<ApiException>(() => TotpUtil.GenerateCode("invalid!", DateTimeOffset.UtcNow));
    }
}
