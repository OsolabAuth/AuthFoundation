using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordUtilTests
{
    [TestMethod]
    public void Verify_ReturnsTrueForMatchingPassword()
    {
        string hash = PasswordUtil.Hash("Passw0rd!");

        Assert.IsTrue(PasswordUtil.Verify("Passw0rd!", hash));
    }

    [TestMethod]
    public void Verify_ReturnsFalseForDifferentPassword()
    {
        string hash = PasswordUtil.Hash("Passw0rd!");

        Assert.IsFalse(PasswordUtil.Verify("WrongPassw0rd!", hash));
    }

    [TestMethod]
    public void Verify_ReturnsFalseForMalformedHash()
    {
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "invalid"));
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "iterations.salt.hash"));
    }
}
