using System.Security.Cryptography;
using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordUtilTests
{
    /// <summary>
    /// Argon2idで作成したハッシュが同じパスワードで検証できることを確認する。
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsTrueForMatchingPassword()
    {
        string hash = PasswordUtil.Hash("Passw0rd!");

        Assert.IsTrue(hash.StartsWith("$argon2id$", StringComparison.Ordinal));
        Assert.IsTrue(hash.Length <= 128);
        Assert.IsFalse(PasswordUtil.NeedsRehash(hash));
        Assert.IsTrue(PasswordUtil.Verify("Passw0rd!", hash));
    }

    /// <summary>
    /// Argon2idで作成したハッシュが異なるパスワードを拒否することを確認する。
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsFalseForDifferentPassword()
    {
        string hash = PasswordUtil.Hash("Passw0rd!");

        Assert.IsFalse(PasswordUtil.Verify("WrongPassw0rd!", hash));
    }

    /// <summary>
    /// 不正な形式のハッシュが例外ではなく検証失敗として扱われることを確認する。
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsFalseForMalformedHash()
    {
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "invalid"));
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "iterations.salt.hash"));
    }

    /// <summary>
    /// 旧PBKDF2形式のハッシュを移行用として検証できることを確認する。
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsTrueForLegacyPbkdf2Hash()
    {
        string hash = CreateLegacyPbkdf2Hash("Passw0rd!");

        Assert.IsTrue(PasswordUtil.NeedsRehash(hash));
        Assert.IsTrue(PasswordUtil.Verify("Passw0rd!", hash));
    }

    /// <summary>
    /// 不正なArgon2id形式のハッシュが例外ではなく検証失敗として扱われることを確認する。
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsFalseForMalformedArgon2idHash()
    {
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "$argon2id$v=19$m=65536,t=3$p$hash"));
        Assert.IsTrue(PasswordUtil.NeedsRehash("$argon2id$v=19$m=65536,t=3$p$hash"));
    }

    /// <summary>
    /// 古いArgon2idパラメータのハッシュが再ハッシュ対象になることを確認する。
    /// </summary>
    [TestMethod]
    public void NeedsRehash_ReturnsTrueForOldArgon2idParameters()
    {
        const string hash = "$argon2id$v=19$m=32768,t=2,p=1$ABEiM0RVZneImaq7zN3u_w$ABEiM0RVZneImaq7zN3u_wABEiM0RVZneImaq7zN3u_w";

        Assert.IsTrue(PasswordUtil.NeedsRehash(hash));
    }

    private static string CreateLegacyPbkdf2Hash(string password)
    {
        byte[] salt = Convert.FromHexString("00112233445566778899aabbccddeeff");
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            100_000,
            HashAlgorithmName.SHA256,
            32);
        return $"100000.{Convert.ToHexString(salt).ToLowerInvariant()}.{Convert.ToHexString(hash).ToLowerInvariant()}";
    }
}
