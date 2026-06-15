using System.Security.Cryptography;
using AuthFoundation.Common;

namespace AuthFoundationTest;

[TestClass]
public sealed class PasswordUtilTests
{
    /// <summary>
    /// Argon2id縺ｧ菴懶ｿｽE縺励◆繝上ャ繧ｷ繝･縺悟酔縺倥ヱ繧ｹ繝ｯ繝ｼ繝峨〒讀懆ｨｼ縺ｧ縺阪ｋ縺薙→繧堤｢ｺ隱阪☆繧九・
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
    /// Argon2id縺ｧ菴懶ｿｽE縺励◆繝上ャ繧ｷ繝･縺檎焚縺ｪ繧九ヱ繧ｹ繝ｯ繝ｼ繝峨ｒ諡貞凄縺吶ｋ縺薙→繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsFalseForDifferentPassword()
    {
        string hash = PasswordUtil.Hash("Passw0rd!");

        Assert.IsFalse(PasswordUtil.Verify("WrongPassw0rd!", hash));
    }

    /// <summary>
    /// 荳肴ｭ｣縺ｪ蠖｢蠑擾ｿｽE繝上ャ繧ｷ繝･縺御ｾ句､悶〒縺ｯ縺ｪ縺乗､懆ｨｼ螟ｱ謨励→縺励※謇ｱ繧上ｌ繧九％縺ｨ繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsFalseForMalformedHash()
    {
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "invalid"));
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "iterations.salt.hash"));
    }

    /// <summary>
    /// 譌ｧPBKDF2蠖｢蠑擾ｿｽE繝上ャ繧ｷ繝･繧堤ｧｻ陦檎畑縺ｨ縺励※讀懆ｨｼ縺ｧ縺阪ｋ縺薙→繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsTrueForLegacyPbkdf2Hash()
    {
        string hash = CreateLegacyPbkdf2Hash("Passw0rd!");

        Assert.IsTrue(PasswordUtil.NeedsRehash(hash));
        Assert.IsTrue(PasswordUtil.Verify("Passw0rd!", hash));
    }

    /// <summary>
    /// 荳肴ｭ｣縺ｪArgon2id蠖｢蠑擾ｿｽE繝上ャ繧ｷ繝･縺御ｾ句､悶〒縺ｯ縺ｪ縺乗､懆ｨｼ螟ｱ謨励→縺励※謇ｱ繧上ｌ繧九％縺ｨ繧堤｢ｺ隱阪☆繧九・
    /// </summary>
    [TestMethod]
    public void Verify_ReturnsFalseForMalformedArgon2idHash()
    {
        Assert.IsFalse(PasswordUtil.Verify("Passw0rd!", "$argon2id$v=19$m=65536,t=3$p$hash"));
        Assert.IsTrue(PasswordUtil.NeedsRehash("$argon2id$v=19$m=65536,t=3$p$hash"));
    }

    /// <summary>
    /// 蜿､縺Бrgon2id繝代Λ繝｡繝ｼ繧ｿ縺ｮ繝上ャ繧ｷ繝･縺鯉ｿｽE繝上ャ繧ｷ繝･蟇ｾ雎｡縺ｫ縺ｪ繧九％縺ｨ繧堤｢ｺ隱阪☆繧九・
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
