using System.Security.Cryptography;
using System.Text;

namespace AuthFoundation.Common
{
    public static class AgentSecretHasher
    {
        public static string ComputeHash(string secret)
        {
            byte[] key = Encoding.UTF8.GetBytes(AppConfig.PasswordHashKey);
            byte[] value = Encoding.UTF8.GetBytes(secret);
            return Convert.ToHexString(HMACSHA256.HashData(key, value));
        }

        public static bool Verify(string secret, string expectedHash)
        {
            string actualHash = ComputeHash(secret);
            return Helper.IsSameValue(expectedHash, actualHash);
        }
    }
}
