using System.Security.Cryptography;

namespace AuthFoundation.Common;

public static class PasswordUtil
{
    private const int SaltBytes = 16;
    private const int HashBytes = 32;
    private const int Iterations = 100_000;

    public static string Hash(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            Iterations,
            HashAlgorithmName.SHA256,
            HashBytes);
        return $"{Iterations}.{Convert.ToHexString(salt).ToLowerInvariant()}.{Convert.ToHexString(hash).ToLowerInvariant()}";
    }

    public static bool Verify(string password, string storedHash)
    {
        string[] parts = storedHash.Split('.');
        if (parts.Length != 3 || !int.TryParse(parts[0], out int iterations))
        {
            return false;
        }

        byte[] salt = Convert.FromHexString(parts[1]);
        byte[] expected = Convert.FromHexString(parts[2]);
        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
