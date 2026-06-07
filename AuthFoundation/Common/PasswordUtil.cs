using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace AuthFoundation.Common;

public static class PasswordUtil
{
    private const int SaltBytes = 16;
    private const int HashBytes = 32;
    private const int Argon2Version = 19;
    private const int Argon2MemoryKiB = 65_536;
    private const int Argon2Iterations = 3;
    private const int Argon2Parallelism = 1;
    private const int LegacyPbkdf2Iterations = 100_000;

    /// <summary>
    /// Hashes a password with Argon2id.
    /// </summary>
    public static string Hash(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(SaltBytes);
        byte[] hash = HashArgon2id(password, salt, Argon2MemoryKiB, Argon2Iterations, Argon2Parallelism, HashBytes);
        return string.Join(
            '$',
            string.Empty,
            "argon2id",
            $"v={Argon2Version}",
            $"m={Argon2MemoryKiB},t={Argon2Iterations},p={Argon2Parallelism}",
            PkceUtil.Base64UrlEncode(salt),
            PkceUtil.Base64UrlEncode(hash));
    }

    /// <summary>
    /// Verifies an Argon2id hash, or a legacy PBKDF2 hash kept only for migration.
    /// </summary>
    public static bool Verify(string password, string storedHash)
    {
        if (storedHash.StartsWith("$argon2id$", StringComparison.Ordinal))
        {
            return VerifyArgon2id(password, storedHash);
        }

        return VerifyLegacyPbkdf2(password, storedHash);
    }

    /// <summary>
    /// Returns whether the stored hash should be upgraded to the current format.
    /// </summary>
    public static bool NeedsRehash(string storedHash)
    {
        try
        {
            if (!TryReadArgon2id(storedHash, out Argon2idHashData hashData))
            {
                return true;
            }

            return hashData.MemoryKiB != Argon2MemoryKiB
                || hashData.Iterations != Argon2Iterations
                || hashData.Parallelism != Argon2Parallelism
                || hashData.Hash.Length != HashBytes;
        }
        catch (FormatException)
        {
            return true;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private static bool VerifyArgon2id(string password, string storedHash)
    {
        try
        {
            if (!TryReadArgon2id(storedHash, out Argon2idHashData hashData))
            {
                return false;
            }

            byte[] actual = HashArgon2id(
                password,
                hashData.Salt,
                hashData.MemoryKiB,
                hashData.Iterations,
                hashData.Parallelism,
                hashData.Hash.Length);
            return CryptographicOperations.FixedTimeEquals(actual, hashData.Hash);
        }
        catch (FormatException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool TryReadArgon2id(string storedHash, out Argon2idHashData hashData)
    {
        hashData = default;
        string[] parts = storedHash.Split('$');
        if (parts.Length != 6
            || parts[1] != "argon2id"
            || parts[2] != $"v={Argon2Version}")
        {
            return false;
        }

        (int memoryKiB, int iterations, int parallelism) = ParseArgon2Parameters(parts[3]);
        hashData = new Argon2idHashData(
            memoryKiB,
            iterations,
            parallelism,
            Base64UrlDecode(parts[4]),
            Base64UrlDecode(parts[5]));
        return true;
    }

    private static bool VerifyLegacyPbkdf2(string password, string storedHash)
    {
        try
        {
            string[] parts = storedHash.Split('.');
            if (parts.Length != 3
                || !int.TryParse(parts[0], out int iterations)
                || iterations != LegacyPbkdf2Iterations)
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
        catch (FormatException)
        {
            return false;
        }
    }

    private static byte[] HashArgon2id(
        string password,
        byte[] salt,
        int memoryKiB,
        int iterations,
        int parallelism,
        int outputBytes)
    {
        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = iterations,
            DegreeOfParallelism = parallelism
        };
        return argon2.GetBytes(outputBytes);
    }

    private static (int memoryKiB, int iterations, int parallelism) ParseArgon2Parameters(string value)
    {
        Dictionary<string, int> parsed = value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(parameter => parameter.Split('=', 2))
            .Where(pair => pair.Length == 2 && int.TryParse(pair[1], out _))
            .ToDictionary(pair => pair[0], pair => int.Parse(pair[1]), StringComparer.Ordinal);

        if (!parsed.TryGetValue("m", out int memoryKiB)
            || !parsed.TryGetValue("t", out int iterations)
            || !parsed.TryGetValue("p", out int parallelism))
        {
            throw new FormatException("argon2 parameters are incomplete");
        }

        return (memoryKiB, iterations, parallelism);
    }

    private static byte[] Base64UrlDecode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        int padding = padded.Length % 4;
        if (padding > 0)
        {
            padded = padded.PadRight(padded.Length + 4 - padding, '=');
        }

        return Convert.FromBase64String(padded);
    }

    private readonly record struct Argon2idHashData(
        int MemoryKiB,
        int Iterations,
        int Parallelism,
        byte[] Salt,
        byte[] Hash);
}
