using System.Security.Cryptography;
using System.Text;

namespace AuthFoundation.Common;

public static class TotpUtil
{
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const int StepSeconds = 30;
    private const int Digits = 6;

    public static string GenerateSecret(int length = 20)
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(length);
        return ToBase32(bytes);
    }

    public static string GenerateCode(string base32Secret, DateTimeOffset now)
    {
        byte[] key = FromBase32(base32Secret);
        long counter = now.ToUnixTimeSeconds() / StepSeconds;
        Span<byte> counterBytes = stackalloc byte[8];
        BitConverter.TryWriteBytes(counterBytes, counter);
        if (BitConverter.IsLittleEndian)
        {
            counterBytes.Reverse();
        }

        byte[] hash = HMACSHA1.HashData(key, counterBytes);
        int offset = hash[^1] & 0x0f;
        int binary =
            ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);
        int code = binary % (int)Math.Pow(10, Digits);
        return code.ToString($"D{Digits}");
    }

    public static bool VerifyCode(string base32Secret, string code, DateTimeOffset now)
    {
        for (int offset = -1; offset <= 1; offset++)
        {
            DateTimeOffset candidate = now.AddSeconds(offset * StepSeconds);
            if (CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(GenerateCode(base32Secret, candidate)),
                    Encoding.ASCII.GetBytes(code)))
            {
                return true;
            }
        }

        return false;
    }

    private static string ToBase32(byte[] bytes)
    {
        var builder = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        foreach (byte value in bytes)
        {
            buffer = (buffer << 8) | value;
            bitsLeft += 8;
            while (bitsLeft >= 5)
            {
                builder.Append(Base32Alphabet[(buffer >> (bitsLeft - 5)) & 31]);
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0)
        {
            builder.Append(Base32Alphabet[(buffer << (5 - bitsLeft)) & 31]);
        }

        return builder.ToString();
    }

    private static byte[] FromBase32(string value)
    {
        string normalized = value.Trim().Replace("=", string.Empty).ToUpperInvariant();
        var bytes = new List<byte>();
        int buffer = 0;
        int bitsLeft = 0;
        foreach (char c in normalized)
        {
            int index = Base32Alphabet.IndexOf(c);
            if (index < 0)
            {
                throw Code.REQUEST_PARAMETER_ERROR;
            }

            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bytes.Add((byte)((buffer >> (bitsLeft - 8)) & 0xff));
                bitsLeft -= 8;
            }
        }

        return bytes.ToArray();
    }
}
