using System.Security.Cryptography;
using System.Text;

namespace AuthFoundation.Common;

public static class PkceUtil
{
    public static bool VerifyS256(string codeVerifier, string codeChallenge)
    {
        return string.Equals(CreateS256Challenge(codeVerifier), codeChallenge, StringComparison.Ordinal);
    }

    public static string CreateS256Challenge(string codeVerifier)
    {
        byte[] hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncode(hash);
    }

    public static string Base64UrlEncode(byte[] value)
    {
        return Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
