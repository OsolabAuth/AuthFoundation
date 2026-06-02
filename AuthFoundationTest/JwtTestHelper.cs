using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthFoundation.Services;

namespace AuthFoundationTest;

internal static class JwtTestHelper
{
    public static string ReadHeaderString(string jwt, string propertyName)
    {
        return ReadString(jwt, 0, propertyName);
    }

    public static string ReadPayloadString(string jwt, string propertyName)
    {
        return ReadString(jwt, 1, propertyName);
    }

    public static bool VerifySignature(string jwt, SigningKeyProvider signingKey)
    {
        string[] parts = jwt.Split('.');
        Assert.AreEqual(3, parts.Length);
        using RSA rsa = RSA.Create(signingKey.ExportPublicParameters());
        return rsa.VerifyData(
            Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}"),
            Base64UrlDecode(parts[2]),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
    }

    private static string ReadString(string jwt, int partIndex, string propertyName)
    {
        string[] parts = jwt.Split('.');
        Assert.AreEqual(3, parts.Length);
        using JsonDocument document = JsonDocument.Parse(Base64UrlDecode(parts[partIndex]));
        return document.RootElement.GetProperty(propertyName).GetString()!;
    }

    private static byte[] Base64UrlDecode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
        return Convert.FromBase64String(padded);
    }
}
