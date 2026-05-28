using System.Security.Cryptography;

namespace AuthFoundation.Common;

public static class Helper
{
    public static string GenerateHex(int length)
    {
        if (length <= 0)
        {
            throw Code.REQUEST_PARAMETER_ERROR;
        }

        int byteLength = (length + 1) / 2;
        Span<byte> bytes = stackalloc byte[byteLength];
        RandomNumberGenerator.Fill(bytes);

        return Convert.ToHexString(bytes).ToLowerInvariant()[..length];
    }

    public static string[] ParseScopes(string scope)
    {
        return scope
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    public static bool IsJsonContentType(string? contentType)
    {
        return contentType?.StartsWith(Code.Content.TYPE_JSON, StringComparison.OrdinalIgnoreCase) == true;
    }
}
