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

    public static string GenerateNumericCode(int digits)
    {
        if (digits <= 0 || digits > 9)
        {
            throw Code.REQUEST_PARAMETER_ERROR;
        }

        int maxExclusive = 1;
        for (int index = 0; index < digits; index++)
        {
            maxExclusive *= 10;
        }

        return RandomNumberGenerator.GetInt32(0, maxExclusive).ToString($"D{digits}");
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
