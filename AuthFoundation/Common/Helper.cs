using System.Security.Cryptography;

namespace AuthFoundation.Common;

public static class Helper
{
    /// <summary>
    /// 指定された桁数のランダムな16進文字列を生成する。
    /// </summary>
    /// <param name="length">生成する文字列の桁数。</param>
    /// <returns>ランダムな小文字16進文字列。</returns>
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

    /// <summary>
    /// スペース区切りのscope文字列を重複なしの配列に変換する。
    /// </summary>
    /// <param name="scope">スペース区切りのscope文字列。</param>
    /// <returns>正規化済みscope配列。</returns>
    public static string[] ParseScopes(string scope)
    {
        return scope
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// Content-TypeがJSON形式かどうかを判定する。
    /// </summary>
    /// <param name="contentType">判定対象のContent-Typeヘッダー値。</param>
    /// <returns>JSON形式の場合はtrue。</returns>
    public static bool IsJsonContentType(string? contentType)
    {
        return contentType?.StartsWith(Code.Content.TYPE_JSON, StringComparison.OrdinalIgnoreCase) == true;
    }
}
