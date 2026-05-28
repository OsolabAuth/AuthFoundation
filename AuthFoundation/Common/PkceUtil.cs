using System.Security.Cryptography;
using System.Text;

namespace AuthFoundation.Common;

public static class PkceUtil
{
    /// <summary>
    /// PKCE S256のcode_challengeがcode_verifierと対応しているか確認する。
    /// </summary>
    /// <param name="codeVerifier">PKCE code_verifier。</param>
    /// <param name="codeChallenge">検証対象のS256 code_challenge。</param>
    /// <returns>PKCE検証に成功した場合はtrue。</returns>
    public static bool VerifyS256(string codeVerifier, string codeChallenge)
    {
        return string.Equals(CreateS256Challenge(codeVerifier), codeChallenge, StringComparison.Ordinal);
    }

    /// <summary>
    /// PKCE code_verifierからS256 code_challengeを生成する。
    /// </summary>
    /// <param name="codeVerifier">PKCE code_verifier。</param>
    /// <returns>S256 code_challenge。</returns>
    public static string CreateS256Challenge(string codeVerifier)
    {
        byte[] hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncode(hash);
    }

    /// <summary>
    /// バイト配列をBase64URL形式の文字列に変換する。
    /// </summary>
    /// <param name="value">エンコード対象のバイト配列。</param>
    /// <returns>Base64URLエンコード済み文字列。</returns>
    public static string Base64UrlEncode(byte[] value)
    {
        return Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
