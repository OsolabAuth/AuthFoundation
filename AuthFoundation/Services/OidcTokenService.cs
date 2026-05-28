using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class OidcTokenService
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly string _kid = Helper.GenerateHex(16);

    /// <summary>
    /// 認可コード情報からtoken endpointの応答を生成する。
    /// </summary>
    /// <param name="code">検証済み認可コードレコード。</param>
    /// <returns>OIDC token endpointの応答。</returns>
    public TokenResponse CreateTokenResponse(AuthorizationCodeRecord code)
    {
        string accessToken = $"dev_{Helper.GenerateHex(48)}";
        string idToken = CreateIdToken(code);
        return new TokenResponse(accessToken, idToken, "Bearer", 900, code.Scope);
    }

    /// <summary>
    /// 認可コード情報からID Token JWTを生成する。
    /// </summary>
    /// <param name="code">ID Token claim生成元の認可コードレコード。</param>
    /// <returns>RS256署名済みID Token。</returns>
    private string CreateIdToken(AuthorizationCodeRecord code)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var payload = new Dictionary<string, object>
        {
            ["iss"] = AppConfig.Issuer.TrimEnd('/'),
            ["sub"] = code.Subject,
            ["aud"] = code.ClientId,
            ["exp"] = now.AddMinutes(15).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["nonce"] = code.Nonce,
            ["email"] = code.Email,
            ["name"] = code.Name
        };

        return CreateSignedJwt(payload);
    }

    /// <summary>
    /// JWT payloadをRS256で署名し、JWT文字列を生成する。
    /// </summary>
    /// <param name="payload">JWT payload claim一覧。</param>
    /// <returns>RS256署名済みJWT。</returns>
    private string CreateSignedJwt(Dictionary<string, object> payload)
    {
        string headerJson = JsonSerializer.Serialize(new
        {
            alg = "RS256",
            typ = "JWT",
            kid = _kid
        });
        string payloadJson = JsonSerializer.Serialize(payload);
        string header = PkceUtil.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        string body = PkceUtil.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        string signingInput = $"{header}.{body}";
        byte[] signature = _rsa.SignData(
            Encoding.UTF8.GetBytes(signingInput),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{PkceUtil.Base64UrlEncode(signature)}";
    }
}

public sealed record TokenResponse(
    string access_token,
    string id_token,
    string token_type,
    int expires_in,
    string scope);
