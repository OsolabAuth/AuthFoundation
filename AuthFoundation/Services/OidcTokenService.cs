using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class OidcTokenService
{
    private readonly RSA _rsa = RSA.Create(2048);
    private readonly string _kid = Helper.GenerateHex(16);
    private readonly InMemoryOidcStore _store;

    public OidcTokenService(InMemoryOidcStore store)
    {
        _store = store;
    }

    public TokenResponse CreateTokenResponse(AuthorizationCodeRecord code)
    {
        AccessTokenRecord accessToken = _store.CreateAccessToken(code);
        string idToken = CreateIdToken(code);
        return new TokenResponse(accessToken.AccessToken, idToken, "Bearer", 900, code.Scope);
    }

    public object CreateJwksResponse()
    {
        RSAParameters parameters = _rsa.ExportParameters(false);
        return new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = _kid,
                    alg = "RS256",
                    n = PkceUtil.Base64UrlEncode(parameters.Modulus!),
                    e = PkceUtil.Base64UrlEncode(parameters.Exponent!)
                }
            }
        };
    }

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
