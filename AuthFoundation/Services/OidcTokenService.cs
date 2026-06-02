using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthFoundation.Common;

namespace AuthFoundation.Services;

public sealed class OidcTokenService
{
    private readonly IOidcStore _store;
    private readonly SigningKeyProvider _signingKey;

    public OidcTokenService(IOidcStore store, SigningKeyProvider signingKey)
    {
        _store = store;
        _signingKey = signingKey;
    }

    public TokenResponse CreateTokenResponse(AuthorizationCodeRecord code)
    {
        AccessTokenRecord accessToken = _store.CreateAccessToken(code);
        string idToken = CreateIdToken(code);
        return new TokenResponse(accessToken.AccessToken, idToken, "Bearer", 900, code.Scope);
    }

    public AgentTokenResponse CreateAgentTokenResponse(AgentRecord agent, AgentDelegationRecord delegation, string scope)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AccessTokenRecord accessToken = _store.CreateAgentAccessToken(agent, delegation, scope);
        var payload = new Dictionary<string, object>
        {
            ["iss"] = AppConfig.Issuer.TrimEnd('/'),
            ["sub"] = agent.AgentId,
            ["aud"] = delegation.ClientId,
            ["exp"] = now.AddMinutes(15).ToUnixTimeSeconds(),
            ["iat"] = now.ToUnixTimeSeconds(),
            ["principal_type"] = "ai_agent",
            ["agent_id"] = agent.AgentId,
            ["agent_name"] = agent.AgentName,
            ["owner_sub"] = agent.OwnerSubject,
            ["delegation_id"] = delegation.DelegationId,
            ["scope"] = scope,
            ["amr"] = new[] { "agent_secret" },
            ["acr"] = "urn:osolab:acr:agent-delegated"
        };

        return new AgentTokenResponse(
            accessToken.AccessToken,
            CreateSignedJwt(payload),
            "Bearer",
            900,
            scope);
    }

    public object CreateJwksResponse()
    {
        RSAParameters parameters = _signingKey.ExportPublicParameters();
        return new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = _signingKey.KeyId,
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
            kid = _signingKey.KeyId
        });
        string payloadJson = JsonSerializer.Serialize(payload);
        string header = PkceUtil.Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        string body = PkceUtil.Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        string signingInput = $"{header}.{body}";
        byte[] signature = _signingKey.SignData(Encoding.UTF8.GetBytes(signingInput));
        return $"{signingInput}.{PkceUtil.Base64UrlEncode(signature)}";
    }
}

public sealed record TokenResponse(
    string access_token,
    string id_token,
    string token_type,
    int expires_in,
    string scope);

public sealed record AgentTokenResponse(
    string access_token,
    string id_token,
    string token_type,
    int expires_in,
    string scope);
