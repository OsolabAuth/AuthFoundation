using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Session;
using Newtonsoft.Json;

namespace AuthFoundation.Common
{
    /// <summary>
    /// OidcSigningService class.
    /// </summary>
    public sealed class OidcSigningService
    {
        private readonly RSA _rsa;

        /// <summary>
        /// Gets or sets KeyId.
        /// </summary>
        public string KeyId { get; }

        /// <summary>
        /// Initializes a new instance of OidcSigningService.
        /// </summary>
        public OidcSigningService()
        {
            _rsa = RSA.Create(2048);
            RSAParameters publicParams = _rsa.ExportParameters(false);
            byte[] kidMaterial = SHA256.HashData(publicParams.Modulus!.Concat(publicParams.Exponent!).ToArray());
            KeyId = Base64UrlEncode(kidMaterial[..12]);
        }

        /// <summary>
        /// Executes CreateIdToken.
        /// </summary>
        public string CreateIdToken(AuthCodeSession session, IEnumerable<string> scopes)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset expires = now.AddSeconds(AppConfig.IdTokenExpireSec);

            var payload = new Dictionary<string, object>
            {
                ["iss"] = AppConfig.Issuer.TrimEnd('/'),
                ["sub"] = session.OsolabId,
                ["aud"] = session.ClientId,
                ["exp"] = expires.ToUnixTimeSeconds(),
                ["iat"] = now.ToUnixTimeSeconds(),
                ["nonce"] = session.Nonce,
                ["jti"] = Helper.GenerateHex(32).ToLowerInvariant()
            };

            HashSet<string> scopeSet = scopes.ToHashSet(StringComparer.Ordinal);
            if (scopeSet.Contains(Code.Scope.EMAIL))
            {
                payload["email"] = session.Email;
            }

            string headerJson = JsonConvert.SerializeObject(new
            {
                alg = "RS256",
                typ = "JWT",
                kid = KeyId
            });

            string payloadJson = JsonConvert.SerializeObject(payload);
            string headerB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
            string payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
            string signingInput = $"{headerB64}.{payloadB64}";

            byte[] signature = _rsa.SignData(
                Encoding.UTF8.GetBytes(signingInput),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            return $"{signingInput}.{Base64UrlEncode(signature)}";
        }

        /// <summary>
        /// Executes CreateJwks.
        /// </summary>
        public object CreateJwks()
        {
            RSAParameters publicParams = _rsa.ExportParameters(false);
            return new
            {
                keys = new[]
                {
                    new
                    {
                        kid = KeyId,
                        kty = "RSA",
                        alg = "RS256",
                        use = "sig",
                        n = Base64UrlEncode(publicParams.Modulus!),
                        e = Base64UrlEncode(publicParams.Exponent!)
                    }
                }
            };
        }

        /// <summary>
        /// Executes Base64UrlEncode.
        /// </summary>
        private static string Base64UrlEncode(byte[] value)
        {
            return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
