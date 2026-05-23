using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;

namespace AuthFoundation.Common
{
    /// <summary>
    /// OidcSigningService class.
    /// </summary>
    public sealed class OidcSigningService
    {
        private const int RsaKeySize = 2048;
        private const int AesGcmNonceBytes = 12;
        private const int AesGcmTagBytes = 16;

        private readonly IServiceScopeFactory _scopeFactory;
        private readonly SemaphoreSlim _initializeLock = new(1, 1);
        private readonly byte[] _encryptionKey;
        private readonly TimeSpan _reloadInterval;

        private RSA? _rsa;
        private JwkPublicKey[] _jwksKeys = Array.Empty<JwkPublicKey>();
        private DateTimeOffset _lastLoadedUtc = DateTimeOffset.MinValue;

        /// <summary>
        /// Gets KeyId.
        /// </summary>
        public string KeyId { get; private set; } = string.Empty;

        /// <summary>
        /// Initializes a new instance of OidcSigningService.
        /// </summary>
        public OidcSigningService(IServiceScopeFactory scopeFactory)
        {
            _scopeFactory = scopeFactory;
            _encryptionKey = DeriveEncryptionKey(AppConfig.JwkPrivateKeyEncryptionKey);
            _reloadInterval = TimeSpan.FromSeconds(Math.Max(0, AppConfig.JwkSigningKeyReloadSec));
        }

        /// <summary>
        /// Executes CreateIdToken.
        /// </summary>
        public async Task<string> CreateIdTokenAsync(AuthCodeSession session, IEnumerable<string> scopes)
        {
            await EnsureInitializedAsync();
            RSA rsa = _rsa ?? throw new ApiException(Code.INTERNAL_SERVER_ERROR, "signing key initialization failed");

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

            byte[] signature = rsa.SignData(
                Encoding.UTF8.GetBytes(signingInput),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            return $"{signingInput}.{Base64UrlEncode(signature)}";
        }

        /// <summary>
        /// Executes CreateJwks.
        /// </summary>
        public async Task<object> CreateJwksAsync()
        {
            await EnsureInitializedAsync();
            return new
            {
                keys = _jwksKeys.Select(x => new
                {
                    kid = x.Kid,
                    kty = x.Kty,
                    alg = x.Alg,
                    use = x.Use,
                    n = x.N,
                    e = x.E
                }).ToArray()
            };
        }

        /// <summary>
        /// Executes EnsureInitializedAsync.
        /// </summary>
        private async Task EnsureInitializedAsync()
        {
            if (!ShouldReload(DateTimeOffset.UtcNow))
            {
                return;
            }

            await _initializeLock.WaitAsync();
            try
            {
                DateTimeOffset now = DateTimeOffset.UtcNow;
                if (!ShouldReload(now))
                {
                    return;
                }

                using IServiceScope scope = _scopeFactory.CreateScope();
                OsolabAuthContext dbContext = scope.ServiceProvider.GetRequiredService<OsolabAuthContext>();

                List<jwk_master> activeKeys = await dbContext.jwk_masters
                    .AsNoTracking()
                    .Where(x => x.status == Code.Status.ACTIVE)
                    .OrderByDescending(x => x.update_datetime)
                    .ThenByDescending(x => x.sequence_id)
                    .ToListAsync();

                if (activeKeys.Count == 0)
                {
                    jwk_master created = await CreateAndPersistSigningKeyAsync(dbContext);
                    activeKeys.Add(created);
                }

                jwk_master signingKey = activeKeys[0];
                byte[] privateKey = DecryptPrivateKey(signingKey, _encryptionKey);

                RSA rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(privateKey, out _);

                _rsa = rsa;
                KeyId = signingKey.kid;
                _jwksKeys = activeKeys.Select(ToPublicKey).ToArray();
                _lastLoadedUtc = now;
            }
            finally
            {
                _initializeLock.Release();
            }
        }

        private bool ShouldReload(DateTimeOffset now)
        {
            if (_rsa == null)
            {
                return true;
            }

            if (_reloadInterval == TimeSpan.Zero)
            {
                return true;
            }

            return now - _lastLoadedUtc >= _reloadInterval;
        }

        /// <summary>
        /// Executes CreateAndPersistSigningKeyAsync.
        /// </summary>
        private async Task<jwk_master> CreateAndPersistSigningKeyAsync(OsolabAuthContext dbContext)
        {
            using RSA rsa = RSA.Create(RsaKeySize);
            RSAParameters publicParams = rsa.ExportParameters(false);

            string kid = BuildKid(publicParams);
            byte[] privateKey = rsa.ExportPkcs8PrivateKey();
            EncryptionResult encrypted = EncryptPrivateKey(privateKey, _encryptionKey);

            DateTime now = DateTime.UtcNow;
            var keyEntity = new jwk_master
            {
                kid = kid,
                kty = "RSA",
                alg = "RS256",
                key_use = "sig",
                public_n = Base64UrlEncode(publicParams.Modulus!),
                public_e = Base64UrlEncode(publicParams.Exponent!),
                private_key_ciphertext = encrypted.Ciphertext,
                private_key_iv = encrypted.Nonce,
                private_key_tag = encrypted.Tag,
                create_datetime = now,
                update_datetime = now,
                status = Code.Status.ACTIVE
            };

            dbContext.jwk_masters.Add(keyEntity);
            await dbContext.SaveChangesAsync();
            return keyEntity;
        }

        /// <summary>
        /// Executes ToPublicKey.
        /// </summary>
        private static JwkPublicKey ToPublicKey(jwk_master key)
        {
            return new JwkPublicKey(key.kid, key.kty, key.alg, key.key_use, key.public_n, key.public_e);
        }

        /// <summary>
        /// Executes BuildKid.
        /// </summary>
        private static string BuildKid(RSAParameters publicParams)
        {
            byte[] kidMaterial = SHA256.HashData(publicParams.Modulus!.Concat(publicParams.Exponent!).ToArray());
            return Base64UrlEncode(kidMaterial[..12]);
        }

        /// <summary>
        /// Executes DeriveEncryptionKey.
        /// </summary>
        private static byte[] DeriveEncryptionKey(string rawKey)
        {
            string normalized = rawKey.Trim();
            if (normalized.Length < 32)
            {
                throw new ApiException(Code.INTERNAL_SERVER_ERROR, "invalid jwk encryption key configuration");
            }

            return SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        }

        /// <summary>
        /// Executes EncryptPrivateKey.
        /// </summary>
        private static EncryptionResult EncryptPrivateKey(byte[] plaintext, byte[] key)
        {
            byte[] nonce = RandomNumberGenerator.GetBytes(AesGcmNonceBytes);
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[AesGcmTagBytes];

            using var aes = new AesGcm(key, AesGcmTagBytes);
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
            return new EncryptionResult(ciphertext, nonce, tag);
        }

        /// <summary>
        /// Executes DecryptPrivateKey.
        /// </summary>
        private static byte[] DecryptPrivateKey(jwk_master keyEntity, byte[] key)
        {
            byte[] plaintext = new byte[keyEntity.private_key_ciphertext.Length];
            using var aes = new AesGcm(key, AesGcmTagBytes);
            aes.Decrypt(keyEntity.private_key_iv, keyEntity.private_key_ciphertext, keyEntity.private_key_tag, plaintext);
            return plaintext;
        }

        /// <summary>
        /// Executes Base64UrlEncode.
        /// </summary>
        private static string Base64UrlEncode(byte[] value)
        {
            return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private readonly record struct EncryptionResult(byte[] Ciphertext, byte[] Nonce, byte[] Tag);
        private readonly record struct JwkPublicKey(string Kid, string Kty, string Alg, string Use, string N, string E);
    }
}
