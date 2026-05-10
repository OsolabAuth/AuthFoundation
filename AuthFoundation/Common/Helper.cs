using System.Security.Cryptography;
using System.Text;
using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Newtonsoft.Json;

namespace AuthFoundation.Common
{
    /// <summary>
    /// Helper class.
    /// </summary>
    public static class Helper
    {
        /// <summary>
        /// Executes CertClient.
        /// </summary>
        public static client_master CertClient(OsolabAuthContext dbContext, string clientId)
        {
            client_master? client = dbContext.client_masters.SingleOrDefault(
                x => x.client_id == clientId && x.status == Code.Status.ACTIVE);

            if (client == null)
            {
                throw new ApiException(Code.ILLEGAL_CLIENT, Code.ILLEGAL_CLIENT.ErrorMessage);
            }

            return client;
        }

        /// <summary>
        /// Executes ValidateTypeApplicationJson.
        /// </summary>
        public static void ValidateTypeApplicationJson(string? type)
        {
            if (HasContentType(type, Code.Content.TYPE_JSON))
            {
                return;
            }

            throw new ApiException(Code.REQUEST_PARAMETER_ERROR, Code.REQUEST_PARAMETER_ERROR.ErrorMessage);
        }

        /// <summary>
        /// Executes ValidateTypeFormUrlEncoded.
        /// </summary>
        public static void ValidateTypeFormUrlEncoded(string? type)
        {
            if (HasContentType(type, Code.Content.TYPE_X_WWW_FORM))
            {
                return;
            }

            throw new ApiException(Code.REQUEST_PARAMETER_ERROR, Code.REQUEST_PARAMETER_ERROR.ErrorMessage);
        }

        /// <summary>
        /// Executes HasContentType.
        /// </summary>
        public static bool HasContentType(string? contentType, string expected)
        {
            if (string.IsNullOrWhiteSpace(contentType))
            {
                return false;
            }

            string mediaType = contentType.Split(';', 2)[0].Trim();
            return string.Equals(mediaType, expected, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Executes GenerateRandomCode.
        /// </summary>
        public static string GenerateRandomCode(int length, string useCharacters)
        {
            byte[] bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);

            StringBuilder builder = new StringBuilder(length);
            foreach (byte b in bytes)
            {
                builder.Append(useCharacters[b % useCharacters.Length]);
            }

            return builder.ToString();
        }

        /// <summary>
        /// Executes GenerateHex.
        /// </summary>
        public static string GenerateHex(int length)
        {
            if (length <= 0)
            {
                return string.Empty;
            }

            int byteLength = (length + 1) / 2;
            byte[] bytes = new byte[byteLength];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToHexString(bytes)[..length];
        }

        /// <summary>
        /// Executes GetPassHash.
        /// </summary>
        public static string GetPassHash(string passwordHashHex, string nonce)
        {
            string passNonce = passwordHashHex + nonce;
            byte[] passNonceByte = Encoding.UTF8.GetBytes(passNonce);
            byte[] keyByte = Encoding.UTF8.GetBytes(AppConfig.PasswordHashKey);
            byte[] hashPass = HMACSHA256.HashData(keyByte, passNonceByte);
            return Convert.ToHexString(hashPass);
        }

        /// <summary>
        /// Executes TryGetLoginSessionAsync.
        /// </summary>
        public static async Task<AuthSession?> TryGetLoginSessionAsync(IRedisClient redis, string? sessionId)
        {
            if (string.IsNullOrWhiteSpace(sessionId))
            {
                return null;
            }

            string? raw = await redis.GetStringAsync(AuthSession.GetRedisKey(sessionId));
            if (string.IsNullOrWhiteSpace(raw))
            {
                return null;
            }

            return JsonConvert.DeserializeObject<AuthSession>(raw);
        }

        /// <summary>
        /// Executes ParseScopes.
        /// </summary>
        public static string[] ParseScopes(string? scope)
        {
            if (string.IsNullOrWhiteSpace(scope))
            {
                return Array.Empty<string>();
            }

            return scope
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
        }

        /// <summary>
        /// Executes IsRedirectUriFormatValid.
        /// </summary>
        public static bool IsRedirectUriFormatValid(string redirectUri)
        {
            if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out Uri? uri))
            {
                return false;
            }

            if (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                && uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Executes BuildRedirectUri.
        /// </summary>
        public static string BuildRedirectUri(string baseUri, IDictionary<string, string> parameters)
        {
            string separator = baseUri.Contains('?') ? "&" : "?";
            StringBuilder builder = new StringBuilder(baseUri);
            builder.Append(separator);

            bool first = true;
            foreach ((string key, string value) in parameters)
            {
                if (!first)
                {
                    builder.Append('&');
                }

                builder.Append(Uri.EscapeDataString(key));
                builder.Append('=');
                builder.Append(Uri.EscapeDataString(value));
                first = false;
            }

            return builder.ToString();
        }
    }
}
