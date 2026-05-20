using AuthFoundation.Data;
using AuthFoundation.Models;
using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthFoundation.Common
{
    /// <summary>
    /// 共通ヘルパーを提供します。
    /// </summary>
    public static class Helper
    {
        /// <summary>
        /// クライアント検証
        /// </summary>
        /// <param name="dbContext">DBコンテキスト</param>
        /// <param name="clientId">クライアントID</param>
        /// <returns>クライアント情報</returns>
        /// <exception cref="ApiException">00002:クライアントが不正</exception>
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
        /// Content-Type が JSON であることを検証します。
        /// </summary>
        /// <param name="type">Content-Type</param>
        /// <exception cref="ApiException">00001:リクエストパラメータエラー</exception>
        public static void ValidateTypeApplicationJson(string? type)
        {
            if (HasContentType(type, Code.Content.TYPE_JSON))
            {
                return;
            }

            throw new ApiException(Code.REQUEST_PARAMETER_ERROR, Code.REQUEST_PARAMETER_ERROR.ErrorMessage);
        }

        /// <summary>
        /// Content-Type が form-urlencoded であることを検証します。
        /// </summary>
        /// <param name="type">Content-Type</param>
        /// <exception cref="ApiException">00001:リクエストパラメータエラー</exception>
        public static void ValidateTypeFormUrlEncoded(string? type)
        {
            if (HasContentType(type, Code.Content.TYPE_X_WWW_FORM))
            {
                return;
            }

            throw new ApiException(Code.REQUEST_PARAMETER_ERROR, Code.REQUEST_PARAMETER_ERROR.ErrorMessage);
        }

        /// <summary>
        /// Content-Type を比較します。
        /// </summary>
        /// <param name="contentType">Content-Type</param>
        /// <param name="expected">期待値</param>
        /// <returns>一致する場合は true</returns>
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
        /// ランダム文字列を生成します。
        /// </summary>
        /// <param name="length">文字数</param>
        /// <param name="useCharacters">使用文字</param>
        /// <returns>ランダム文字列</returns>
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
        /// 16進文字列を生成します。
        /// </summary>
        /// <param name="length">文字数</param>
        /// <returns>16進文字列</returns>
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
        /// パスワードハッシュを計算します。
        /// </summary>
        /// <param name="password">パスワード</param>
        /// <param name="saltString">ソルト</param>
        /// <returns>認証用ハッシュ</returns>
        public static string GetPassHash(string password, string saltString)
        {
            byte[] salt = Encoding.UTF8.GetBytes(saltString);
            using (var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password)))
            {
                argon2.Salt = salt;
                argon2.DegreeOfParallelism = 1;
                argon2.MemorySize = 65536;
                argon2.Iterations = 3;

                byte[] hash = argon2.GetBytes(32);
                return Convert.ToHexString(hash);
            }
        }

        /// <summary>
        /// 文字列を固定時間比較します。
        /// </summary>
        /// <param name="expected">期待値</param>
        /// <param name="actual">比較値</param>
        /// <returns>一致する場合は true</returns>
        public static bool IsSameValue(string expected, string actual)
        {
            byte[] expectedBytes = Encoding.UTF8.GetBytes(expected);
            byte[] actualBytes = Encoding.UTF8.GetBytes(actual);
            return expectedBytes.Length == actualBytes.Length
                && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
        }

        /// <summary>
        /// Scope をリストへ分解します。
        /// </summary>
        /// <param name="scope">Scope 文字列</param>
        /// <returns>Scope リスト</returns>
        public static List<string> ParseScopes(string? scope)
        {
            if (string.IsNullOrWhiteSpace(scope))
            {
                return new List<string>();
            }

            return scope
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .ToList();
        }

        /// <summary>
        /// RedirectUri の形式を検証します。
        /// </summary>
        /// <param name="redirectUri">RedirectUri</param>
        /// <returns>許可された形式の場合は true</returns>
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

            if (!uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return uri.Host.StartsWith("osolab-", StringComparison.OrdinalIgnoreCase)
                && uri.Host.EndsWith("-local", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// RedirectUri を組み立てます。
        /// </summary>
        /// <param name="baseUri">ベース URI</param>
        /// <param name="parameters">クエリパラメータ</param>
        /// <returns>組み立てた URI</returns>
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

        /// <summary>
        /// 認証メール送信
        /// </summary>
        /// <param name="mailaddress">メールアドレス</param>
        /// <returns></returns>
        public static async Task<string> SendMailAsync(BrevoMail brevo, string mailaddress)
        {
            // ダミーアドレス
            if (Regex.IsMatch(mailaddress, Code.HttpBodies.DUMMY_EMAIL.Regex))
            {
                return "00000";
            }

            // 認証コード生成
            string code = Helper.GenerateRandomCode(5, "0123456789");

            string subject = "メール認証コード";

            string html = $@"
<html>
<body>
    <p>サインアップ認証コードをお送りします。</p>

    <p style='font-size:24px;font-weight:bold;letter-spacing:4px;'>
        {code}
    </p>

    <p>このコードを画面へ入力してください。</p>

    <hr />

    <p style='color:#888;font-size:12px;'>
        このメールに心当たりがない場合は破棄してください。
    </p>
</body>
</html>";

            await brevo.SendMailAsync(mailaddress, string.Empty, subject, html);

            return code;
        }

    }
}
