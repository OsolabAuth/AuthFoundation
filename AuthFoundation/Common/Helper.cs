using AuthFoundation.Data;
using AuthFoundation.Models;
using AuthFoundation.Session;
using Azure.Core;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR.Protocol;
using Newtonsoft.Json;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace AuthFoundation.Common
{
    // ヘルパーメソッドをここに実装
    public static class Helper
    {
        public static IResult CreateOKResponse()
        {
            IResult response = Results.Ok();

            return response;
        }

        /// <summary>
        /// クライアント検証
        /// </summary>
        /// <param name="dbContex">DBコンテキスト</param>
        /// <param name="clientId">クライアントID</param>
        /// <returns>クライアント</returns>
        /// <exception cref="ApiException"></exception>
        public static client_master CertClient(OsolabAuthContext dbContex, string clientId)
        {
            client_master? client = dbContex.client_masters.SingleOrDefault(
                x => x.client_id == clientId && x.status == Code.Status.ACTIVE);

            if (client == null)
            {
                throw new ApiException(Common.Code.ILLEGAL_CLIENT, Common.Code.ILLEGAL_CLIENT.ErrorMessage);
            }
            else
            {
                return client;
            }
        }

        /// <summary>
        /// メールアドレス使用中確認
        /// </summary>
        /// <param name="dbContex">DBコンテキスト</param>
        /// <param name="emailAddress">メールアドレス</param>
        public static void CertEmail(OsolabAuthContext dbContex, string emailAddress)
        {
            osolab_user? user = dbContex.osolab_users
                .SingleOrDefault(x => x.email == emailAddress && x.status == Code.Status.ACTIVE);

            if (user != null)
            {
                throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, "別のe-mailアドレスを利用してください");
            }

        }

        /// <summary>
        /// Content-Typeチェック（application/json）
        /// </summary>
        /// <param name="type">ContentType</param>
        public static void ValidateTypeApplicationJson(string? type)
        {
            if (!string.IsNullOrEmpty(type))
            {
                // application/json
                string[] types = type.Split(";");
                if (types[0] == Code.Content.TYPE_JSON)
                {
                    return;
                }
            }
            throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, "Content-Typeが不正です");
        }

        public static class ValidateUtil
        {
            /// <summary>
            /// 必須チェック
            /// </summary>
            /// <param name="argValue">チェックする値</param>
            /// <param name="argMessage">メッセージに指定する値</param>
            public static void IndispensableParam(string argValue, string argMessage)
            {
                if (string.IsNullOrEmpty(argValue))
                {
                    throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, $"{argMessage}が指定されていません");
                }
            }

            /// <summary>
            /// Patternチェック
            /// </summary>
            /// <param name="argValue">チェックする値</param>
            /// <param name="argMessage">メッセージに指定する値</param>
            /// <param name="pattern">チェックするパターン</param>
            /// <param name="nullOrEnptyPermission">nullと空文字を許可するフラグ(true:nullと空文字を許可、false:nullと空文字を不許可)</param>
            public static void FormatParam(string argValue, string argMessage, string pattern, bool nullOrEnptyPermission = false)
            {
                if (nullOrEnptyPermission == true && string.IsNullOrEmpty(argValue))
                {
                    return;
                }
                if (!Regex.IsMatch(argValue, pattern))
                {
                    throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, $"{argMessage}に使用できない文字が含まれています");
                }
            }
        }

        /// <summary>
        /// 指定された文字列argUseCharactersで長さlengthの文字列を生成して返す
        /// </summary>
        /// <param name="argLength">生成する文字列の長さ</param>
        /// <param name="argUseCharacters">使用する文字</param>
        /// <returns></returns>
        public static string GenerateRandomCode(int argLength, string argUseCharacters)
        {
            byte[] bs = new byte[argLength];

            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            StringBuilder sb = new StringBuilder();
            rng.GetBytes(bs);
            foreach (byte b in bs)
            {
                sb.Append(argUseCharacters[b % argUseCharacters.Length]);
            }
            return sb.ToString();
        }

        /// <summary>
        /// 任意の長さのhex文字列を生成
        /// </summary>
        /// <param name="length"></param>
        /// <returns></returns>
        public static string GenerateHex(int length)
        {
            Span<byte> bytes = stackalloc byte[length];
            RandomNumberGenerator.Fill(bytes);

            return Convert.ToHexString(bytes)[0..length];
        }

        /// <summary>
        /// ハッシュ化パスワードを取得
        /// </summary>
        /// <param name="password">パスワード</param>
        /// <param name="nonce">ノンス</param>
        /// <returns></returns>
        public static string GetPassHash(string password, string nonce)
        {
            string passNonce = password + nonce;
            byte[] passNonceByte = Encoding.UTF8.GetBytes(passNonce);
            string key = AppConfig.PasswordHashKey;
            byte[] keyByte = Encoding.UTF8.GetBytes(key);
            byte[] hashPass = HMACSHA256.HashData(keyByte, passNonceByte);
            return BitConverter.ToString(hashPass).Replace("-", String.Empty); ;
        }

        public static async Task<bool> LoginCertificationAsync(RedisClient redis, HttpRequest request)
        {
            request.Cookies["session_id"]

        }

        public static async Task<AuthSession?> TryGetLoginSessionAsync(RedisClient redis, string? sessionId)
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
    }
}
