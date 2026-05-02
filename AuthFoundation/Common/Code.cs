using System.Net;
using System.Security.Cryptography.Pkcs;

namespace AuthFoundation.Common
{
    public static class Code
    {
        public static readonly ApiException SUCCESS = new ApiException("00000", HttpStatusCode.OK, "OK" );
        public static readonly ApiException REQUEST_PARAMETER_ERROR = new ApiException("00001", HttpStatusCode.BadRequest, "リクエストの内容が異常です");
        public static readonly ApiException ILLEGAL_CLIENT = new ApiException("00002", HttpStatusCode.BadRequest, "不正なクライアント");
        public static readonly ApiException AUTHENTICATION_FAILED = new ApiException("00003", HttpStatusCode.Unauthorized, "認証に失敗しました");

        public static readonly ApiException INTERNAL_SERVER_ERROR = new ApiException("90000", HttpStatusCode.InternalServerError, "ハンドルされていないエラーが発生しました");
        public static readonly ApiException ID_GENERATION_ERORR = new ApiException("90001", HttpStatusCode.InternalServerError, "ID生成に失敗しました");

        public class RequestValidation
        {
            public string Key { get; set; }
            public string Regex { get; set; }
            public RequestValidation(string key, string regex)
            {
                Key = key;
                Regex = regex;
            }
        }
        public static class HttpHeaders
        {
            public static readonly RequestValidation X_AUTH_CLIENT_ID = new RequestValidation("x-auth-clientid", @"^[0-9]{32}$");
            public static readonly RequestValidation X_FLOW_TYPE = new RequestValidation("x-flow-type", @"^AuthorizationCode$");
            public static readonly RequestValidation X_SESSION_ID = new RequestValidation("x-session-id", @"^[0-9a-zA-Z]{32}$");

        }

        public static class HttpQueries
        {
            public static readonly RequestValidation RESPONSE_TYPE = new RequestValidation("response_type", @"^code$");
            public static readonly RequestValidation CODE_CHALLENGE_METHOD = new RequestValidation("code_challenge_method", @"^S256$");
            public static readonly RequestValidation CODE_CHALLENGE = new RequestValidation("code_challenge", @"^[A-Za-z0-9_-]{43,128}$");
            public static readonly RequestValidation STATUS = new RequestValidation("status", @".*");
        }
        public static class HttpBodies
        {
            public static readonly RequestValidation EMAIL = new RequestValidation("email", @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
            public static readonly RequestValidation PASSWORD = new RequestValidation("password",@"^[0-9a-zA-Z]{64}$");
            public static readonly RequestValidation GRANT_TYPE = new RequestValidation("grant_type", @"^authorization_code$");
            public static readonly RequestValidation CODE_VERIFIER = new RequestValidation("code_verifier", @"^[A-Za-z0-9\-._~]{43,128}$");
            public static readonly RequestValidation AUTH_CODE = new RequestValidation("code", @"^[0-9a-zA-Z]{64}$");
        }

        /// <summary>
        /// ステータス関連定数
        /// </summary>
        public static class Status
        {
            public const byte TENTATIVE = 2;
            public const byte ACTIVE = 1;
            public const byte INACTIVE = 0;
        }

        /// <summary>
        /// 区切り文字関連定数
        /// </summary>
        public static class Delimiter
        {
            public const string UNDERSCORE = "_";
            public const string COMMA = ",";
            public const string COLON = ":";
            public const string HYPHEN = "-";
            public const string EQUAL = "=";
            public const string SEMICOLON = ";";
            public const string DOT = ".";
            public const string SPACE = " ";
            public const string FULL_WIDTH_SPACE = "　";
            public const string OPEN_BRACE = "{";
            public const string CLOSE_BRACE = "}";
            public const string DOUBLE_QUOTATION = "\"";
            public const string OPEN_BOX_BRACKET = "[";
            public const string CLOSE_BOX_BRACKET = "]";
            public const string QUESTION = "?";
            public const string AND = "&";
            public const string NEW_LINE = "\r\n";
            public const string DOLLAR = "$";
            public const string SLASH = "/";
        }

        /// <summary>
        /// ノンス関連定数
        /// </summary>
        public static class Nonce
        {
            public const int LENGTH = 8;
            public const string CHARACTORS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        }

        public static class OsolabId
        {
            public const int LENGTH = 16;
            public const int MAX_RETRY_COUNT = 2;
        }

        /// <summary>
        /// コンテントタイプ関連定数
        /// </summary>
        public static class Content
        {
            public const string TYPE_JSON = "application/json";
            public const string TYPE_X_WWW_FORM = "application/x-www-form-urlencoded";
            public const string TYPE_XML = "application/xml";
            public const string TYPE_OCTET_STREAM = "application/octet-stream";
        }
        /// <summary>
        /// セッション関連定数
        /// </summary>
        public static class Session
        {
            public const int LENGTH = 32;
            public const string CHARACTORS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            public const string TYPE_SMS = "10";
            public const int TIME = 15;
        }

        public static class AuthCode
        {
            public const int LENGTH = 64;
            public const int EXPIRE_SEC = 300;
            public const string CHARACTORS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            public const string REDIS_KEY_PREFIX = "auth_code:";
        }

        public static class AccessToken
        {
            public const int LENGTH = 64;
            public const string CHARACTORS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            public const string REDIS_KEY_PREFIX = "access_token:";
            public const string TOKEN_TYPE_BEARER = "Bearer";
        }

        public static class ResponseType
        {
            public const string CODE = "code";
            public const string CODE_TOKEN = "code token";
            public const string CODE_TOKEN_ID_TOKEN = "code token id_token";
            public const string TOKEN = "token";
        }
    }
}
