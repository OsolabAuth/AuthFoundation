using System.Net;

namespace AuthFoundation.Common
{
    /// <summary>
    /// Code class.
    /// </summary>
    public static class Code
    {
        public static readonly ApiException SUCCESS = new("00000", HttpStatusCode.OK, "OK");
        public static readonly ApiException REQUEST_PARAMETER_ERROR = new("00001", HttpStatusCode.BadRequest, "request parameter error");
        public static readonly ApiException ILLEGAL_CLIENT = new("00002", HttpStatusCode.BadRequest, "illegal client");
        public static readonly ApiException SCREEN_EXPIRED = new("00003", HttpStatusCode.BadRequest, "screen expired");
        public static readonly ApiException AUTHENTICATION_FAILED = new("00004", HttpStatusCode.BadRequest, "authentication failed");
        public static readonly ApiException ILLEGAL_REDIRECT_URI = new("00005", HttpStatusCode.BadRequest, "illegal redirect_uri");
        public static readonly ApiException INVALID_AUTH_CODE = new("00007", HttpStatusCode.BadRequest, "invalid auth code");
        public static readonly ApiException UNAUTHORIZED = new("00008", HttpStatusCode.Unauthorized, "unauthorized");
        public static readonly ApiException INVALID_SCOPE = new("00009", HttpStatusCode.BadRequest, "invalid scope");

        public static readonly ApiException INTERNAL_SERVER_ERROR = new("90000", HttpStatusCode.InternalServerError, "Unhandled server error");
        public static readonly ApiException ID_GENERATION_ERROR = new("90001", HttpStatusCode.InternalServerError, "ID generation failed");

        public const string AUTH_SESSION_COOKIE_KEY = "AuthSessionId";
        public const string AUTH_REQUEST_SESSION_COOKIE_KEY = "AuthRequestSessionId";

        /// <summary>
        /// RequestValidation class.
        /// </summary>
        public sealed class RequestValidation
        {
            /// <summary>
            /// Gets or sets Key.
            /// </summary>
            public string Key { get; }

            /// <summary>
            /// Gets or sets Regex.
            /// </summary>
            public string Regex { get; }

            /// <summary>
            /// Initializes a new instance of RequestValidation.
            /// </summary>
            public RequestValidation(string key, string regex)
            {
                Key = key;
                Regex = regex;
            }
        }

        /// <summary>
        /// HttpHeaders class.
        /// </summary>
        public static class HttpHeaders
        {
            public static readonly RequestValidation X_AUTH_CLIENT_ID = new("x-auth-clientid", @"^[0-9]{32}$");
            public static readonly RequestValidation X_FLOW_TYPE = new("x-flow-type", @"^AuthorizationCode$");
            public static readonly RequestValidation X_SESSION_ID = new("x-session-id", @"^[A-Fa-f0-9]{32}$");
            public static readonly RequestValidation AUTHORIZATION_BEARER = new("Authorization", @"^Bearer [A-Fa-f0-9]{16}_[A-Fa-f0-9]{32}_[0-9]{32}$");
            public static readonly RequestValidation AUTHORIZATION_BASIC = new("Authorization", @"^Basic .+$");
        }

        /// <summary>
        /// HttpQueries class.
        /// </summary>
        public static class HttpQueries
        {
            public static readonly RequestValidation RESPONSE_TYPE = new("response_type", @"^code$");
            public static readonly RequestValidation CLIENT_ID = new("client_id", @"^[0-9]{32}$");
            public static readonly RequestValidation REDIRECT_URI = new("redirect_uri", @"^(https://.+|http://(localhost|osolab-[A-Za-z0-9-]+-local)(:[0-9]+)?(/.*)?)$");
            public static readonly RequestValidation STATE = new("state", @"^.{1,255}$");
            public static readonly RequestValidation SCOPE = new("scope", @"^[A-Za-z0-9_ ]+$");
            public static readonly RequestValidation CODE_CHALLENGE_METHOD = new("code_challenge_method", @"^S256$");
            public static readonly RequestValidation CODE_CHALLENGE = new("code_challenge", @"^[A-Za-z0-9._~-]{43,128}$");
            public static readonly RequestValidation NONCE = new("nonce", @"^.{1,255}$");
            public static readonly RequestValidation TOKEN = new("token", @"^[A-Za-z0-9_-]{20,}$");
            public static readonly RequestValidation CODE = new("code", @"^[0-9]{5}$");
        }

        /// <summary>
        /// HttpBodies class.
        /// </summary>
        public static class HttpBodies
        {
            public static readonly RequestValidation EMAIL = new("email", @"^.+@.+$");
            public static readonly RequestValidation DUMMY_EMAIL = new("dummy_email", @"^[A-Za-z0-9._%+-]+@example\.(com|org|net)$");
            public static readonly RequestValidation PASSWORD = new("password", @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,64}$");
            public static readonly RequestValidation GRANT_TYPE = new("grant_type", @"^authorization_code$");
            public static readonly RequestValidation CODE_VERIFIER = new("code_verifier", @"^[A-Za-z0-9._~-]{43,128}$");
            public static readonly RequestValidation AUTH_CODE = new("code", @"^[A-Za-z0-9._~-]{20,}$");
            public static readonly RequestValidation SESSION_ID = new("session_id", @"^[A-Fa-f0-9]{32}$");
            public static readonly RequestValidation ACCEPTED = new("accepted", @"^(true|false|on)$");
            public static readonly RequestValidation LOGOUT_ALL = new("logout_all", @"^(true|false)$");
            public static readonly RequestValidation CLIENT_ID = new("client_id", @"^[0-9]{32}$");
            public static readonly RequestValidation TERM_SEQ_ID = new("term_seq_id", @"^[0-9]*$");
            public static readonly RequestValidation TERM_NAME = new("term_name", @"^[0-9A-Za-z._~-]{1,32}$");
            public static readonly RequestValidation TERM_URL = new("term_url", @"^(https://.+|http://(localhost|osolab-[A-Za-z0-9-]+-local)(:[0-9]+)?(/.*)?)$");
        }

        /// <summary>
        /// Status class.
        /// </summary>
        public static class Status
        {
            public const byte TENTATIVE = 2;
            public const byte ACTIVE = 1;
            public const byte INACTIVE = 0;
        }

        /// <summary>
        /// Scope class.
        /// </summary>
        public static class Scope
        {
            public const string OPENID = "openid";
            public const string EMAIL = "email";
            public const string PROFILE = "profile";
        }

        /// <summary>
        /// Content class.
        /// </summary>
        public static class Content
        {
            public const string TYPE_JSON = "application/json";
            public const string TYPE_X_WWW_FORM = "application/x-www-form-urlencoded";
        }

        /// <summary>
        /// OsolabId class.
        /// </summary>
        public static class OsolabId
        {
            public const int LENGTH = 16;
            public const int MAX_RETRY_COUNT = 2;
        }

        /// <summary>
        /// Nonce class.
        /// </summary>
        public static class Nonce
        {
            public const int LENGTH = 8;
            public const string CHARACTORS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        }

        /// <summary>
        /// Session class.
        /// </summary>
        public static class Session
        {
            public const int LENGTH = 32;
            public const string CHARACTERS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            public const string CHARACTORS = CHARACTERS;
            public const string HEX_CHARACTORS = "0123456789abcdef";
        }

        /// <summary>
        /// AuthCode class.
        /// </summary>
        public static class AuthCode
        {
            public const int LENGTH = 64;
            public const int EXPIRE_SEC = 300;
            public const string CHARACTORS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._~-";
            public const string REDIS_KEY_PREFIX = "auth_code:";
        }

        /// <summary>
        /// AccessToken class.
        /// </summary>
        public static class AccessToken
        {
            public const int LENGTH = 64;
            public const string CHARACTERS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            public const string CHARACTORS = CHARACTERS;
            public const string REDIS_KEY_PREFIX = "access_token:";
            public const string TOKEN_TYPE_BEARER = "Bearer";
        }

        /// <summary>
        /// RefreshToken class.
        /// </summary>
        public static class RefreshToken
        {
            public const string REDIS_KEY_PREFIX = "refresh_token:";
        }

        /// <summary>
        /// Revocation class.
        /// </summary>
        public static class Revocation
        {
            public const string LOGOUT_ALL_PREFIX = "logout_all:";
            public const string ID_TOKEN_PREFIX = "id_token_jti:";
        }

        /// <summary>
        /// 内部クライアントクラス
        /// </summary>
        public static class InnerClient
        {
            public const string OSOLAB_CLIENT_ID = "00000000000000000000000000000000";
        }

        public static class RedisDbNo
        {
            public const int AUTH_SESSION = 1;
            public const int AUTHORIZATION_CODE = 2;
            public const int ACCESS_TOKEN = 3;
            public const int REFRESH_TOKEN = 4;
            public const int AUTH_REQUEST_SESSION = 6;
            public const int SIGNUP_SESSION = 7;
        }

    }
}
