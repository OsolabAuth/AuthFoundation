using System.Net;

namespace AuthFoundation.Common;

public static class Code
{
    public static readonly ApiException SUCCESS = Define("00000", HttpStatusCode.OK, string.Empty, string.Empty);
    public static readonly ApiException REQUEST_PARAMETER_ERROR = Define("00001", HttpStatusCode.BadRequest, "invalid_request", "some of the input values are incorrect");
    public static readonly ApiException ILLEGAL_CLIENT = Define("00002", HttpStatusCode.BadRequest, "invalid_client", "illegal client");
    public static readonly ApiException UNAUTHORIZED = Define("00008", HttpStatusCode.Unauthorized, "invalid_token", "unauthorized");
    public static readonly ApiException INVALID_SCOPE = Define("00009", HttpStatusCode.BadRequest, "invalid_scope", "invalid scope");
    public static readonly ApiException INTERNAL_SERVER_ERROR = Define("90000", HttpStatusCode.InternalServerError, "server_error", "Unhandled server error");

    public sealed record RequestValidation(string Key, string Regex);

    public static class HttpBodies
    {
        public static readonly RequestValidation EMAIL = new("email", @"^.+@.+$");
        public static readonly RequestValidation PASSWORD = new("password", @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,128}$");
    }

    public static class Scope
    {
        public const string OPENID = "openid";
        public const string EMAIL = "email";
        public const string PROFILE = "profile";
    }

    public static class Content
    {
        public const string TYPE_JSON = "application/json";
        public const string TYPE_X_WWW_FORM = "application/x-www-form-urlencoded";
    }

    private static ApiException Define(string code, HttpStatusCode status, string error, string description)
    {
        return new ApiException(code, status, error, description);
    }
}
