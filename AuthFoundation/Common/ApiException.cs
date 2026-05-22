using Newtonsoft.Json;
using System;
using System.Net;

namespace AuthFoundation.Common;

/// <summary>
/// 基盤用例外クラス
/// </summary>
public class ApiException : Exception
{
    /// <summary>
    /// Sample実装の FoundationException.Value に合わせたコード値オブジェクト。
    /// </summary>
    public readonly struct Value : IEquatable<Value>
    {
        public string Code { get; init; }
        public HttpStatusCode Status { get; init; }
        public string Msg { get; init; }
        public string Error { get; init; }
        public string ErrorUri { get; init; }
        public bool CanRedirect { get; init; }

        public bool Equals(Value other)
        {
            return string.Equals(Code, other.Code, StringComparison.Ordinal)
                && Status == other.Status
                && string.Equals(Msg, other.Msg, StringComparison.Ordinal)
                && string.Equals(Error, other.Error, StringComparison.Ordinal)
                && string.Equals(ErrorUri, other.ErrorUri, StringComparison.Ordinal)
                && CanRedirect == other.CanRedirect;
        }

        public override bool Equals(object? obj)
        {
            return obj is Value other && Equals(other);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Code, Status, Msg, Error, ErrorUri, CanRedirect);
        }

        public static bool operator ==(Value left, Value right) => left.Equals(right);

        public static bool operator !=(Value left, Value right) => !(left == right);
    }

    [JsonProperty("error")]
    public string Error { get; set; } = string.Empty;
    [JsonProperty("error_description")]
    public string ErrorDescription { get; set; } = string.Empty;
    [JsonProperty("error_uri")]
    public string ErrorUri { get; set; } = string.Empty;

    // 内部制御用
    [JsonProperty("internal_error_code")]
    public string InternalCode { get; set; } = string.Empty;
    [JsonProperty("can_redirect")]
    public bool CanRedirect { get; set; } = false;
    [JsonProperty("status_code")]
    public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.InternalServerError;

    [JsonIgnore]
    public string Code
    {
        get => InternalCode;
        set => InternalCode = value;
    }

    [JsonIgnore]
    public HttpStatusCode Status
    {
        get => StatusCode;
        set => StatusCode = value;
    }

    [JsonIgnore]
    public string ErrorMessage
    {
        get => ErrorDescription;
        set => ErrorDescription = value;
    }

    [JsonIgnore]
    public Value Cause => new()
    {
        Code = InternalCode,
        Status = StatusCode,
        Msg = ErrorDescription,
        Error = Error,
        ErrorUri = ErrorUri,
        CanRedirect = CanRedirect
    };

    /// <summary>
    /// コンストラクタ
    /// </summary>
    public ApiException()
    { 
    
    }

    /// <summary>
    /// Valueから例外生成（sample互換）。
    /// </summary>
    public ApiException(Value value)
        : this(
            value.Code,
            value.Status,
            string.IsNullOrWhiteSpace(value.Msg) ? string.Empty : value.Msg)
    {
        if (!string.IsNullOrWhiteSpace(value.Error))
        {
            Error = value.Error;
        }

        ErrorUri = value.ErrorUri;
        CanRedirect = value.CanRedirect;
    }

    /// <summary>
    /// Valueから例外生成（メッセージ上書き、sample互換）。
    /// </summary>
    public ApiException(Value value, string errorDescription)
        : this(value.Code, value.Status, errorDescription)
    {
        if (!string.IsNullOrWhiteSpace(value.Error))
        {
            Error = value.Error;
        }

        ErrorUri = value.ErrorUri;
        CanRedirect = value.CanRedirect;
    }

    /// <summary>
    /// 内部エラー用コンストラクタ
    /// </summary>
    /// <param name="code">エラーコード</param>
    /// <param name="status">HTTPステータスコード</param>
    /// <param name="errorDescription">メッセージ</param>
    public ApiException(
        string code,
        HttpStatusCode status,
        string errorDescription)
        : base(errorDescription)
    {
        InternalCode = code;
        StatusCode = status;
        Error = ToOAuthError(code);
        ErrorDescription = errorDescription;
    }

    /// <summary>
    /// コンストラクタ(ハンドルされない例外用)
    /// </summary>
    /// <param name="code">エラーコード</param>
    /// <param name="status">HTTPステータスコード</param>
    /// <param name="errorDescription">メッセージ</param>
    /// <param name="innerException">内部例外</param>
    public ApiException(
        string code,
        HttpStatusCode status,
        string errorDescription,
        Exception innerException)
        : base(errorDescription, innerException)
    {
        InternalCode = code;
        StatusCode = status;
        Error = ToOAuthError(code);
        ErrorDescription = errorDescription;
    }

    /// <summary>
    /// コンストラクタ(メッセージの上書き)
    /// </summary>
    /// <param name="baseEx">例外</param>
    /// <param name="errorDescription">メッセージ</param>
    public ApiException(ApiException baseEx, string errorDescription)
        : base(errorDescription)
    {
        Error = baseEx.Error;
        ErrorUri = baseEx.ErrorUri;
        InternalCode = baseEx.InternalCode;
        CanRedirect = baseEx.CanRedirect;
        StatusCode = baseEx.StatusCode;
        ErrorDescription = errorDescription;
    }

    private static string ToOAuthError(string internalCode)
    {
        return internalCode switch
        {
            "00002" => "invalid_client",
            "00004" => "access_denied",
            "00008" => "invalid_token",
            "00009" => "invalid_scope",
            "90000" => "server_error",
            "90001" => "server_error",
            _ => "invalid_request"
        };
    }
}
