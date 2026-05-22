using Newtonsoft.Json;
using System;
using System.Net;

namespace AuthFoundation.Common;

/// <summary>
/// 基盤用例外クラス
/// </summary>
public class ApiException : Exception
{
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

    /// <summary>
    /// コンストラクタ
    /// </summary>
    public ApiException()
    { 
    
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
