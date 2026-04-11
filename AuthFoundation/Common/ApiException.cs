using System;
using System.Net;
using System.Net.NetworkInformation;

namespace AuthFoundation.Common;

/// <summary>
/// API用の業務例外。
/// コード、HTTPステータス、表示用メッセージを保持する。
/// </summary>
public class ApiException : Exception
{
    /// <summary>
    /// 業務エラーコード
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// 返却したいHTTPステータス
    /// </summary>
    public HttpStatusCode Status { get; }

    /// <summary>
    /// API返却用メッセージ
    /// </summary>
    public string ErrorMessage { get; set; }

    public ApiException(
        string code,
        HttpStatusCode status,
        string errorMessage)
        : base(errorMessage)
    {
        Code = code;
        Status = status;
        ErrorMessage = errorMessage;
    }

    public ApiException(
        string code,
        HttpStatusCode status,
        string errorMessage,
        Exception innerException)
        : base(errorMessage, innerException)
    {
        Code = code;
        Status = status;
        ErrorMessage = errorMessage;
    }

    public ApiException(ApiException baseEx, string errorMessage)
    {
        Code = baseEx.Code;
        Status = baseEx.Status;
        ErrorMessage = errorMessage;

    }
}