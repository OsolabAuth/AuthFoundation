using System.Net;

namespace AuthFoundation.Common;

public sealed class ApiException : Exception
{
    public string InternalCode { get; }
    public HttpStatusCode StatusCode { get; }
    public string Error { get; }
    public string ErrorDescription { get; }

    /// <summary>
    /// APIレスポンスに変換するAuthFoundation共通例外を生成する。
    /// </summary>
    /// <param name="internalCode">AuthFoundation内部の返却コード。</param>
    /// <param name="statusCode">HTTPステータスコード。</param>
    /// <param name="error">OAuthエラーコード。</param>
    /// <param name="errorDescription">エラー説明。</param>
    public ApiException(
        string internalCode,
        HttpStatusCode statusCode,
        string error,
        string errorDescription)
        : base(errorDescription)
    {
        InternalCode = internalCode;
        StatusCode = statusCode;
        Error = error;
        ErrorDescription = errorDescription;
    }
}
