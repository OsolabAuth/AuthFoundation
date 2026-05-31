using System.Net;

namespace AuthFoundation.Common;

public sealed class ApiException : Exception
{
    public string InternalCode { get; }
    public HttpStatusCode StatusCode { get; }
    public string Error { get; }
    public string ErrorDescription { get; }

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
