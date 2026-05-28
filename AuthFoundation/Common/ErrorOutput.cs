namespace AuthFoundation.Common;

public sealed class ErrorOutput
{
    public string ResponseCode { get; }
    public string ErrorCode { get; }
    public string Message { get; }
    public string Error { get; }
    public string ErrorDescription { get; }

    public ErrorOutput(ApiException ex)
    {
        ResponseCode = ex.InternalCode;
        ErrorCode = ex.InternalCode;
        Message = ex.ErrorDescription;
        Error = ex.Error;
        ErrorDescription = ex.ErrorDescription;
    }
}
