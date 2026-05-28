using System.Text.Json.Serialization;

namespace AuthFoundation.Common;

public sealed class ErrorOutput
{
    [JsonPropertyName("response_code")]
    public string ResponseCode { get; }

    [JsonPropertyName("error_code")]
    public string ErrorCode { get; }

    [JsonPropertyName("message")]
    public string Message { get; }

    [JsonPropertyName("error")]
    public string Error { get; }

    [JsonPropertyName("error_description")]
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
