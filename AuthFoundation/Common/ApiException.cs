using System;
using System.Net;
using System.Net.NetworkInformation;

namespace AuthFoundation.Common;

/// <summary>
/// ApiException class.
/// </summary>
public class ApiException : Exception
{
    /// <summary>
    /// Gets or sets Code.
    /// </summary>
    public string Code { get; }

    /// <summary>
    /// Gets or sets Status.
    /// </summary>
    public HttpStatusCode Status { get; }

    /// <summary>
    /// Gets or sets ErrorMessage.
    /// </summary>
    public string ErrorMessage { get; set; }

    /// <summary>
    /// Initializes a new instance of ApiException.
    /// </summary>
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

    /// <summary>
    /// Initializes a new instance of ApiException.
    /// </summary>
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

    /// <summary>
    /// Initializes a new instance of ApiException.
    /// </summary>
    public ApiException(ApiException baseEx, string errorMessage)
    {
        Code = baseEx.Code;
        Status = baseEx.Status;
        ErrorMessage = errorMessage;

    }
}
