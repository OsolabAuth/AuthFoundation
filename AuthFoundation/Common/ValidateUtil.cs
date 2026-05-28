using System.Text.RegularExpressions;

namespace AuthFoundation.Common;

public static partial class ValidateUtil
{
    public static void IndispensableParam(string? value, string key)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ApiException(
                Code.REQUEST_PARAMETER_ERROR.InternalCode,
                Code.REQUEST_PARAMETER_ERROR.StatusCode,
                Code.REQUEST_PARAMETER_ERROR.Error,
                $"{key} is required");
        }
    }

    public static void FormatParam(string? value, string key, string regex)
    {
        IndispensableParam(value, key);
        if (!Regex.IsMatch(value!, regex))
        {
            throw new ApiException(
                Code.REQUEST_PARAMETER_ERROR.InternalCode,
                Code.REQUEST_PARAMETER_ERROR.StatusCode,
                Code.REQUEST_PARAMETER_ERROR.Error,
                $"{key} is invalid");
        }
    }
}
