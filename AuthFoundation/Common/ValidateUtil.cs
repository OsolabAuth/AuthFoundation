using System.Text.RegularExpressions;

namespace AuthFoundation.Common;

public static partial class ValidateUtil
{
    /// <summary>
    /// 必須パラメータが指定されているか確認する。
    /// </summary>
    /// <param name="value">確認対象の値。</param>
    /// <param name="key">エラーメッセージに使用する項目名。</param>
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

    /// <summary>
    /// 必須チェックと正規表現による形式チェックを行う。
    /// </summary>
    /// <param name="value">確認対象の値。</param>
    /// <param name="key">エラーメッセージに使用する項目名。</param>
    /// <param name="regex">許可する形式を表す正規表現。</param>
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
