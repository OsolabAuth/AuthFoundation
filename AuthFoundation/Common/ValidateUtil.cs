using System.Net.Mail;
using System.Text.RegularExpressions;

namespace AuthFoundation.Common
{
    /// <summary>
    /// ValidateUtil class.
    /// </summary>
    public static class ValidateUtil
    {
        /// <summary>
        /// Executes IndispensableParam.
        /// </summary>
        public static void IndispensableParam(string argValue, string argMessage)
        {
            if (string.IsNullOrEmpty(argValue))
            {
                throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, $"{argMessage}が指定されていません");
            }
        }

        /// <summary>
        /// Executes FormatParam.
        /// </summary>
        public static void FormatParam(string argValue, string argMessage, string pattern, bool nullOrEnptyPermission = false)
        {
            if (nullOrEnptyPermission == true && string.IsNullOrEmpty(argValue))
            {
                return;
            }
            if (!Regex.IsMatch(argValue, pattern))
            {
                throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, $"{argMessage}の形式が不正です");
            }
        }

        /// <summary>
        /// メールアドレス形式を検証します。
        /// </summary>
        /// <param name="argValue">入力値</param>
        /// <param name="argMessage">項目名</param>
        /// <param name="nullOrEnptyPermission">空値許可フラグ</param>
        public static void EmailParam(string argValue, string argMessage, bool nullOrEnptyPermission = false)
        {
            string normalized = argValue?.Trim() ?? string.Empty;
            if (nullOrEnptyPermission && string.IsNullOrEmpty(normalized))
            {
                return;
            }

            IndispensableParam(normalized, argMessage);
            FormatParam(normalized, argMessage, Code.HttpBodies.EMAIL.Regex);

            if (!MailAddress.TryCreate(normalized, out MailAddress? parsed)
                || !string.Equals(parsed.Address, normalized, StringComparison.OrdinalIgnoreCase))
            {
                throw new ApiException(Common.Code.REQUEST_PARAMETER_ERROR, $"{argMessage}の形式が不正です");
            }
        }
    }
}
