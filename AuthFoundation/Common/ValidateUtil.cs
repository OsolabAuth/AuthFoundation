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



    }
}
