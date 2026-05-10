namespace AuthFoundation.Common
{
    /// <summary>
    /// DateTimeHelper class.
    /// </summary>
    public static class DateTimeHelper
    {
        private const string Format = "yyyy-MM-ddTHH:mm:sszzz";
        private const string TimeZoneJst = "Tokyo Standard Time";

        /// <summary>
        /// Executes GetJstNow.
        /// </summary>
        public static DateTime GetJstNow()
        {
            TimeZoneInfo jst = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneJst);
            return TimeZoneInfo.ConvertTime(DateTime.UtcNow, TimeZoneInfo.Utc, jst);
        }

        /// <summary>
        /// Executes ToJstString.
        /// </summary>
        public static string ToJstString(DateTime datetime)
        {
            TimeZoneInfo jst = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneJst);
            DateTimeOffset dto = datetime.Kind == DateTimeKind.Unspecified
                ? new DateTimeOffset(datetime, jst.BaseUtcOffset)
                : new DateTimeOffset(datetime);

            return dto.ToOffset(jst.BaseUtcOffset).ToString(Format);
        }
    }
}
