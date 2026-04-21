using Microsoft.IdentityModel.Tokens;

namespace AuthFoundation.Common
{
    public static class DateTimeHelper
    {
        private static readonly string Format = "yyyy-MM-ddTHH:mm:sszzz";
        private static readonly string TimeZoneJst = "Tokyo Standard Time";

        public static DateTime GetJstNow()
        {
            TimeZoneInfo JST = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneJst);
            return TimeZoneInfo.ConvertTime(DateTime.UtcNow, TimeZoneInfo.Utc, JST);
        }

        public static string ToJstString(DateTime datetime)
        {
            TimeZoneInfo JST = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneJst);
            DateTimeOffset dto;
            if (datetime.Kind == DateTimeKind.Unspecified)
            {
                dto = new DateTimeOffset(datetime, JST.BaseUtcOffset);
            }
            else
            {
                dto = new DateTimeOffset(datetime);
            }
            return dto.ToOffset(JST.BaseUtcOffset).ToString(Format);
        }

    }
}
