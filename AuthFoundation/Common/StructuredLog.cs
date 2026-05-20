using System.Text.Json;

namespace AuthFoundation.Common
{
    public static class StructuredLog
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        public static void LogException(ILogger logger, string eventName, Exception exception, object? context = null)
        {
            var payload = new
            {
                eventName,
                exceptionType = exception.GetType().FullName,
                message = exception.Message,
                stackTrace = exception.StackTrace,
                innerException = exception.InnerException?.Message,
                context
            };

            logger.LogError("{SerializedLog}", JsonSerializer.Serialize(payload, JsonOptions));
        }

        public static void LogInfo(ILogger logger, string eventName, object? context = null)
        {
            var payload = new
            {
                eventName,
                context
            };

            logger.LogInformation("{SerializedLog}", JsonSerializer.Serialize(payload, JsonOptions));
        }
    }
}
