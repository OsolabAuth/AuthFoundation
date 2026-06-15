using System.Text.Json.Serialization;

namespace AuthFoundation.Session;

public sealed class StepUpGrantSession
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    [JsonPropertyName("step_up_token")]
    public string StepUpToken { get; init; } = string.Empty;

    [JsonPropertyName("subject")]
    public string Subject { get; init; } = string.Empty;

    [JsonPropertyName("method")]
    public string Method { get; init; } = string.Empty;

    [JsonPropertyName("expires_at")]
    public DateTimeOffset ExpiresAt { get; init; }

    public static string GetRedisKey(string stepUpToken)
    {
        return $"auth:session:step_up_grant:{stepUpToken}";
    }
}
