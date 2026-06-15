using System.Text.Json.Serialization;

namespace AuthFoundation.Session;

public sealed class AttemptCounterSession
{
    [JsonPropertyName("failures")]
    public int Failures { get; init; }

    [JsonPropertyName("expires_at")]
    public DateTimeOffset ExpiresAt { get; init; }

    public static string GetRedisKey(string key)
    {
        return $"auth:session:attempt:{key}";
    }
}
