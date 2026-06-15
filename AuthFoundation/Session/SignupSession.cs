using System.Text.Json.Serialization;

namespace AuthFoundation.Session;

public sealed class SignupSession
{
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan VerifiedLifetime = TimeSpan.FromMinutes(10);

    [JsonPropertyName("session_id")]
    public string SessionId { get; init; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    [JsonPropertyName("code")]
    public string Code { get; init; } = string.Empty;

    [JsonPropertyName("code_expires_at")]
    public DateTimeOffset CodeExpiresAt { get; init; }

    [JsonPropertyName("verified_at")]
    public DateTimeOffset? VerifiedAt { get; init; }

    public static string GetRedisKey(string sessionId)
    {
        return $"auth:session:signup:{sessionId}";
    }
}
