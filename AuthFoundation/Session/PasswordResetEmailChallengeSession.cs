using System.Text.Json.Serialization;

namespace AuthFoundation.Session;

public sealed class PasswordResetEmailChallengeSession
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    [JsonPropertyName("code")]
    public string Code { get; init; } = string.Empty;

    [JsonPropertyName("expires_at")]
    public DateTimeOffset ExpiresAt { get; init; }

    public static string GetRedisKey(string email)
    {
        return $"auth:session:password_reset_email_challenge:{email.ToLowerInvariant()}";
    }
}
