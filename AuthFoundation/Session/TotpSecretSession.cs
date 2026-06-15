using System.Text.Json.Serialization;

namespace AuthFoundation.Session;

public sealed class TotpSecretSession
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(365);

    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    [JsonPropertyName("secret")]
    public string Secret { get; init; } = string.Empty;

    public static string GetRedisKey(string email)
    {
        return $"auth:session:totp_secret:{email.ToLowerInvariant()}";
    }
}
