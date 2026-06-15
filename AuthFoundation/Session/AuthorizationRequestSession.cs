using System.Text.Json.Serialization;

namespace AuthFoundation.Session;

public sealed class AuthorizationRequestSession
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    [JsonPropertyName("request_id")]
    public string RequestId { get; init; } = string.Empty;

    [JsonPropertyName("client_id")]
    public string ClientId { get; init; } = string.Empty;

    [JsonPropertyName("redirect_uri")]
    public string RedirectUri { get; init; } = string.Empty;

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = string.Empty;

    [JsonPropertyName("state")]
    public string State { get; init; } = string.Empty;

    [JsonPropertyName("nonce")]
    public string Nonce { get; init; } = string.Empty;

    [JsonPropertyName("code_challenge")]
    public string CodeChallenge { get; init; } = string.Empty;

    [JsonPropertyName("expires_at")]
    public DateTimeOffset ExpiresAt { get; init; }

    public static string GetRedisKey(string requestId)
    {
        return $"auth:session:authorization_request:{requestId}";
    }
}
