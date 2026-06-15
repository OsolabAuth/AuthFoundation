using System.Text.Json.Serialization;

namespace AuthFoundation.Session;

public sealed class AccessTokenSession
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    [JsonPropertyName("access_token")]
    public string AccessToken { get; init; } = string.Empty;

    [JsonPropertyName("client_id")]
    public string ClientId { get; init; } = string.Empty;

    [JsonPropertyName("scope")]
    public string Scope { get; init; } = string.Empty;

    [JsonPropertyName("subject")]
    public string Subject { get; init; } = string.Empty;

    [JsonPropertyName("email")]
    public string Email { get; init; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("principal_type")]
    public string PrincipalType { get; init; } = string.Empty;

    [JsonPropertyName("owner_subject")]
    public string OwnerSubject { get; init; } = string.Empty;

    [JsonPropertyName("delegation_id")]
    public string DelegationId { get; init; } = string.Empty;

    [JsonPropertyName("expires_at")]
    public DateTimeOffset ExpiresAt { get; init; }

    public static string GetRedisKey(string accessToken)
    {
        return $"auth:session:access_token:{accessToken}";
    }
}
